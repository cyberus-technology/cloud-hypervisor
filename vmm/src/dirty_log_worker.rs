// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

use std::any::Any;
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use std::{io, mem, thread};

use arch::PAGE_SIZE;
use log::{error, info};
use vm_migration::protocol::MemoryRangeTable;
use vm_migration::{Migratable, MigratableError};

use crate::cpu::CpuManager;
use crate::memory_manager::MemoryManager;

/// Throttle (sleep) time of the thread per iteration.
///
/// 33ms means roughly 10-30 effective iterations per second. If this value is
/// too small, we take computation time from the vCPUs away. If we set too big,
/// the dirty memory ranges computations might take too long as there is too
/// much data to process - this might delay the final iteration.
///
/// If the thread is in its sleep, it can be interrupted.
const THREAD_THROTTLE: Duration = Duration::from_millis(33);

/// The timeslice in which we calculate the current dirty rate of the VM.
///
/// Every [`THREAD_THROTTLE`] seconds, we get a set of dirtied memory and
/// calculate the dirty rate. This constant specifies how many samples we
/// look back into the future to calculate the average dirty rate.
///
/// In other words: If this is 1s, we always return the average dirty rate of
/// the past second.
const DIRTY_RATE_CALC_TIMESLICE: Duration = Duration::from_secs(1);

type JoinError = Box<dyn Any + Send + 'static>;

/// All shared state of [`DirtyLogWorker`] that is behind the same lock.
struct DirtyLogWorkerSharedState {
    /// The dirty rates measured in the past [`DIRTY_RATE_CALC_TIMESLICE`].
    ///
    /// Used to calculate the dirty rate.
    dirty_rates_pps: VecDeque<u64>,
    /// The constantly updated (and merged) memory range table since the data
    /// was moved out of the struct the last time.
    table: MemoryRangeTable,
    /// The timestamp of the last processing, used to calculate the dirty rate.
    last_timestamp: Instant,
    /// Set to true to signal the worker thread to stop and exit.
    stop: bool,
}

impl DirtyLogWorkerSharedState {
    /// Adds a new dirty rate measurement to the underlying vector.
    ///
    /// Removes old elements from the vector.
    fn update_dirty_rate(&mut self, dirty_rate_pps: u64) {
        self.dirty_rates_pps.push_front(dirty_rate_pps);
        if self.dirty_rates_pps.len() > Self::dirty_rate_vec_capacity() {
            self.dirty_rates_pps.pop_back();
        }
    }

    /// Returns the average dirty rate in pages per second.
    fn average_dirty_rate_pps(&self) -> u64 {
        if self.dirty_rates_pps.is_empty() {
            0
        } else {
            self.dirty_rates_pps
                .iter()
                .sum::<u64>()
                .div_ceil(self.dirty_rates_pps.len() as u64)
        }
    }

    /// Removes old elements from the vector and returns the average
    /// dirty rate for the past [`DIRTY_RATE_CALC_TIMESLICE`].
    const fn dirty_rate_vec_capacity() -> usize {
        DIRTY_RATE_CALC_TIMESLICE
            .as_millis()
            .div_ceil(THREAD_THROTTLE.as_millis()) as usize
    }
}

/// Worker thread that continuously fetches the dirty log.
pub struct DirtyLogWorker {
    stop_condvar: Arc<Condvar>,
    shared_state: Arc<Mutex<DirtyLogWorkerSharedState>>,
    cpu_manager: Weak<Mutex<CpuManager>>,
    memory_manager: Weak<Mutex<MemoryManager>>,
}

impl DirtyLogWorker {
    /// Spawns a new [`DirtyLogWorker`] and returns a [`DirtyLogWorkerHandle`] to it.
    pub fn spawn(
        cpu_manager: &Arc<Mutex<CpuManager>>,
        memory_manager: &Arc<Mutex<MemoryManager>>,
    ) -> Result<DirtyLogWorkerHandle, io::Error /* spawn error */> {
        let stop_condvar = Arc::new(Condvar::new());
        let table = MemoryRangeTable::from_dirty_bitmap([], 0, 0);

        let shared_state = DirtyLogWorkerSharedState {
            last_timestamp: Instant::now(),
            dirty_rates_pps: VecDeque::new(),
            table,
            stop: false,
        };
        let shared_state = Arc::new(Mutex::new(shared_state));

        let worker = Self {
            stop_condvar: stop_condvar.clone(),
            shared_state: shared_state.clone(),
            cpu_manager: Arc::downgrade(cpu_manager),
            memory_manager: Arc::downgrade(memory_manager),
        };

        let inner_handle = thread::Builder::new()
            .name("dirty-log-worker".to_string())
            .spawn(|| worker.run())?;

        let handle = DirtyLogWorkerHandle {
            handle: Some(inner_handle),
            stop_condvar,
            shared_state,
        };

        Ok(handle)
    }

    /// Fetches the latest snapshot of all dirty tables and merges them into a single one.
    fn fetch_table(&self) -> Result<MemoryRangeTable, MigratableError /* dirty log error */> {
        let mut cpu_table = self
            .cpu_manager
            .upgrade()
            .expect("VM's CpuManager should outlive this thread")
            .lock()
            .unwrap()
            .dirty_log()?;

        let memory_table = self
            .memory_manager
            .upgrade()
            .expect("VM's MemoryManager should outlive this thread")
            .lock()
            .unwrap()
            .dirty_log()?;

        // Extend here is fine as they won't overlap.
        cpu_table.extend(memory_table);
        Ok(cpu_table)
    }

    /// Updates internal metrics, such as the dirty rate. Also merges the new table
    /// with the table of the previous iteration.
    fn calc_metrics_and_update_table(&self, new_table: MemoryRangeTable) {
        let mut state_lock = self.shared_state.lock().unwrap();

        let elapsed = state_lock.last_timestamp.elapsed();
        let new_dirty_size = new_table
            .regions()
            .iter()
            .map(|range| range.length)
            .sum::<u64>();

        // Calc dirty rate for current cycle
        let dirty_rate_pps = if elapsed.is_zero() {
            0
        } else {
            let dirty_rate_f64 = (new_dirty_size / PAGE_SIZE as u64) as f64 / elapsed.as_secs_f64();
            dirty_rate_f64.ceil() as u64
        };

        state_lock.update_dirty_rate(dirty_rate_pps);
        state_lock.table.merge_in_place(new_table);
        state_lock.last_timestamp = Instant::now();
    }

    /// Starts the thread and let it run until [`DirtyLogWorkerHandle::stop`] is called.
    pub fn run(self) -> Result<(), MigratableError /* dirty log error */> {
        info!("thread started");

        let worker_res = loop {
            // Fetch the latest dirty log and release locks ASAP
            let new_table = self.fetch_table()?;
            self.calc_metrics_and_update_table(new_table);

            // Rate limiting plus better resolution for dirty rate calculation.
            // Uses the condvar so we can be woken up early if stop is requested.
            // To ensure the last call returns the freshest data, we exit the
            // thread after querying the latest data.
            let state_lock = self.shared_state.lock().unwrap();

            // We sleep but might get woken up by our handler to exit.
            let (guard, _timed_out) = self
                .stop_condvar
                .wait_timeout_while(state_lock, THREAD_THROTTLE, |state| !state.stop)
                .unwrap();

            if guard.stop {
                // At this point, we assume the VM is stopped and perform one last fetch.
                let new_table = self.fetch_table()?;
                self.calc_metrics_and_update_table(new_table);

                info!("thread exiting");
                break Ok(());
            }
        };

        if let Err(e) = &worker_res {
            error!("Thread experienced an error and stopped its work: {e:?}");
        }

        worker_res
    }
}

/// Handle to a [`DirtyLogWorker`] thread.
pub struct DirtyLogWorkerHandle {
    // Option so that we can take the inner handle.
    handle: Option<JoinHandle<Result<(), MigratableError /* dirty log error */>>>,
    stop_condvar: Arc<Condvar>,
    shared_state: Arc<Mutex<DirtyLogWorkerSharedState>>,
}

impl DirtyLogWorkerHandle {
    fn exit_and_join_thread(&mut self) -> Result<(), JoinError> {
        info!("stopping thread ...");
        let begin = Instant::now();

        // Tells the thread that it should exit ASAP.
        self.shared_state.lock().unwrap().stop = true;
        // We kick it out of a potential sleep()
        self.stop_condvar.notify_one();

        let thread_res = self
            .handle
            .take()
            .expect("should have thread handle")
            .join()?;

        match thread_res {
            Ok(_) => {
                info!("stopped thread after {}ms", begin.elapsed().as_millis());
            }
            Err(e) => {
                error!(
                    "Thread encountered an error: {e} (stopped thread after {}ms)",
                    begin.elapsed().as_millis()
                );
            }
        }

        Ok(())
    }

    /// Stops and terminates the thread gracefully.
    ///
    /// You must call this **after the VM is paused** and **before dirty logging** was stopped!
    /// The call will then return the final memory range table of dirtied memory.
    pub fn stop(mut self) -> Result<(MemoryRangeTable, u64 /* dirty rate */), JoinError> {
        self.exit_and_join_thread()?;
        Ok(self.get())
    }

    /// Gets the latest [`MemoryRangeTable`] of dirtied memory and the latest dirty rate.
    ///
    /// It replaces the internal state with an empty table. Callers are expected to call this once
    /// per precopy iteration.
    pub fn get(&self) -> (MemoryRangeTable, u64 /* dirty rate */) {
        let mut lock = self.shared_state.lock().unwrap();
        let table = mem::take(&mut lock.table);
        (table, lock.average_dirty_rate_pps())
    }
}

impl Drop for DirtyLogWorkerHandle {
    fn drop(&mut self) {
        if self.handle.is_some() {
            // We end up here in case of canceled or failed migrations.
            if let Err(e) = self.exit_and_join_thread() {
                error!("Failed to join thread: {e:?}");
            }
        }
    }
}
