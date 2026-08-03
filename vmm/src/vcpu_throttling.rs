// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0

//! # vCPU throttling for Auto Converging
//!
//! vCPU throttling is crucial to reach a reasonable downtime when using a
//! precopy strategy for live-migration of VMs with memory-intensive workloads.
//! Auto converge means an increasing vCPU throttling over time until the memory
//! delta is small enough for the migration thread(s) to perform the switch-over
//! to the new host.
//!
//! Therefore, the migration thread(s) use this thread to help them reach their
//! goal. Next to typical lifecycle management, this thread must fulfill various
//! requirements to ensure a minimal downtime.
//!
//! ## Thread Requirements
//! - Needs to be able to gracefully wait for work.
//! - Must be able to exit gracefully.
//! - Must be able to cancel any work and return to its init state to support
//!   live-migration cancellation and restart of live-migrations.
//! - Must not block the migration thread(s) whenever possible, to facilitate
//!   fast live-migrations with short downtimes.
//! - Must be interruptible during a sleep phase to not block the migration
//!   thread(s).
//! - Must not confuse or hinder the migration thread(s) regarding
//!   pause()/resume() operations. Context: migration thread shuts down the
//!   vCPUs for the handover. The throttle thread must not restart the vCPUs
//!   again.

use std::cell::Cell;
use std::cmp::min;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use log::{debug, warn};
use vm_migration::Pausable;

use crate::cpu::CpuManager;

/// The possible command of the thread, i.e., the current state.
#[derive(Debug)]
enum ThrottleCommand {
    /// Waiting for next event.
    Waiting,
    /// Ongoing vCPU throttling.
    ///
    /// The inner value shows the current throttling percentage in range `1..=99`.
    Throttling(u8 /* `1..=99` */),
    /// Thread is shutting down gracefully.
    Exiting,
}

/// Helper to adapt the throttling timeslice as we go, depending on the time it
/// takes to pause() and resume() all vCPUs.
#[derive(Debug)]
struct TimesliceContext {
    current_timeslice: Duration,
    /// Duration it took to pause() all vCPUs on the previous iteration.
    previous_pause_duration: Duration,
    /// Duration it took to resume() all vCPUs on the previous iteration.
    previous_resume_duration: Duration,
}

impl TimesliceContext {
    /// The initial timeslice for a throttling cycle (vCPU pause & resume).
    const INITIAL_TIMESLICE: Duration = Duration::from_millis(100);

    /// The minimal value for the operations.
    ///
    /// Any value smaller than this is upgraded to this to prevent math
    /// exceptions during timing calculations.
    const MIN_DURATION: Duration = Duration::from_millis(1);

    /// Maximum time slice. This should not be too big.
    ///
    /// Otherwise, for example: Assuming we have 10% throttling and
    /// 2000ms time slice, then the WM will be unresponsive for
    /// 200ms every 1800ms. This is not convenient.    ///
    const MAX_TIMESLICE: Duration = Duration::from_millis(800);

    /// Creates a new instance with [`Self::INITIAL_TIMESLICE`].
    fn new() -> Self {
        Self {
            current_timeslice: Self::INITIAL_TIMESLICE,
            previous_pause_duration: Self::MIN_DURATION,
            previous_resume_duration: Self::MIN_DURATION,
        }
    }

    /// Updates the timeslice.
    fn update_timeslice(&mut self) {
        // CpuManager::pause() plus CpuManager::resume() without additional delay is the shortest
        // we can get.
        let one_percent = self.previous_pause_duration + self.previous_resume_duration;
        self.current_timeslice = one_percent * 100;
        self.current_timeslice = min(self.current_timeslice, Self::MAX_TIMESLICE);
    }

    /// Calculates the sleep durations for after the `pause()` and `resume()` operations with
    /// the current `timeslice`.
    ///
    /// It uses the `timeslice` that was calculated on the previous
    /// invocation of [`Self::update_timeslice`].
    fn calc_sleep_durations(
        &mut self,
        percentage: u64,
    ) -> (
        Duration, /* after pause */
        Duration, /* after resume */
    ) {
        assert!(percentage <= 100);
        assert!(percentage > 0);

        let timeslice_ms = self.current_timeslice.as_millis() as u64;
        let wait_ms_after_pause_ms = timeslice_ms * percentage / 100;
        let wait_ms_after_resume_ms = timeslice_ms - wait_ms_after_pause_ms;

        let wait_ms_after_pause_ms =
            wait_ms_after_pause_ms.saturating_sub(self.previous_pause_duration.as_millis() as u64);
        let wait_ms_after_resume_ms = wait_ms_after_resume_ms
            .saturating_sub(self.previous_resume_duration.as_millis() as u64);

        (
            Duration::from_millis(wait_ms_after_pause_ms),
            Duration::from_millis(wait_ms_after_resume_ms),
        )
    }

    /// Set the previous pause duration.
    ///
    /// In case this is below [`Self::MIN_DURATION`], we upgrade it to [`Self::MIN_DURATION`].
    pub fn set_previous_pause_duration(&mut self, mut duration: Duration) {
        if duration < Self::MIN_DURATION {
            duration = Self::MIN_DURATION;
        }

        self.previous_pause_duration = duration;
    }

    /// Set the duration it took to `resume()` all vCPUs on the previous iteration.
    ///
    /// In case this is below [`Self::MIN_DURATION`], we upgrade it to [`Self::MIN_DURATION`].
    pub fn set_previous_resume_duration(&mut self, mut duration: Duration) {
        if duration < Self::MIN_DURATION {
            duration = Self::MIN_DURATION;
        }
        self.previous_resume_duration = duration;
    }
}

/// Context of the vCPU throttle thread.
// The main justification for this dedicated type is to split the thread
// functions from the higher-level control API.
// TODO seccomp is missing
pub struct ThrottleWorker {
    handle: Option<JoinHandle<()>>,
}

impl ThrottleWorker {
    /// This should not be named "vcpu*" as libvirt fails when
    /// iterating the vCPU threads then. Fix this first in libvirt!
    const THREAD_NAME: &'static str = "throttle-vcpu";

    /// Executes the provided callback and goes to sleep until the specified
    /// `sleep_duration` passed.
    ///
    /// The time to execute the callback itself is not taken into account
    /// when sleeping for `sleep_duration`. Therefore, the callback is
    /// supposed to be quick (a couple of milliseconds).
    ///
    /// The thread is interruptible during the sleep phase when the `receiver`
    /// receives a new [`ThrottleCommand`].
    ///
    /// # Arguments
    /// - `callback`: Function to run
    /// - `set_callback_duration`: Set the duration to execute the callback.
    /// - `sleep_duration`: Duration this function takes at most, including
    ///   running the `callback`.
    /// - `receiver`: Receiving end of the channel to the migration managing
    ///   thread.
    fn execute_and_wait_interruptible(
        callback: &impl Fn(),
        mut set_callback_duration: impl FnMut(Duration),
        sleep_duration: Duration,
        receiver: &mpsc::Receiver<ThrottleCommand>,
    ) -> Option<ThrottleCommand> {
        let begin = Instant::now();
        callback();
        let cb_duration = begin.elapsed();
        // Help to adjust the timeslice in the next cycle.
        set_callback_duration(cb_duration);

        // It might happen that sometimes we get interrupted during a sleep phase
        // with a new higher throttle percentage but this is negligible. For an
        // auto-converge cycle, there are typically only ~10 steps involved over
        // a time frame from a couple of seconds up to a couple of minutes.
        match receiver.recv_timeout(sleep_duration) {
            Ok(next_task) => Some(next_task),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => {
                panic!("thread and channel should exit gracefully")
            }
        }
    }

    /// Executes one throttling step: either pause or resume of vCPUs.
    ///
    /// Runs the given callback, then waits for the specified duration, unless
    /// interrupted by a new [`ThrottleCommand`].
    ///
    /// # Behavior
    /// - Runs the provided `callback` immediately.
    /// - Waits up to `duration` for new commands on the `receiver`.
    /// - If no command arrives before the timeout, this step completes
    ///   normally and returns `None`.
    /// - If a [`ThrottleCommand::Throttling`] arrives, updates the current
    ///   throttle percentage in `current_throttle` and continues with the
    ///   loop. Returns `None`.
    /// - If a [`ThrottleCommand::Waiting`] or [`ThrottleCommand::Exiting`]
    ///   arrives, this command is forwarded to the caller.
    ///
    /// # Arguments
    /// - `callback`: Function to run (e.g., pause or resume vCPUs).
    /// - `set_callback_duration`: Set the duration to execute the callback.
    /// - `receiver`: Channel for receiving new [`ThrottleCommand`]s.
    /// - `current_throttle`: Mutable reference to the current throttle
    ///   percentage (updated on [`ThrottleCommand::Throttling`]).
    ///
    /// # Returns
    /// - `None` if the throttling cycle should continue.
    /// - `Some(ThrottleCommand::Waiting | ThrottleCommand::Exiting)` if
    ///   throttling should stop.
    fn throttle_step<F>(
        callback: &F,
        set_callback_duration: impl FnMut(Duration),
        duration: Duration,
        receiver: &mpsc::Receiver<ThrottleCommand>,
        current_throttle: &mut u64,
    ) -> Option<ThrottleCommand>
    where
        F: Fn(),
    {
        let maybe_task = Self::execute_and_wait_interruptible(
            callback,
            set_callback_duration,
            duration,
            receiver,
        );
        match maybe_task {
            None => None,
            Some(ThrottleCommand::Throttling(next)) => {
                // A new throttle value is only applied at the end of a full
                // throttling cycle. This is fine and negligible in a series of
                // (tens of) thousands of cycles.
                *current_throttle = next as u64;
                None
            }
            Some(cmd @ (ThrottleCommand::Exiting | ThrottleCommand::Waiting)) => Some(cmd),
        }
    }

    /// Helper for [`Self::control_loop`] that runs the actual throttling loop.
    ///
    /// This function returns the next [`ThrottleCommand`] **only** if the thread
    /// stopped the vCPU throttling.
    fn throttle_loop(
        receiver: &mpsc::Receiver<ThrottleCommand>,
        initial_throttle: u8,
        callback_pause_vcpus: &impl Fn(),
        callback_resume_vcpus: &impl Fn(),
    ) -> ThrottleCommand {
        // The current throttle value, as long as the thread is throttling.
        let mut current_throttle = initial_throttle as u64;
        let mut timeslice_ctx = TimesliceContext::new();

        loop {
            // Catch logic bug: We should have exited in this case already.
            assert_ne!(current_throttle, 0);
            assert!(current_throttle < 100);

            let (wait_ms_after_pause, wait_ms_after_resume) =
                timeslice_ctx.calc_sleep_durations(current_throttle);

            // pause vCPUs
            if let Some(cmd) = Self::throttle_step(
                callback_pause_vcpus,
                |new_duration| timeslice_ctx.set_previous_pause_duration(new_duration),
                wait_ms_after_pause,
                receiver,
                &mut current_throttle,
            ) {
                // TODO: future optimization
                // Prevent unnecessary resume() here when the migration thread
                // performs .pause() right after anyway. We could make .pause() and
                // .resume() idempotent.
                callback_resume_vcpus();
                // We only exit here in case if ThrottleCommand::Waiting or ::Exiting
                return cmd;
            }

            // resume vCPUs
            if let Some(cmd) = Self::throttle_step(
                callback_resume_vcpus,
                |new_duration| timeslice_ctx.set_previous_resume_duration(new_duration),
                wait_ms_after_resume,
                receiver,
                &mut current_throttle,
            ) {
                // We only exit here in case if ThrottleCommand::Waiting or ::Exiting
                return cmd;
            }

            // Update timeslice for next cycle. This way, we can closely match the expected
            // percentage for pause() and resume().
            timeslice_ctx.update_timeslice();
        }
    }

    /// Implements the control loop of the thread.
    ///
    /// It wraps the actual throttling with the necessary thread lifecycle
    /// management.
    fn control_loop(
        receiver: mpsc::Receiver<ThrottleCommand>,
        callback_pause_vcpus: impl Fn() + Send + 'static,
        callback_resume_vcpus: impl Fn() + Send + 'static,
    ) -> impl Fn() {
        move || {
            // In the outer loop, we gracefully wait for commands.
            'control: loop {
                let thread_task = receiver.recv().expect("channel should not be closed");
                match thread_task {
                    ThrottleCommand::Exiting => {
                        break 'control;
                    }
                    ThrottleCommand::Waiting => {
                        continue 'control;
                    }
                    ThrottleCommand::Throttling(initial_throttle) => {
                        let next_task = Self::throttle_loop(
                            &receiver,
                            initial_throttle,
                            &callback_pause_vcpus,
                            &callback_resume_vcpus,
                        );
                        if matches!(next_task, ThrottleCommand::Exiting) {
                            break 'control;
                        }
                        // else: thread is in Waiting state
                    }
                }
            }
            debug!("thread exited gracefully");
        }
    }

    /// Spawns a new thread.
    fn spawn(
        receiver: mpsc::Receiver<ThrottleCommand>,
        callback_pause_vcpus: impl Fn() + Send + 'static,
        callback_resume_vcpus: impl Fn() + Send + 'static,
    ) -> Self {
        let handle = {
            let thread_fn =
                Self::control_loop(receiver, callback_pause_vcpus, callback_resume_vcpus);
            thread::Builder::new()
                .name(String::from(Self::THREAD_NAME))
                .spawn(thread_fn)
                .expect("should spawn thread")
        };

        Self {
            handle: Some(handle),
        }
    }
}

impl Drop for ThrottleWorker {
    fn drop(&mut self) {
        // Note: The thread handle must send the shutdown command first.
        if let Some(handle) = self.handle.take() {
            handle.join().expect("thread should have succeeded");
        }
    }
}

/// Handler for controlling the vCPU throttle thread.
///
/// vCPU throttling is needed for live-migration of memory-intensive workloads.
/// The current design assumes that all vCPUs are throttled equally.
///
/// # Transitions
/// - `Waiting` -> `Throttling(x %)`, `Exit`
/// - `Throttling(x %)` -> `Exit`, `Waiting`, `Throttling(y %)`
/// - `Exiting`
pub struct ThrottleThreadHandle {
    /// Thread state wrapped by synchronization primitives.
    state_sender: mpsc::Sender<ThrottleCommand>,
    /// Current throttle value.
    ///
    /// This is the last throttle value that was sent to the
    /// thread.
    current_throttle: Cell<u8>,
    /// The underlying thread handle. Option to have more control over when it is dropped.
    throttle_thread: Option<ThrottleWorker>,
}

impl ThrottleThreadHandle {
    /// Spawns a new thread and returning a handle to it.
    ///
    /// # Parameters
    /// - `cpu_manager`: CPU manager to pause and resume vCPUs
    pub fn new_from_cpu_manager(cpu_manager: &Arc<Mutex<CpuManager>>) -> Self {
        let callback_pause_vcpus = {
            let cpu_manager = cpu_manager.clone();
            Box::new(move || cpu_manager.lock().unwrap().pause().unwrap())
        };

        let callback_resume_vcpus = {
            let cpu_manager = cpu_manager.clone();
            Box::new(move || cpu_manager.lock().unwrap().resume().unwrap())
        };

        Self::new(callback_pause_vcpus, callback_resume_vcpus)
    }

    /// Spawns a new thread and returning a handle to it.
    ///
    /// This function returns when the thread gracefully arrived in
    /// [`ThrottleCommand::Waiting`].
    ///
    /// # Parameters
    /// - `callback_pause_vcpus`: Function putting all vCPUs into pause state. The
    ///   function must not perform any artificial delay itself.
    /// - `callback_resume_vcpus`: Function putting all vCPUs back into running
    ///   state. The function must not perform any artificial delay itself.
    fn new(
        callback_pause_vcpus: Box<dyn Fn() + Send + 'static>,
        callback_resume_vcpus: Box<dyn Fn() + Send + 'static>,
    ) -> Self {
        // Channel used for synchronization.
        let (sender, receiver) = mpsc::channel::<ThrottleCommand>();

        let thread = ThrottleWorker::spawn(receiver, callback_pause_vcpus, callback_resume_vcpus);

        Self {
            state_sender: sender,
            current_throttle: Cell::new(0),
            throttle_thread: Some(thread),
        }
    }

    /// Set's the throttle percentage to a value in range `0..=99` and updates
    /// the thread's state.
    ///
    /// Setting the value back to `0` equals setting the thread back into
    /// [`ThrottleCommand::Waiting`].
    ///
    /// In case of an ongoing throttling cycle (vCPU pause & resume), any new
    /// throttling percentage will be applied no later than when the current cycle
    /// ends.
    ///
    /// # Panic
    /// Panics, if `percent_new` is not in range `0..=99`.
    pub fn set_throttle_percent(&self, percent_new: u8) {
        assert!(
            percent_new <= 100,
            "setting a percentage of 100 or above is not allowed: {percent_new}%"
        );

        // We have no problematic race condition here as in normal operation
        // there is exactly one thread calling these functions.
        let percent_old = self.throttle_percent();

        // Return early, no action needed.
        if percent_old == percent_new {
            return;
        }

        if percent_new == 0 {
            self.state_sender
                .send(ThrottleCommand::Waiting)
                .expect("channel should not be closed");
        } else {
            self.state_sender
                .send(ThrottleCommand::Throttling(percent_new))
                .expect("channel should not be closed");
        }

        self.current_throttle.set(percent_new);
    }

    /// Get the current throttle percentage in range `0..=99`.
    ///
    /// Please note that the value is not synchronized.
    pub fn throttle_percent(&self) -> u8 {
        self.current_throttle.get()
    }

    /// Stops and terminates the thread gracefully.
    ///
    /// Waits for the thread to finish. This function **must** be called before
    /// the migration thread(s) do anything with the CPU manager to prevent
    /// odd states.
    pub fn shutdown(&mut self) {
        let begin = Instant::now();

        {
            // drop thread; ensure that the channel is still alive when it is dropped
            if let Some(worker) = self.throttle_thread.take() {
                self.state_sender
                    .send(ThrottleCommand::Exiting)
                    .expect("channel should not be closed");

                // Ensure the sender is still living when this is dropped.
                drop(worker);
            }
        }

        let elapsed = begin.elapsed();
        if elapsed > Duration::from_millis(20) {
            warn!(
                "shutting down thread takes too long ({} ms): this increases the downtime!",
                elapsed.as_millis()
            );
        }
    }
}

impl Drop for ThrottleThreadHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread::sleep;

    use super::*;

    // The test is successful if it does not get stuck. Then, the thread exits
    // gracefully.
    #[test]
    fn test_vcpu_throttling_thread_lifecycle() {
        for _ in 0..5 {
            // State transitions: Waiting -> Exit
            {
                let mut handler = ThrottleThreadHandle::new(Box::new(|| {}), Box::new(|| {}));

                // The test is successful if it does not get stuck.
                handler.shutdown();
            }

            // Dummy CpuManager
            let cpus_throttled = Arc::new(AtomicBool::new(false));
            let callback_pause_vcpus = {
                let cpus_running = cpus_throttled.clone();
                Box::new(move || {
                    let old = cpus_running.swap(true, Ordering::SeqCst);
                    assert!(!old);
                })
            };
            let callback_resume_vcpus = {
                let cpus_running = cpus_throttled.clone();
                Box::new(move || {
                    let old = cpus_running.swap(false, Ordering::SeqCst);
                    assert!(old);
                })
            };

            // State transitions: Waiting -> Throttle -> Waiting -> Throttle -> Exit
            {
                let mut handler =
                    ThrottleThreadHandle::new(callback_pause_vcpus, callback_resume_vcpus);
                handler.set_throttle_percent(5);
                sleep(TimesliceContext::INITIAL_TIMESLICE);
                handler.set_throttle_percent(10);
                sleep(TimesliceContext::INITIAL_TIMESLICE);

                // Assume we aborted vCPU throttling (or the live-migration at all).
                handler.set_throttle_percent(0 /* reset to waiting */);
                handler.set_throttle_percent(5);
                sleep(TimesliceContext::INITIAL_TIMESLICE);
                handler.set_throttle_percent(10);
                sleep(TimesliceContext::INITIAL_TIMESLICE);

                // The test is successful if we don't have a panic here due to a
                // closed channel.
                for _ in 0..10 {
                    handler.shutdown();
                    sleep(Duration::from_millis(1));
                }

                // The test is successful if it does not get stuck.
                drop(handler);
            }
        }
    }
}
