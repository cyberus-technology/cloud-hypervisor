// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! Helpers for advisory file locking.
//!
//! Under the hood, the implementation uses OFD locks for the entire file,
//! as described in [[0]]. The advantage over `F_SETLKW` (currently used by
//! Rust std: `File::try_lock()`) is that only the very last `close()` on a
//! file descriptor releases the lock. This prevents mistakes and unexpected
//! behavior.
//!
//! [0]: <https://apenwarr.ca/log/20101213>.

use std::fmt::Debug;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::str::FromStr;

use thiserror::Error;

/// Errors that can happen when working with file locks.
#[derive(Error, Debug)]
pub enum LockError {
    /// The file is already locked.
    #[error("The file is already locked")]
    AlreadyLocked,
    /// IO error.
    #[error("The lock state could not be checked or set")]
    Io(#[source] io::Error),
}

/// Commands for use with [`fcntl`].
#[allow(non_camel_case_types)]
enum FcntlArg<'a> {
    /// Set an OFD lock from the given lock description.
    F_OFD_SETLK(&'a libc::flock),
    /// Get the first OFD lock for the given lock description.
    F_OFD_GETLK(&'a mut libc::flock),
}

/// Wrapper for [`libc::fcntl`] that properly sets the function arguments.
fn fcntl(fd: RawFd, mut arg: FcntlArg) -> Result<(), LockError> {
    loop {
        // SAFETY:
        // - `F_OFD_SETLK` and `F_OFD_GETLK` fcntl calls handle invalid file descriptors.
        // - `F_OFD_SETLK` does not modify `flock`.
        // - `F_OFD_GETLK` uses a mutable pointer to `flock`.
        let result = unsafe {
            match &mut arg {
                FcntlArg::F_OFD_SETLK(flock) => {
                    libc::fcntl(fd, libc::F_OFD_SETLK, *flock as *const libc::flock)
                }
                FcntlArg::F_OFD_GETLK(flock) => {
                    libc::fcntl(fd, libc::F_OFD_GETLK, *flock as *mut libc::flock)
                }
            }
        };
        match result {
            0 => return Ok(()),
            -1 => {
                let io_error = io::Error::last_os_error();
                let errno = io_error.raw_os_error().unwrap();
                match errno {
                    // See man page for error code:
                    // <https://man7.org/linux/man-pages/man2/fcntl.2.html>
                    libc::EAGAIN | libc::EACCES => return Err(LockError::AlreadyLocked),
                    libc::EINTR => continue,
                    _ => return Err(LockError::Io(io_error)),
                }
            }
            val => panic!("Unexpected return value from fcntl(): {val}"),
        }
    }
}

/// Describes the type of lock you want to set.
#[derive(Clone, Copy, Debug)]
pub enum LockType {
    /// Clear a lock.
    Unlock,
    /// Set a write lock (exclusive).
    Write,
    /// Set a read lock (shared).
    Read,
}

impl LockType {
    pub const fn to_libc_val(self) -> libc::c_int {
        match self {
            Self::Unlock => libc::F_UNLCK as libc::c_int,
            Self::Write => libc::F_WRLCK as libc::c_int,
            Self::Read => libc::F_RDLCK as libc::c_int,
        }
    }
}

/// Amount of bytes by which the first lock is offset from the start of the file.
const QEMU_LOCK_OFFSET: u64 = 100;
/// Amount of bytes by which the first unshared lock is offset from the start of the file.
///
/// Unsharing is equivalent to marking lock as exclusive.
///
/// # Example
///
/// Setting `QEMU_LOCK_OFFSET` + `QEMU_READ_BYTE` indicates a reader lock that may be shared with
/// other readers.
/// Setting `QEMU_UNSHARE_LOCK_OFFSET` + `QEMU_READ_BYTE` additionally indicates, that the reader
/// lock is "unshared" (exclusive) and may not be shared with others.
const QEMU_UNSHARE_LOCK_OFFSET: u64 = 200;

/// Read permission lock index for QEMU.
const QEMU_READ_BYTE: u64 = 0;
/// Write permission lock index for QEMU.
const QEMU_WRITE_BYTE: u64 = 1;

/// The granularity of the advisory lock.
///
/// The granularity has significant implications in typical cloud deployments
/// with network storage. The Linux kernel will sync advisory locks to network
/// file systems, but these backends may have different policies and handle
/// locks differently. For example, Netapp speaks a NFS API but will treat
/// advisory OFD locks for the whole file as mandatory locks, whereas byte-range
/// locks for the whole file will remain advisory [0].
///
/// As it is a valid use case to prevent multiple CHV instances from accessing
/// the same disk but disk management software (e.g., Cinder in OpenStack)
/// should be able to snapshot disks while VMs are running, we need special
/// control over the lock granularity. Therefore, it is a valid use case to lock
/// the whole byte range of a disk image without technically locking the whole
/// file - to get the best of both worlds.
///
/// [0] https://kb.netapp.com/on-prem/ontap/da/NAS/NAS-KBs/How_is_Mandatory_Locking_supported_for_NFSv4_on_ONTAP_9
#[derive(Clone, Copy, Debug)]
pub enum LockGranularity {
    WholeFile,
    ByteRange(u64 /* from, inclusive */, u64 /* len */),
    QemuCompatible,
}

impl LockGranularity {
    const fn l_len(self) -> u64 {
        match self {
            LockGranularity::WholeFile => 0, /* EOF */
            LockGranularity::ByteRange(_, len) => len,
            // QEMU uses multiple one byte long locks.
            LockGranularity::QemuCompatible => 1,
        }
    }

    /// Internal implementation of [`Self::try_acquire_lock`] for [`LockGranularity::WholeFile`] and
    /// [`LockGranularity::ByteRange`].
    fn try_acquire_lock_file<Fd: AsRawFd>(
        self,
        file: &Fd,
        lock_type: LockType,
        l_start: u64,
    ) -> Result<(), LockError> {
        let flock = self.flock(lock_type.to_libc_val(), l_start);

        fcntl(file.as_raw_fd(), FcntlArg::F_OFD_SETLK(&flock))
    }

    /// Releases all locks not required for `lock_type`.
    ///
    /// Used to roll back a lock acquisition attempt to a previously acquired lock.
    fn release_unneeded_locks_qemu<Fd: AsRawFd>(
        self,
        file: &Fd,
        lock_type: LockType,
    ) -> Result<(), LockError> {
        let flocks = match lock_type {
            LockType::Unlock => vec![
                LockGranularity::QemuCompatible
                    .flock(libc::F_UNLCK, QEMU_LOCK_OFFSET + QEMU_READ_BYTE),
                LockGranularity::QemuCompatible
                    .flock(libc::F_UNLCK, QEMU_LOCK_OFFSET + QEMU_WRITE_BYTE),
                LockGranularity::QemuCompatible
                    .flock(libc::F_UNLCK, QEMU_UNSHARE_LOCK_OFFSET + QEMU_READ_BYTE),
                LockGranularity::QemuCompatible
                    .flock(libc::F_UNLCK, QEMU_UNSHARE_LOCK_OFFSET + QEMU_WRITE_BYTE),
            ],
            LockType::Write => vec![],
            LockType::Read => vec![
                LockGranularity::QemuCompatible
                    .flock(libc::F_UNLCK, QEMU_LOCK_OFFSET + QEMU_WRITE_BYTE),
            ],
        };

        let mut first_error = None;
        for flock in flocks {
            if let Err(error) = fcntl(file.as_raw_fd(), FcntlArg::F_OFD_SETLK(&flock)) {
                first_error.get_or_insert(error);
            }
        }
        if let Some(first_error) = first_error {
            return Err(first_error);
        }
        Ok(())
    }

    /// Internal implementation of [`Self::try_acquire_lock`] for [`LockGranularity::QemuCompatible`].
    fn try_acquire_lock_qemu<Fd: AsRawFd>(
        self,
        file: &Fd,
        lock_type: LockType,
        current_lock_status: LockType,
    ) -> Result<(), LockError> {
        let flocks = match lock_type {
            LockType::Unlock => vec![
                LockGranularity::QemuCompatible
                    .flock(libc::F_UNLCK, QEMU_LOCK_OFFSET + QEMU_READ_BYTE),
                LockGranularity::QemuCompatible
                    .flock(libc::F_UNLCK, QEMU_LOCK_OFFSET + QEMU_WRITE_BYTE),
                LockGranularity::QemuCompatible
                    .flock(libc::F_UNLCK, QEMU_UNSHARE_LOCK_OFFSET + QEMU_READ_BYTE),
                LockGranularity::QemuCompatible
                    .flock(libc::F_UNLCK, QEMU_UNSHARE_LOCK_OFFSET + QEMU_WRITE_BYTE),
            ],
            LockType::Write => vec![
                LockGranularity::QemuCompatible
                    .flock(libc::F_RDLCK, QEMU_LOCK_OFFSET + QEMU_READ_BYTE),
                LockGranularity::QemuCompatible
                    .flock(libc::F_RDLCK, QEMU_LOCK_OFFSET + QEMU_WRITE_BYTE),
                LockGranularity::QemuCompatible
                    .flock(libc::F_RDLCK, QEMU_UNSHARE_LOCK_OFFSET + QEMU_WRITE_BYTE),
            ],
            LockType::Read => vec![
                LockGranularity::QemuCompatible
                    .flock(libc::F_RDLCK, QEMU_LOCK_OFFSET + QEMU_READ_BYTE),
                LockGranularity::QemuCompatible
                    .flock(libc::F_RDLCK, QEMU_UNSHARE_LOCK_OFFSET + QEMU_WRITE_BYTE),
            ],
        };

        for flock in flocks {
            if let Err(error) = fcntl(file.as_raw_fd(), FcntlArg::F_OFD_SETLK(&flock)) {
                if let LockType::Unlock = lock_type {
                    return Err(error);
                }
                let _ = self.release_unneeded_locks_qemu(file, current_lock_status);
                return Err(error);
            }
        }

        if let Err(error) = self.check_lock_success_qemu(file, lock_type) {
            let _ = self.release_unneeded_locks_qemu(file, current_lock_status);
            return Err(error);
        }
        Ok(())
    }

    /// Tries to acquire a lock using [`fcntl`] with respect to the given
    /// parameters.
    ///
    /// Please note that `fcntl()` OFD locks are **advisory locks**, which do not
    /// prevent to `open()` a file if a lock is already placed.
    ///
    /// # Parameters
    /// - `file`: The file to acquire a lock for [`LockType`]. The file's state will
    ///   be logically mutated, but not technically.
    /// - `lock_type`: The [`LockType`]
    /// - `current_lock_status`: Already held locks on this `file`.
    ///   Used for [`LockGranularity::QemuCompatible`] to roll back to if locking fails.
    pub fn try_acquire_lock<Fd: AsRawFd>(
        self,
        file: &Fd,
        lock_type: LockType,
        current_lock_status: LockType,
    ) -> Result<(), LockError> {
        match self {
            LockGranularity::WholeFile => self.try_acquire_lock_file(file, lock_type, 0),
            LockGranularity::ByteRange(start, _) => {
                self.try_acquire_lock_file(file, lock_type, start)
            }
            LockGranularity::QemuCompatible => {
                self.try_acquire_lock_qemu(file, lock_type, current_lock_status)
            }
        }
    }

    /// Clears a lock.
    ///
    /// # Parameters
    /// - `file`: The file to clear all locks for [`LockType`].
    pub fn clear_lock<Fd: AsRawFd>(self, file: &Fd) -> Result<(), LockError> {
        self.try_acquire_lock(file, LockType::Unlock, LockType::Unlock)
    }

    /// Checks whether any conflicting locks are set.
    ///
    /// Returns an error if a conflicting lock is set.
    fn check_lock_success_qemu<Fd: AsRawFd>(
        &self,
        file: &Fd,
        lock_type: LockType,
    ) -> Result<(), LockError> {
        let flocks = match lock_type {
            LockType::Unlock => vec![],
            LockType::Write => vec![
                LockGranularity::QemuCompatible
                    .flock(libc::F_WRLCK, QEMU_UNSHARE_LOCK_OFFSET + QEMU_READ_BYTE),
                LockGranularity::QemuCompatible
                    .flock(libc::F_WRLCK, QEMU_UNSHARE_LOCK_OFFSET + QEMU_WRITE_BYTE),
                LockGranularity::QemuCompatible
                    .flock(libc::F_WRLCK, QEMU_LOCK_OFFSET + QEMU_WRITE_BYTE),
            ],
            LockType::Read => vec![
                LockGranularity::QemuCompatible
                    .flock(libc::F_WRLCK, QEMU_UNSHARE_LOCK_OFFSET + QEMU_READ_BYTE),
                LockGranularity::QemuCompatible
                    .flock(libc::F_WRLCK, QEMU_LOCK_OFFSET + QEMU_WRITE_BYTE),
            ],
        };

        for mut flock in flocks {
            fcntl(file.as_raw_fd(), FcntlArg::F_OFD_GETLK(&mut flock))?;

            if flock.l_type as libc::c_int != libc::F_UNLCK {
                return Err(LockError::AlreadyLocked);
            }
        }
        Ok(())
    }

    /// Returns a [`struct@libc::flock`] structure.
    const fn flock(self, lock_type: libc::c_int, l_start: u64) -> libc::flock {
        libc::flock {
            l_type: lock_type as libc::c_short,
            l_whence: libc::SEEK_SET as libc::c_short,
            l_start: l_start as libc::c_long,
            l_len: self.l_len() as libc::c_long,
            l_pid: 0, /* filled by callee */
        }
    }
}

/// User-facing choice for the lock granularity.
///
/// This allows external management software to create snapshots of the disk
/// image. Without a byte-range lock, some NFS implementations may treat the
/// entire file as exclusively locked and prevent such operations (e.g. NetApp).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum LockGranularityChoice {
    /// Byte-range lock covering [0, size).
    ByteRange,
    /// Whole-file lock (l_start=0, l_len=0) - original OFD whole-file lock behavior.
    Full,
    /// Locking scheme that mimics QEMU's marker byte based locking scheme.
    #[default]
    QemuCompatible,
}

/// Error returned when parsing a [`LockGranularityChoice`] from a string.
#[derive(Error, Debug)]
#[error("Invalid lock granularity value: {0}, expected 'byte-range', 'full' or 'qemu-compatible'")]
pub struct LockGranularityParseError(String);

impl FromStr for LockGranularityChoice {
    type Err = LockGranularityParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "byte-range" => Ok(LockGranularityChoice::ByteRange),
            "full" => Ok(LockGranularityChoice::Full),
            "qemu-compatible" => Ok(Self::QemuCompatible),
            _ => Err(LockGranularityParseError(s.to_owned())),
        }
    }
}
