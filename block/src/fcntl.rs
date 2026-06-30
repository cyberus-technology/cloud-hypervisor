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
    #[expect(unused, reason = "will be used in the following commits")]
    /// Get the first OFD lock for the given lock description.
    F_OFD_GETLK(&'a mut libc::flock),
}

/// Wrapper for [`libc::fcntl`] that properly sets the function arguments.
fn fcntl(fd: RawFd, arg: FcntlArg) -> libc::c_int {
    // SAFETY: We use a valid FD.
    unsafe {
        match arg {
            FcntlArg::F_OFD_SETLK(flock) => libc::fcntl(fd, libc::F_OFD_SETLK, flock),
            FcntlArg::F_OFD_GETLK(flock) => libc::fcntl(fd, libc::F_OFD_GETLK, flock),
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
}

impl LockGranularity {
    const fn l_len(self) -> u64 {
        match self {
            LockGranularity::WholeFile => 0, /* EOF */
            LockGranularity::ByteRange(_, len) => len,
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
        let flock = self.flock(lock_type, l_start);

        loop {
            let res = fcntl(file.as_raw_fd(), FcntlArg::F_OFD_SETLK(&flock));
            match res {
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
    pub fn try_acquire_lock<Fd: AsRawFd>(
        self,
        file: &Fd,
        lock_type: LockType,
    ) -> Result<(), LockError> {
        match self {
            LockGranularity::WholeFile => self.try_acquire_lock_file(file, lock_type, 0),
            LockGranularity::ByteRange(start, _) => {
                self.try_acquire_lock_file(file, lock_type, start)
            }
        }
    }

    /// Clears a lock.
    ///
    /// # Parameters
    /// - `file`: The file to clear all locks for [`LockType`].
    pub fn clear_lock<Fd: AsRawFd>(self, file: &Fd) -> Result<(), LockError> {
        self.try_acquire_lock(file, LockType::Unlock)
    }

    /// Returns a [`struct@libc::flock`] structure.
    const fn flock(self, lock_type: LockType, l_start: u64) -> libc::flock {
        libc::flock {
            l_type: lock_type.to_libc_val() as libc::c_short,
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
    #[default]
    ByteRange,
    /// Whole-file lock (l_start=0, l_len=0) - original OFD whole-file lock behavior.
    Full,
}

/// Error returned when parsing a [`LockGranularityChoice`] from a string.
#[derive(Error, Debug)]
#[error("Invalid lock granularity value: {0}, expected 'byte-range' or 'full'")]
pub struct LockGranularityParseError(String);

impl FromStr for LockGranularityChoice {
    type Err = LockGranularityParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "byte-range" => Ok(LockGranularityChoice::ByteRange),
            "full" => Ok(LockGranularityChoice::Full),
            _ => Err(LockGranularityParseError(s.to_owned())),
        }
    }
}
