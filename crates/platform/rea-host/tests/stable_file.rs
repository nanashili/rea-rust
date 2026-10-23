#![cfg(unix)]
//! Real native handles with controlled interleavings at the host interface.
use rea_core::cancellation::Cancellation;
use rea_host::{
    fs::stable_file::{self, CloseOutcome, FileAccess, FileError, Fingerprint, IoKind, ReadIssue},
    fs::unix_file::UnixFiles,
};
use rustix::fd::OwnedFd;
use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[derive(Clone, Copy, Debug, Default)]
enum Action {
    #[default]
    Normal,
    Replace,
    Grow,
    Cancel,
    Fail,
}

#[derive(Debug)]
struct Controlled {
    path: PathBuf,
    cancellation: Cancellation,
    action: Action,
    cancel_on_close: bool,
    fail_close: AtomicUsize,
    released_error: bool,
    reads: AtomicUsize,
    opens: AtomicUsize,
    closes: AtomicUsize,
}
impl Controlled {
    fn new(path: &Path) -> Self {
        Self {
            path: path.into(),
            cancellation: Cancellation::default(),
            action: Action::Normal,
            cancel_on_close: false,
            fail_close: AtomicUsize::new(0),
            released_error: false,
            reads: AtomicUsize::new(0),
            opens: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
        }
    }
}
fn denied() -> FileError {
    FileError {
        kind: IoKind::AccessDenied,
        system_code: Some("EACCES"),
        source: io::ErrorKind::PermissionDenied.into(),
    }
}
impl FileAccess for Controlled {
    type Handle = OwnedFd;
    fn lstat(&self, path: &Path) -> Result<Fingerprint, FileError> {
        UnixFiles.lstat(path)
    }
    fn open_regular_candidate(&self, path: &Path) -> Result<OwnedFd, FileError> {
        self.opens.fetch_add(1, Ordering::SeqCst);
        UnixFiles.open_regular_candidate(path)
    }
    fn stat(&self, handle: &OwnedFd) -> Result<Fingerprint, FileError> {
        UnixFiles.stat(handle)
    }
    fn read(&self, handle: &OwnedFd, output: &mut [u8]) -> Result<usize, FileError> {
        let first = self.reads.fetch_add(1, Ordering::SeqCst) == 0;
        if matches!(self.action, Action::Fail) {
            return Err(denied());
        }
        let count = UnixFiles.read(handle, output)?;
        if first {
            match self.action {
                Action::Replace => {
                    let replacement = self.path.with_extension("replacement");
                    fs::write(&replacement, b"xyz").unwrap();
                    fs::rename(replacement, &self.path).unwrap();
                }
                Action::Grow => fs::OpenOptions::new()
                    .append(true)
                    .open(&self.path)
                    .unwrap()
                    .write_all(b"0123456789")
                    .unwrap(),
                Action::Cancel => {
                    self.cancellation.cancel("during read");
                }
                _ => {}
            }
        }
        Ok(count)
    }
    fn close(&self, handle: OwnedFd) -> CloseOutcome<OwnedFd> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        if self.cancel_on_close {
            self.cancellation.cancel("during finalization");
        }
        if self.fail_close.load(Ordering::SeqCst) > 0 {
            self.fail_close.fetch_sub(1, Ordering::SeqCst);
            return CloseOutcome::Retained {
                handle,
                error: denied(),
            };
        }
        let result = UnixFiles.close(handle);
        if self.released_error && matches!(result, CloseOutcome::Released) {
            CloseOutcome::ReleasedWithError(FileError {
                kind: IoKind::Other,
                system_code: Some("EIO"),
                source: io::Error::other("post-release I/O failure"),
            })
        } else {
            result
        }
    }
}

#[test]
fn reads_and_hashes_real_bytes_without_following_a_selected_symlink() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("artifact");
    fs::write(&path, b"abc").unwrap();
    let access = Arc::new(Controlled::new(&path));
    let snapshot = stable_file::read(access.clone(), &path, 3, &access.cancellation).unwrap();
    assert_eq!(snapshot.bytes, b"abc");
    assert_eq!(
        snapshot.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(access.opens.load(Ordering::SeqCst), 1);
    assert_eq!(access.closes.load(Ordering::SeqCst), 1);
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    for bad in [&link, directory.path()] {
        assert!(matches!(
            stable_file::read(access.clone(), bad, 3, &access.cancellation)
                .unwrap_err()
                .primary,
            Some(ReadIssue::InvalidPath)
        ));
    }
    assert_eq!(access.opens.load(Ordering::SeqCst), 1);
    directory.close().unwrap();
}

#[test]
fn rejects_oversize_and_cancelled_admission_without_opening_a_descriptor() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("artifact");
    fs::write(&path, b"abc").unwrap();
    let access = Arc::new(Controlled::new(&path));
    assert!(matches!(
        stable_file::read(access.clone(), &path, 2, &access.cancellation)
            .unwrap_err()
            .primary,
        Some(ReadIssue::Limit { maximum_bytes: 2 })
    ));
    assert!(access.cancellation.cancel("first reason"));
    assert!(!access.cancellation.cancel("later reason"));
    assert!(
        matches!(stable_file::read(access.clone(),&path,3,&access.cancellation).unwrap_err().primary,Some(ReadIssue::Cancelled(reason)) if reason=="first reason")
    );
    assert_eq!(access.opens.load(Ordering::SeqCst), 0);
    assert_eq!(access.closes.load(Ordering::SeqCst), 0);
    directory.close().unwrap();
}

#[test]
fn path_replacement_growth_and_active_cancellation_are_not_successful_snapshots() {
    for action in [Action::Replace, Action::Grow, Action::Cancel] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("artifact");
        fs::write(&path, b"abc").unwrap();
        let mut access = Controlled::new(&path);
        access.action = action;
        let access = Arc::new(access);
        let failure =
            stable_file::read(access.clone(), &path, 8, &access.cancellation).unwrap_err();
        match action {
            Action::Replace => assert!(matches!(
                failure.primary,
                Some(ReadIssue::Changed("during read"))
            )),
            Action::Grow => assert!(matches!(
                failure.primary,
                Some(ReadIssue::Limit { maximum_bytes: 8 })
            )),
            Action::Cancel => assert!(
                matches!(failure.primary,Some(ReadIssue::Cancelled(reason)) if reason=="during read")
            ),
            _ => unreachable!(),
        }
        assert!(failure.completed.is_none());
        assert!(failure.retained.is_none());
        assert!(failure.cleanup_failures.is_empty());
        assert_eq!(access.closes.load(Ordering::SeqCst), 1);
        directory.close().unwrap();
    }
}

#[test]
fn finalization_cancellation_retains_completed_facts_and_exact_cleanup_retry() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("artifact");
    fs::write(&path, b"abc").unwrap();
    let mut access = Controlled::new(&path);
    access.cancel_on_close = true;
    access.fail_close.store(1, Ordering::SeqCst);
    let access = Arc::new(access);
    let mut failure =
        stable_file::read(access.clone(), &path, 3, &access.cancellation).unwrap_err();
    assert!(
        matches!(&failure.primary,Some(ReadIssue::Cancelled(reason)) if reason=="during finalization")
    );
    assert_eq!(failure.completed.as_ref().unwrap().bytes, b"abc");
    assert!(!failure.latest_cleanup_failure().unwrap().resource_released);
    assert!(failure.retained.as_ref().unwrap().retains_resource());
    failure.retry_cleanup().unwrap();
    assert!(failure.retained.is_none());
    assert_eq!(failure.cleanup_failures.len(), 1);
    failure.retry_cleanup().unwrap();
    assert_eq!(access.opens.load(Ordering::SeqCst), 1);
    assert_eq!(access.closes.load(Ordering::SeqCst), 2);
    assert_eq!(failure.completed.as_ref().unwrap().bytes, b"abc");
    directory.close().unwrap();
}

#[test]
fn read_failure_precedes_late_cancellation_and_close_failure_remains_attributed() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("artifact");
    fs::write(&path, b"abc").unwrap();
    let mut access = Controlled::new(&path);
    access.action = Action::Fail;
    access.cancel_on_close = true;
    access.fail_close.store(1, Ordering::SeqCst);
    let access = Arc::new(access);
    let mut failure =
        stable_file::read(access.clone(), &path, 3, &access.cancellation).unwrap_err();
    assert!(
        matches!(&failure.primary,Some(ReadIssue::Io{stage:"read",error}) if error.kind==IoKind::AccessDenied)
    );
    assert!(failure.completed.is_none());
    assert!(failure.retained.is_some());
    failure.retry_cleanup().unwrap();
    assert!(failure.retained.is_none());
    assert_eq!(failure.cleanup_failures.len(), 1);
    assert_eq!(access.closes.load(Ordering::SeqCst), 2);
    assert!(matches!(
        failure.primary,
        Some(ReadIssue::Io { stage: "read", .. })
    ));
    directory.close().unwrap();
}

#[test]
fn released_close_errors_preserve_observations_without_retrying_a_reusable_fd_number() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("artifact");
    fs::write(&path, b"abc").unwrap();
    let mut access = Controlled::new(&path);
    access.released_error = true;
    let access = Arc::new(access);
    let mut failure =
        stable_file::read(access.clone(), &path, 3, &access.cancellation).unwrap_err();
    assert!(failure.primary.is_none());
    assert_eq!(failure.completed.as_ref().unwrap().bytes, b"abc");
    assert!(failure.latest_cleanup_failure().unwrap().resource_released);
    assert_eq!(failure.cleanup_failures.len(), 1);
    assert!(failure.retained.is_none());
    failure.retry_cleanup().unwrap();
    assert_eq!(access.closes.load(Ordering::SeqCst), 1);
    directory.close().unwrap();
}

#[test]
fn every_failed_cleanup_retry_remains_available_after_later_recovery() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("artifact");
    fs::write(&path, b"abc").unwrap();
    let access = Controlled::new(&path);
    access.fail_close.store(3, Ordering::SeqCst);
    let access = Arc::new(access);
    let mut failure =
        stable_file::read(access.clone(), &path, 3, &access.cancellation).unwrap_err();

    assert_eq!(failure.cleanup_failures.len(), 1);
    assert!(failure.retry_cleanup().is_err());
    assert_eq!(failure.cleanup_failures.len(), 2);
    assert!(failure.retry_cleanup().is_err());
    assert_eq!(failure.cleanup_failures.len(), 3);
    assert!(failure.retry_cleanup().is_ok());
    assert!(failure.retained.is_none());
    assert_eq!(failure.cleanup_failures.len(), 3);
    assert_eq!(access.closes.load(Ordering::SeqCst), 4);
    directory.close().unwrap();
}
