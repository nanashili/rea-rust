//! Darwin process table through `sysctl(KERN_PROC)`.
//!
//! Compatibility owner: `readProcessSnapshot` in
//! `bridge/process/ProcessRunTokenReader.swift`. Unlike
//! `proc_pidinfo(PROC_PIDTBSDINFO)`, `KERN_PROC` reports every account's
//! processes, so ownership baselines include processes this user cannot
//! inspect further. `libc` does not define `kinfo_proc` for Apple targets;
//! the fields are read at the SDK's offsets and the layout is verified
//! against this process before any record is trusted.

use std::collections::HashMap;

const KINFO_PROC_SIZE: usize = 648;
const START_SEC: usize = 0;
const START_USEC: usize = 8;
const P_FLAG: usize = 32;
const P_STAT: usize = 36;
const P_PID: usize = 40;
const E_UID: usize = 420;
const E_PPID: usize = 560;
const E_PGID: usize = 564;
const P_LP64: i32 = 0x4;
const SZOMB: u8 = 5;

/// One `kinfo_proc` record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KernelProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub process_group_id: u32,
    pub uid: u32,
    /// `start_sec:start_usec`.
    pub identity: String,
    pub zombie: bool,
    pub pointer_size: usize,
}

fn i32_at(record: &[u8], offset: usize) -> i32 {
    i32::from_ne_bytes(record[offset..offset + 4].try_into().expect("four bytes"))
}

fn parse(record: &[u8]) -> Option<KernelProcess> {
    let pid = u32::try_from(i32_at(record, P_PID)).ok()?;
    let seconds = i64::from_ne_bytes(record[START_SEC..START_SEC + 8].try_into().ok()?);
    Some(KernelProcess {
        pid,
        parent_pid: u32::try_from(i32_at(record, E_PPID)).ok()?,
        process_group_id: u32::try_from(i32_at(record, E_PGID)).ok()?,
        uid: i32_at(record, E_UID) as u32,
        identity: format!("{seconds}:{}", i32_at(record, START_USEC)),
        zombie: record[P_STAT] == SZOMB,
        pointer_size: if i32_at(record, P_FLAG) & P_LP64 != 0 { 8 } else { 4 },
    })
}

fn errno() -> i32 {
    // SAFETY: __error returns Darwin's thread-local errno slot.
    unsafe { *libc::__error() }
}

fn query(mib: &mut [libc::c_int]) -> Result<Vec<u8>, String> {
    for _ in 0..3 {
        let mut size: libc::size_t = 0;
        // SAFETY: a null output buffer only queries the required size.
        if unsafe { libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0) } != 0 {
            return Err(format!("process_table_failed_{}", errno()));
        }
        // Headroom for processes started between the two calls.
        size += 64 * KINFO_PROC_SIZE;
        let mut bytes = vec![0_u8; size];
        // SAFETY: the owned buffer has exactly `size` bytes.
        if unsafe { libc::sysctl(mib.as_mut_ptr(), mib.len() as u32, bytes.as_mut_ptr().cast(), &mut size, std::ptr::null_mut(), 0) } != 0 {
            let error = errno();
            if error == libc::ENOMEM {
                continue;
            }
            return Err(format!("process_table_failed_{error}"));
        }
        if size % KINFO_PROC_SIZE != 0 {
            return Err(format!("process_table_failed_{}", libc::EIO));
        }
        bytes.truncate(size);
        return Ok(bytes);
    }
    Err(format!("process_table_failed_{}", libc::ENOMEM))
}

/// Check the hard-coded layout against this process's own record.
fn verify_layout() -> Result<(), String> {
    // SAFETY: getpid/getppid/getpgrp/geteuid have no preconditions.
    let (pid, parent, group, uid) = unsafe { (libc::getpid(), libc::getppid(), libc::getpgrp(), libc::geteuid()) };
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    let bytes = query(&mut mib)?;
    match bytes.chunks_exact(KINFO_PROC_SIZE).next().and_then(parse) {
        Some(own) if own.pid == pid as u32 && own.parent_pid == parent as u32 && own.process_group_id == group as u32 && own.uid == uid => Ok(()),
        _ => Err("process_table_layout_unverified".to_owned()),
    }
}

/// Every process in one `KERN_PROC_ALL` snapshot, zombies included.
pub fn snapshot() -> Result<HashMap<u32, KernelProcess>, String> {
    verify_layout()?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL, 0];
    let bytes = query(&mut mib)?;
    Ok(bytes.chunks_exact(KINFO_PROC_SIZE).filter_map(parse).map(|process| (process.pid, process)).collect())
}

/// One PID's record; `Ok(None)` when it is not in the table.
pub fn process(pid: u32) -> Result<Option<KernelProcess>, String> {
    verify_layout()?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid as libc::c_int];
    let bytes = query(&mut mib)?;
    Ok(bytes.chunks_exact(KINFO_PROC_SIZE).filter_map(parse).find(|process| process.pid == pid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_includes_this_process_and_other_accounts() {
        let table = snapshot().unwrap();
        let own = &table[&std::process::id()];
        assert_eq!(own.parent_pid, std::os::unix::process::parent_id());
        // launchd is root-owned; proc_pidinfo cannot read it, KERN_PROC can.
        assert_eq!(table.get(&1).map(|launchd| launchd.uid), Some(0));
        assert_eq!(process(std::process::id()).unwrap().as_ref(), Some(own));
        assert_eq!(process(i32::MAX as u32).unwrap(), None);
    }
}
