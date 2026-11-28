// ABOUTME: Complete descriptor inventory for single-threaded process startup.
// ABOUTME: Allocation limits cannot enumerate descriptors retained above lowered limits.
use std::{convert::TryFrom, io, mem};

use darwin_libproc_sys::{proc_fdinfo, proc_pidinfo, PROC_PIDLISTFDS};

/// Lists all open descriptors of this process, regardless of its resource limits.
///
/// The caller must prevent concurrent opens/closes if it uses this snapshot to close descriptors.
/// An ambiguous full buffer is retried; an incomplete or malformed inventory is an error.
pub fn self_fds() -> io::Result<Vec<i32>> {
    let pid = i32::try_from(std::process::id())
        .map_err(|_| io::Error::other("process ID does not fit libproc"))?;
    inventory(|buffer| {
        let bytes = i32::try_from(mem::size_of_val(buffer))
            .map_err(|_| io::Error::other("descriptor inventory exceeds libproc size"))?;
        // SAFETY: initialized writable records cover exactly `bytes`; the kernel writes only
        // into that buffer. The returned byte count is validated before any records are used.
        let result = unsafe {
            proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buffer.as_mut_ptr().cast(), bytes)
        };
        if result <= 0 {
            let error = io::Error::last_os_error();
            return Err(if error.raw_os_error() == Some(0) {
                io::Error::other("libproc returned no descriptor inventory")
            } else {
                error
            });
        }
        Ok(result as usize)
    })
}

fn inventory(mut query: impl FnMut(&mut [proc_fdinfo]) -> io::Result<usize>) -> io::Result<Vec<i32>> {
    let mut count = 64usize;
    loop {
        let capacity = count.checked_mul(mem::size_of::<proc_fdinfo>())
            .filter(|bytes| *bytes <= i32::MAX as usize)
            .ok_or_else(|| io::Error::other("descriptor inventory size overflow"))?;
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(count).map_err(io::Error::other)?;
        buffer.resize_with(count, || proc_fdinfo { proc_fd: -1, proc_fdtype: 0 });
        let bytes = query(&mut buffer)?;
        if bytes == 0 || bytes > capacity || bytes % mem::size_of::<proc_fdinfo>() != 0 {
            return Err(io::Error::other("invalid descriptor inventory length"));
        }
        if bytes == capacity {
            count = count.checked_mul(2)
                .ok_or_else(|| io::Error::other("descriptor inventory size overflow"))?;
            continue;
        }
        let mut fds = Vec::new();
        for record in &buffer[..bytes / mem::size_of::<proc_fdinfo>()] {
            if record.proc_fd < 0 {
                return Err(io::Error::other("invalid descriptor in inventory"));
            }
            fds.push(record.proc_fd);
        }
        fds.sort_unstable();
        fds.dedup();
        return Ok(fds);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_inventory_is_retried_and_sparse_high_descriptors_are_preserved() {
        let mut calls = 0;
        let fds = inventory(|buffer| {
            calls += 1;
            if calls == 1 { return Ok(mem::size_of_val(buffer)); }
            buffer[0].proc_fd = 100_000;
            buffer[1].proc_fd = 3;
            buffer[2].proc_fd = 3;
            Ok(3 * mem::size_of::<proc_fdinfo>())
        }).unwrap();
        assert_eq!(calls, 2);
        assert_eq!(fds, [3, 100_000]);
    }

    #[test]
    fn malformed_or_missing_inventory_is_never_success() {
        for bytes in [0, 1, 64 * mem::size_of::<proc_fdinfo>() + 1] {
            assert!(inventory(|_| Ok(bytes)).is_err());
        }
        assert!(inventory(|_| Ok(mem::size_of::<proc_fdinfo>())).is_err());
        assert!(inventory(|_| Err(io::Error::other("denied"))).is_err());
    }
}
