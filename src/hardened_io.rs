//! THET v21 - hardened file I/O

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    pub ino: u64,
    pub size: u64,
    pub mtime_ns: u64,
    pub ctime_ns: u64,
}

pub fn fingerprint(fd: RawFd) -> io::Result<Fingerprint> {
    #[cfg(target_os = "linux")]
    {
        let mut stx: libc::statx = unsafe { std::mem::zeroed() };
        let ret = unsafe {
            libc::statx(
                fd,
                b"\0".as_ptr() as *const libc::c_char,
                libc::AT_EMPTY_PATH | libc::AT_STATX_SYNC_AS_STAT,
                libc::STATX_INO | libc::STATX_SIZE | libc::STATX_MTIME | libc::STATX_CTIME,
                &mut stx,
            )
        };
        if ret == 0 {
            return Ok(Fingerprint {
                ino: stx.stx_ino,
                size: stx.stx_size,
                mtime_ns: (stx.stx_mtime.tv_sec as u64) * 1_000_000_000
                    + stx.stx_mtime.tv_nsec as u64,
                ctime_ns: (stx.stx_ctime.tv_sec as u64) * 1_000_000_000
                    + stx.stx_ctime.tv_nsec as u64,
            });
        }
    }
    let st = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            return Err(io::Error::last_os_error());
        }
        st
    };
    Ok(Fingerprint {
        ino: st.st_ino,
        size: st.st_size as u64,
        mtime_ns: (st.st_mtime as u64) * 1_000_000_000 + (st.st_mtime_nsec as u64),
        ctime_ns: (st.st_ctime as u64) * 1_000_000_000 + (st.st_ctime_nsec as u64),
    })
}

pub fn lock_exclusive(fd: RawFd) -> io::Result<()> {
    let r = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if r != 0 {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "flock failed: file is locked by another process",
        ));
    }
    let fl = libc::flock {
        l_type: libc::F_WRLCK as i16,
        l_whence: libc::SEEK_SET as i16,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
    };
    let r = unsafe { libc::fcntl(fd, libc::F_OFD_SETLK, &fl) };
    if r != 0 {
        unsafe { libc::flock(fd, libc::LOCK_UN) };
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn unlock(fd: RawFd) {
    unsafe {
        libc::flock(fd, libc::LOCK_UN);
        let fl = libc::flock {
            l_type: libc::F_UNLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        libc::fcntl(fd, libc::F_OFD_SETLK, &fl);
    }
}

pub fn has_mmap_users(ino: u64, device: u64) -> io::Result<bool> {
    let proc = std::fs::read_dir("/proc")?;
    for entry in proc.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let maps_path = entry.path().join("maps");
        let content = match std::fs::read_to_string(&maps_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 { continue; }
            let dev_str = parts[3];
            let ino_str = parts[4];
            let Ok(line_ino) = ino_str.parse::<u64>() else { continue };
            if line_ino != ino { continue; }
            let dev_parts: Vec<&str> = dev_str.split(':').collect();
            if dev_parts.len() != 2 { continue; }
            let Ok(major) = u32::from_str_radix(dev_parts[0], 16) else { continue };
            let Ok(minor) = u32::from_str_radix(dev_parts[1], 16) else { continue };
            let line_dev = unsafe { libc::makedev(major, minor) } as u64;
            if line_dev == device { return Ok(true); }
        }
    }
    Ok(false)
}

pub fn atomic_rename_noreplace(src: &Path, dst: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        const RENAME_NOREPLACE: libc::c_uint = 1;

        let src_c = CString::new(src.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "src has NUL"))?;
        let dst_c = CString::new(dst.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "dst has NUL"))?;

        let ret = unsafe {
            libc::syscall(
                libc::SYS_renameat2 as libc::c_long,
                libc::AT_FDCWD as libc::c_long,
                src_c.as_ptr() as libc::c_long,
                libc::AT_FDCWD as libc::c_long,
                dst_c.as_ptr() as libc::c_long,
                RENAME_NOREPLACE as libc::c_long,
            )
        };
        if ret == 0 { return Ok(()); }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOSYS)
            && err.raw_os_error() != Some(libc::EINVAL)
        {
            return Err(err);
        }
    }
    std::fs::rename(src, dst)
}

pub fn open_locked(path: &Path) -> io::Result<(File, Fingerprint)> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let fd = f.as_raw_fd();

    lock_exclusive(fd)?;

    let fp = fingerprint(fd)?;

    let dev = unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st) != 0 {
            unlock(fd);
            return Err(io::Error::last_os_error());
        }
        st.st_dev
    };
    if has_mmap_users(fp.ino, dev).unwrap_or(false) {
        unlock(fd);
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "file is mmap'd by another process; refusing to decrypt",
        ));
    }

    Ok((f, fp))
}
