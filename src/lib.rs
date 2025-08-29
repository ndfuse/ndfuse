use libc::{c_char, c_int, c_long, c_uint, c_void, mode_t, size_t};
use std::fs;
use std::io::Write;
use std::sync::{LazyLock, Mutex};
mod ipc;
mod lklfs;

static FS: LazyLock<Mutex<lklfs::LKLFS>> = LazyLock::new(|| {
    Mutex::new(lklfs::LKLFS::new(
        env::var("NDFUSE_SOCKET_PATH").unwrap_or_else(|_| "/tmp/ndfuse.sock".to_string()),
        env::var("NDFUSE_LKLFS_LOG_PATH")
            .unwrap_or_else(|_| "/tmp/ndfuse-shim-lklfs.log".to_string()),
    ))
});

use std::env;

type SyscallFn = extern "C" fn(c_long, c_long, c_long, c_long, c_long, c_long, c_long) -> c_long;

static mut NEXT_SYS_CALL: Option<SyscallFn> = None;

#[unsafe(no_mangle)]
extern "C" fn hook_function(
    a1: c_long,
    a2: c_long,
    a3: c_long,
    a4: c_long,
    a5: c_long,
    a6: c_long,
    a7: c_long,
) -> c_long {
    unsafe {
        if let Some(original_syscall) = NEXT_SYS_CALL {
            // 保存しておいた元の関数を呼び出します。
            let res: Option<i64> = if a1 == syscall_numbers::x86_64::SYS_open {
                unimplemented!("open called");
            } else if a1 == syscall_numbers::x86_64::SYS_openat {
                println!("openat called");
                openat(a2 as c_int, a3 as *const c_char, a4 as c_int, a5 as mode_t)
            } else if a1 == syscall_numbers::x86_64::SYS_read {
                println!("read called");
                read(a2 as c_int, a3 as *mut c_void, a4 as size_t)
            } else if a1 == syscall_numbers::x86_64::SYS_fstat {
                println!("fstat called");
                fstat(a2 as c_int, a3 as *mut libc::stat)
            } else if a1 == syscall_numbers::x86_64::SYS_statx {
                println!("statx called");
                statx(
                    a2 as c_int,
                    a3 as *const c_char,
                    a4 as c_int,
                    a5 as c_uint,
                    a6 as *mut libc::statx,
                )
            } else if a1 == syscall_numbers::x86_64::SYS_getdents64 {
                println!("getdents64 called");
                getdents64(a2 as c_int, a3 as *mut libc::dirent64, a4 as usize)
            } else if a1 == syscall_numbers::x86_64::SYS_lgetxattr {
                println!("lgetxattr called");
                lgetxattr(
                    a2 as *const c_char,
                    a3 as *const c_char,
                    a4 as *mut std::ffi::c_void,
                    a5 as size_t,
                )
            } else if a1 == syscall_numbers::x86_64::SYS_listxattr {
                println!("listxattr called");
                listxattr(a2 as *const c_char, a3 as *mut c_char, a4 as usize)
            } else if a1 == syscall_numbers::x86_64::SYS_close {
                println!("close called");
                close(a2 as c_int)
            } else {
                Some(original_syscall(a1, a2, a3, a4, a5, a6, a7))
            };
            match res {
                Some(res) => return res,
                None => return original_syscall(a1, a2, a3, a4, a5, a6, a7),
            }
        } else {
            // `__hook_init` が呼ばれる前にこの関数が呼ばれた場合、
            // プログラムは不正な状態なのでパニックさせます。
            panic!("Hook called before initialization!");
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn __hook_init(
    _placeholder: c_long,
    sys_call_hook_ptr: *mut SyscallFn,
) -> i32 {
    println!("output from __hook_init: we can do some init work here");

    unsafe {
        NEXT_SYS_CALL = Some(*sys_call_hook_ptr);
        *sys_call_hook_ptr = hook_function;
    }

    match init() {
        Ok(_) => {
            return 0;
        }
        Err(e) => {
            eprintln!("Filesystem initialization failed: {}", e);
            return -1;
        }
    };
}

fn init() -> Result<(), anyhow::Error> {
    // Set up logging
    let log_path =
        env::var("NDFUSE_LOG_PATH").unwrap_or_else(|_| "/tmp/ndfuse-shim.log".to_string());

    // You can use env_logger or a simple file logger
    let mut log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .unwrap_or_else(|_| fs::File::create("/dev/null").unwrap());

    writeln!(log, "[INIT] ndfuse-shim library loaded").ok();

    match FS.lock().unwrap().init() {
        Ok(_) => {}
        Err(e) => {
            writeln!(log, "[INIT] Filesystem initialization failed: {}", e).ok();
            return Err(e);
        }
    };

    writeln!(log, "[INIT] Filesystem hooks initialized successfully").ok();

    Ok(())
}

pub fn statx(
    dirfd: c_int,
    pathname: *const c_char,
    flags: c_int,
    mask: c_uint,
    statxbuf: *mut libc::statx,
) -> Option<i64> {
    if let Some(d) = FS
        .lock()
        .unwrap()
        .statx(dirfd, pathname, flags, mask, statxbuf)
    {
        return Some(d);
    } else {
        return None;
    }
}

pub fn fstat(fd: c_int, stat: *mut libc::stat) -> Option<i64> {
    if let Some(d) = FS.lock().unwrap().fstat(fd, stat) {
        return Some(d);
    } else {
        return None;
    }
}

fn lgetxattr(
    path: *const c_char,
    name: *const c_char,
    value: *mut std::ffi::c_void,
    size: libc::size_t,
) -> Option<i64> {
    if let Some(d) = FS.lock().unwrap().lgetxattr(path, name, value, size) {
        return Some(d);
    } else {
        return None;
    }
}

fn listxattr(path: *const c_char, list: *mut c_char, size: usize) -> Option<i64> {
    if let Some(d) = FS.lock().unwrap().listxattr(path, list, size) {
        return Some(d);
    } else {
        return None;
    }
}

fn open(path: *const c_char, flags: c_int, mode: mode_t) -> Option<i64> {
    // Variable arguments handling for mode
    let mode: Option<mode_t> = if flags & libc::O_CREAT != 0 {
        Some(mode)
    } else {
        None
    };

    if let Some(d) = FS.lock().unwrap().open(path, flags, mode) {
        return Some(d);
    } else {
        return None;
    }
}

// Also hook openat for completeness
fn openat(dirfd: c_int, path: *const c_char, flags: c_int, mode: mode_t) -> Option<i64> {
    if dirfd == libc::AT_FDCWD {
        // If dirfd is AT_FDCWD, we can use the original open function
        return open(path, flags, mode);
    }
    return None;
}

fn close(fd: c_int) -> Option<i64> {
    if let Some(d) = FS.lock().unwrap().close(fd) {
        return Some(d);
    } else {
        return None;
    }
}

fn read(fd: c_int, buf: *mut c_void, count: size_t) -> Option<i64> {
    if let Some(d) = FS.lock().unwrap().read(fd, buf, count) {
        return Some(d);
    } else {
        return None;
    }
}

fn getdents64(fd: c_int, dirent: *mut libc::dirent64, count: usize) -> Option<i64> {
    if let Some(d) = FS.lock().unwrap().getdents64(fd, dirent, count) {
        return Some(d);
    } else {
        return None;
    }
}
