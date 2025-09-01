use crate::lklfs::LKLFS;
use libc::{c_char, c_int, c_long, c_uint, c_void, mode_t, size_t};
use log::debug;
use std::env;
use std::fs;
use std::io::Write;
use std::sync::{LazyLock, Mutex};
mod ipc;
mod lklfs;

static FS: LazyLock<Mutex<Option<LKLFS>>> = LazyLock::new(|| Mutex::new(None));

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
            let mut fs_lock = match FS.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    eprintln!("Failed to acquire FS lock: {}", e);
                    return original_syscall(a1, a2, a3, a4, a5, a6, a7);
                }
            };
            let fs = match fs_lock.as_mut() {
                None => {
                    eprintln!("Filesystem not initialized");
                    return original_syscall(a1, a2, a3, a4, a5, a6, a7);
                }
                Some(f) => f,
            };

            let res: Option<i64> = if a1 == syscall_numbers::x86_64::SYS_open {
                debug!("open called");
                fs.open(a2 as *const c_char, a3 as c_int, a4 as mode_t)
            } else if a1 == syscall_numbers::x86_64::SYS_openat {
                debug!("openat called");
                if a2 as c_int == libc::AT_FDCWD {
                    fs.open(a3 as *const c_char, a4 as c_int, a5 as mode_t)
                } else {
                    None
                }
            } else if a1 == syscall_numbers::x86_64::SYS_read {
                debug!("read called");
                fs.read(a2 as c_int, a3 as *mut c_void, a4 as size_t)
            } else if a1 == syscall_numbers::x86_64::SYS_fstat {
                debug!("fstat called");
                fs.fstat(a2 as c_int, a3 as *mut libc::stat)
            } else if a1 == syscall_numbers::x86_64::SYS_statx {
                debug!("statx called");
                fs.statx(
                    a2 as c_int,
                    a3 as *const c_char,
                    a4 as c_int,
                    a5 as c_uint,
                    a6 as *mut libc::statx,
                )
            } else if a1 == syscall_numbers::x86_64::SYS_getdents64 {
                debug!("getdents64 called");
                fs.getdents64(a2 as c_int, a3 as *mut libc::dirent64, a4 as usize)
            } else if a1 == syscall_numbers::x86_64::SYS_lgetxattr {
                debug!("lgetxattr called");
                fs.lgetxattr(
                    a2 as *const c_char,
                    a3 as *const c_char,
                    a4 as *mut std::ffi::c_void,
                    a5 as size_t,
                )
            } else if a1 == syscall_numbers::x86_64::SYS_listxattr {
                debug!("listxattr called");
                fs.listxattr(a2 as *const c_char, a3 as *mut c_char, a4 as usize)
            } else if a1 == syscall_numbers::x86_64::SYS_close {
                debug!("close called");
                fs.close(a2 as c_int)
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

            // Not to return '-1' to avoid hang-up
            return 0;
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

    let fs = LKLFS::new(
        env::var("NDFUSE_SOCKET_PATH").unwrap_or_else(|_| "/tmp/ndfuse.sock".to_string()),
        env::var("NDFUSE_LKLFS_LOG_PATH")
            .unwrap_or_else(|_| "/tmp/ndfuse-shim-lklfs.log".to_string()),
    )?;
    FS.lock().unwrap().replace(fs);

    writeln!(log, "[INIT] Filesystem hooks initialized successfully").ok();

    Ok(())
}
