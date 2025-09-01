use command_fds::{CommandFdExt, FdMapping};
use log::{debug, error, info};
use nix::sys::socket::{AddressFamily, SockFlag, SockProtocol, SockType, socketpair};
use std::env;
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::process::Command;
use std::thread;
use std::time::Duration;
use uds::{UnixSeqpacketConn, UnixSeqpacketListener};

use crate::ipc::BinSerdes;
use crate::ipc::{Request, RequestKind};
use crate::ipc::{Response, ResponseKind, StatusCode};

mod ipc;

// LKL FFI bindings - use wrapper functions
#[link(name = "lkl_wrapper")]
unsafe extern "C" {
    fn lkl_wrapper_init() -> i32;
    fn lkl_wrapper_start_kernel(cmd_line: *const i8) -> i32;
    fn lkl_wrapper_cleanup();
    fn lkl_wrapper_sys_mknod(pathname: *const i8, mode: i32, dev: i32) -> i64;
    fn lkl_wrapper_sys_open(pathname: *const i8, flags: i32, mode: i32) -> i64;
    fn lkl_wrapper_sys_close(fd: i32) -> i64;
    fn lkl_wrapper_sys_mkdir(pathname: *const i8, mode: i32) -> i64;
    fn lkl_wrapper_sys_mount(
        source: *const i8,
        target: *const i8,
        filesystemtype: *const i8,
        mountflags: u64,
        data: *const i8,
    ) -> i64;
    fn lkl_wrapper_sys_read(fd: i32, buf: *mut u8, count: usize) -> i64;
    fn lkl_wrapper_sys_write(fd: i32, buf: *const u8, count: usize) -> i64;
    fn lkl_wrapper_sys_statx(
        dirfd: i32,
        pathname: *const i8,
        flags: u32,
        mask: u32,
        statxbuf: *mut libc::statx,
    ) -> i64;
    fn lkl_wrapper_sys_fstat(fd: i32, statbuf: *mut ipc::Stat) -> i64;
    fn lkl_wrapper_sys_getdents64(fd: i32, dirent: *mut libc::dirent64, count: u32) -> i64;
    fn lkl_wrapper_sys_mmap(
        addr: *mut u8,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut u8;
    fn lkl_wrapper_strerror(err: i32) -> *const i8;
}

// Constants
const LKL_S_IFCHR: u32 = 0o020000;
const LKL_O_RDWR: i32 = 2;
const LKL_PROT_READ: i32 = 1;
const LKL_PROT_WRITE: i32 = 2;
const LKL_MAP_PRIVATE: i32 = 2;
const LKL_MAP_ANONYMOUS: i32 = 0x20;
const LKL_MAP_POPULATE: i32 = 0x8000;

const CMD_LINE: &str = "mem=32M debug=1 loglevel=0 ";
const BUF_SIZE: usize = 4096 * 128;
const FUSE_MOUNTPOINT: &str = "/mnt";

fn lkl_strerror_safe(err: i32) -> String {
    unsafe {
        let ptr = lkl_wrapper_strerror(err);
        if ptr.is_null() {
            format!("Unknown error: {}", err)
        } else {
            CStr::from_ptr(ptr).to_string_lossy().into_owned()
        }
    }
}

fn fuse_handler_thread(lkl_fd: i32, sockfd: OwnedFd) -> Result<(), Box<dyn std::error::Error>> {
    let mut sockfd: std::fs::File = sockfd.into();
    // Allocate memory using LKL
    let mem = unsafe {
        lkl_wrapper_sys_mmap(
            std::ptr::null_mut(),
            BUF_SIZE,
            LKL_PROT_WRITE | LKL_PROT_READ,
            LKL_MAP_ANONYMOUS | LKL_MAP_PRIVATE | LKL_MAP_POPULATE,
            -1,
            0,
        )
    };

    if mem as isize == -1 {
        error!("Failed to mmap memory");
        return Err("mmap failed".into());
    }

    info!("Successfully allocated memory at {:p}", mem);
    debug!("fuse handler thread started");

    let buffer = unsafe { std::slice::from_raw_parts_mut(mem, BUF_SIZE) };

    loop {
        debug!("Waiting for data...");

        // Read from /dev/fuse using LKL
        let read_size = unsafe { lkl_wrapper_sys_read(lkl_fd, buffer.as_mut_ptr(), BUF_SIZE) };
        if read_size < 0 {
            error!(
                "lkl_sys_read failed: {}",
                lkl_strerror_safe((-read_size) as i32)
            );
            break;
        }
        debug!("Read {} bytes from /dev/fuse", read_size);

        // Write to socket
        match sockfd.write_all(&buffer[..read_size as usize]) {
            Ok(_) => debug!("Wrote {} bytes to socket", read_size),
            Err(e) => {
                error!("write to socket failed: {}", e);
                break;
            }
        }

        // Read from socket
        let mut read_buf = vec![0u8; BUF_SIZE];
        let read_size = match sockfd.read(&mut read_buf) {
            Ok(size) => size,
            Err(e) => {
                error!("read from socket failed: {}", e);
                break;
            }
        };
        debug!("Read {} bytes from socket", read_size);

        // Copy to LKL buffer
        buffer[..read_size].copy_from_slice(&read_buf[..read_size]);

        // Write to /dev/fuse using LKL
        let write_size = unsafe { lkl_wrapper_sys_write(lkl_fd, buffer.as_ptr(), read_size) };
        if write_size < 0 {
            error!(
                "lkl_sys_write failed: {}",
                lkl_strerror_safe((-write_size) as i32)
            );
            break;
        }
        debug!("Wrote {} bytes to /dev/fuse", write_size);
    }

    info!("Thread exiting");
    Ok(())
}

fn handle_client(stream: UnixSeqpacketConn) -> anyhow::Result<()> {
    info!("Client connected");

    // Handle client communication here
    // This is a placeholder - implement the actual protocol handling
    let mut buffer = [0; 1024];
    loop {
        match stream.recv(&mut buffer) {
            Ok(0) => {
                info!("Client disconnected");
                break;
            }
            Ok(n) => {
                debug!("Received {} bytes from client", n);

                match handle_request(&buffer[..n]) {
                    Ok(res) => {
                        if res.len() > 0 {
                            stream.send(&res)?;
                        }
                    }
                    Err(e) => {
                        error!("Error handling request: {}", e);
                        break;
                    }
                }
            }
            Err(e) => {
                error!("Client read error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

fn handle_request(buffer: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut reader = std::io::Cursor::new(buffer);
    let req = Request::from_reader(&mut reader)?;
    debug!("received: {:?}", &req);

    match req.kind {
        RequestKind::Init => {
            return Ok(Response {
                status: StatusCode::OK,
                retval: 0,
                kind: ResponseKind::Init(ipc::InitResponse {
                    mountpoint: FUSE_MOUNTPOINT.to_string(),
                }),
            }
            .to_bytes()?);
        }
        RequestKind::Statx(req) => {
            let path = CString::new(req.abs_path).unwrap();
            let mut statx = unsafe { std::mem::zeroed::<libc::statx>() };
            let ret = unsafe {
                lkl_wrapper_sys_statx(
                    req.dirfd,
                    path.as_ptr(),
                    req.flags as u32,
                    req.mask,
                    &mut statx as *mut libc::statx,
                )
            };
            if ret < 0 {
                debug!("lkl_sys_statx failed: {}", lkl_strerror_safe((-ret) as i32));
            }
            return Ok(Response {
                status: StatusCode::OK,
                retval: ret,
                kind: ResponseKind::Statx(statx),
            }
            .to_bytes()?);
        }
        RequestKind::Fstat(req) => {
            let mut stat = unsafe { std::mem::zeroed::<ipc::Stat>() };
            let ret = unsafe { lkl_wrapper_sys_fstat(req.fd, &mut stat as *mut ipc::Stat) };
            if ret < 0 {
                debug!("lkl_sys_fstat failed: {}", lkl_strerror_safe((-ret) as i32));
            }
            return Ok(Response {
                status: StatusCode::OK,
                retval: ret,
                kind: ResponseKind::Fstat(stat),
            }
            .to_bytes()?);
        }
        RequestKind::Getdents64(req) => {
            let mut dirents = vec![0u8; req.count as usize];
            let ret = unsafe {
                lkl_wrapper_sys_getdents64(
                    req.fd,
                    dirents.as_mut_ptr() as *mut libc::dirent64,
                    req.count,
                )
            };
            if ret < 0 {
                debug!(
                    "lkl_sys_getdents64 failed: {}",
                    lkl_strerror_safe((-ret) as i32)
                );
            }
            return Ok(Response {
                status: StatusCode::OK,
                retval: ret,
                kind: ResponseKind::Getdents64(dirents[..ret as usize].to_vec()),
            }
            .to_bytes()?);
        }
        RequestKind::Open(req) => {
            let path = CString::new(req.abs_path).unwrap();
            let ret =
                unsafe { lkl_wrapper_sys_open(path.as_ptr(), req.flags as i32, req.mode as i32) };

            if ret < 0 {
                debug!("lkl_sys_open failed: {}", lkl_strerror_safe((-ret) as i32));
            }
            return Ok(Response {
                status: StatusCode::OK,
                retval: ret,
                kind: ResponseKind::Open,
            }
            .to_bytes()?);
        }
        RequestKind::Read(req) => {
            let mut buf = vec![0u8; req.size as usize];
            let ret =
                unsafe { lkl_wrapper_sys_read(req.fh as i32, buf.as_mut_ptr(), req.size as usize) };
            if ret < 0 {
                debug!("lkl_sys_read failed: {}", lkl_strerror_safe((-ret) as i32));
            }
            return Ok(Response {
                status: StatusCode::OK,
                retval: ret,
                kind: ResponseKind::Read(buf[..ret as usize].to_vec()),
            }
            .to_bytes()?);
        }
        RequestKind::Close(req) => {
            let ret = unsafe { lkl_wrapper_sys_close(req.fh as i32) };
            if ret < 0 {
                debug!("lkl_sys_close failed: {}", lkl_strerror_safe((-ret) as i32));
            }
            return Ok(Response {
                status: StatusCode::OK,
                retval: ret,
                kind: ResponseKind::Close,
            }
            .to_bytes()?);
        }
    };
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket_path =
        env::var("NDFUSE_SOCKET_PATH").unwrap_or_else(|_| "/tmp/ndfuse.sock".to_string());

    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .format_timestamp(None)
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <path_to_fuse_binary>", args[0]);
        return Ok(());
    }

    // Initialize LKL
    let ret = unsafe { lkl_wrapper_init() };
    if ret < 0 {
        error!("Failed to initialize LKL: {}", lkl_strerror_safe(-ret));
        return Err("LKL initialization failed".into());
    }

    // Start LKL kernel
    let cmd_line = CString::new(CMD_LINE)?;
    let ret = unsafe { lkl_wrapper_start_kernel(cmd_line.as_ptr()) };
    if ret < 0 {
        error!("Failed to start LKL kernel: {}", lkl_strerror_safe(-ret));
        return Err("LKL kernel start failed".into());
    }

    // Create /dev/fuse
    let dev_fuse = CString::new("/dev/fuse")?;
    let ret =
        unsafe { lkl_wrapper_sys_mknod(dev_fuse.as_ptr(), (LKL_S_IFCHR | 0o666) as i32, 0xAE5) };
    if ret < 0 {
        error!(
            "Failed to create /dev/fuse: {}",
            lkl_strerror_safe((-ret) as i32)
        );
        return Err("Failed to create /dev/fuse".into());
    }
    info!("Successfully created /dev/fuse");

    // Open /dev/fuse
    let fd = unsafe { lkl_wrapper_sys_open(dev_fuse.as_ptr(), LKL_O_RDWR, 0) };
    if fd < 0 {
        error!(
            "Failed to open /dev/fuse: {}",
            lkl_strerror_safe((-fd) as i32)
        );
        return Err("Failed to open /dev/fuse".into());
    }
    info!("Successfully opened /dev/fuse fd={}", fd);

    // Create mount point
    let mountpoint = CString::new(FUSE_MOUNTPOINT)?;
    let ret = unsafe { lkl_wrapper_sys_mkdir(mountpoint.as_ptr(), 0o755) };
    if ret < 0 {
        error!(
            "Failed to create {} directory: {}",
            FUSE_MOUNTPOINT,
            lkl_strerror_safe((-ret) as i32)
        );
        return Err("Failed to create mount directory".into());
    }
    info!("Successfully created {} directory", FUSE_MOUNTPOINT);

    // Mount filesystem
    let source = CString::new("ndfuse")?;
    let fstype = CString::new("fuse.ndfuse")?;
    let mount_data = CString::new("max_read=131072,fd=0,rootmode=40000,user_id=0,group_id=0")?;
    let ret = unsafe {
        lkl_wrapper_sys_mount(
            source.as_ptr(),
            mountpoint.as_ptr(),
            fstype.as_ptr(),
            0,
            mount_data.as_ptr(),
        )
    };
    if ret < 0 {
        error!(
            "Failed to mount ndfuse: {}",
            lkl_strerror_safe((-ret) as i32)
        );
        return Err("Failed to mount filesystem".into());
    }
    info!("Successfully mounted ndfuse at {}", FUSE_MOUNTPOINT);

    // Create socketpair
    let (sock_parent, sock_child) = socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None::<SockProtocol>, // No specific protocol needed for AF_UNIX, SOCK_STREAM
        SockFlag::empty(),
    )
    .expect("Failed to create socketpair");
    info!("Successfully created socketpair");

    let fuse_process_handle = std::thread::spawn(move || {
        // Prepare arguments for execve
        let sock_fd_arg = "/dev/fd/3";
        let mut child_args = Vec::new();

        for arg in args.iter().skip(1) {
            if arg == "/dev/fd/ndfuse" {
                child_args.push(sock_fd_arg);
            } else {
                child_args.push(arg);
            }
        }

        info!("Child process: executing {}", child_args[0]);

        // Execute the fuse binary
        let mut cmd = Command::new(&child_args[0]);
        cmd.fd_mappings(vec![FdMapping {
            parent_fd: sock_child,
            child_fd: 3,
        }])
        .unwrap();
        if child_args.len() > 1 {
            cmd.args(&child_args[1..]);
        }

        match cmd.status() {
            Ok(s) => {
                error!("Child process exited with status: {}", s);
            }
            Err(e) => {
                error!("Failed to execute child process: {}", e);
            }
        }
    });

    // Start fuse handler thread
    let fuse_exchange_handle = thread::spawn(move || {
        if let Err(e) = fuse_handler_thread(fd as i32, sock_parent) {
            error!("Fuse handler thread error: {}", e);
        }
    });
    info!("Created thread for fuse handling");

    // Remove existing socket file and create new one.
    let _ = std::fs::remove_file(&socket_path);
    let listener = UnixSeqpacketListener::bind(&socket_path)?;
    info!("Waiting for seqpacket connections on {}", &socket_path);

    // Create a simple polling loop
    let shim_listen_handle = thread::spawn(move || {
        loop {
            // Try to create or receive seqpacket connection
            match listener.accept_unix_addr() {
                Ok((conn, _)) => {
                    info!("Seqpacket connection established");
                    thread::spawn(move || {
                        if let Err(e) = handle_client(conn) {
                            error!("Client handler error: {}", e);
                        }
                    });
                }
                Err(_) => {
                    // Socket file doesn't exist yet, continue polling
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    });

    // Wait for any thread to finish (indicating an error condition)
    let handles = vec![
        fuse_process_handle,
        fuse_exchange_handle,
        shim_listen_handle,
    ];

    loop {
        // Check if any thread has finished
        for i in 0..handles.len() {
            if handles[i].is_finished() {
                error!("Thread {} has finished unexpectedly", i);
                unsafe {
                    lkl_wrapper_cleanup();
                }
                return Err("A critical thread has terminated".into());
            }
        }

        std::thread::sleep(Duration::from_millis(100));
    }
}
