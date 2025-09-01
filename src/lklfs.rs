use crate::ipc;
use crate::ipc::FstatRequest;
use crate::ipc::Getdents64Request;
use crate::ipc::{BinSerdes, StatusCode};
use crate::ipc::{CloseRequest, OpenRequest, ReadRequest, StatxRequest};
use crate::ipc::{Request, RequestKind, Response, ResponseKind};
use libc::{c_char, c_int, c_long, c_uint};
use log::{debug, error, info};
use std::collections::HashMap;
use std::path;
use std::path::PathBuf;
use std::sync::Mutex;

pub struct LKLFS {
    mountpoint: path::PathBuf,
    socket_path: String,
    log_path: String,
    conn: Option<uds::UnixSeqpacketConn>,

    // (fd for local kernel, fh for fuse)
    fds: Mutex<HashMap<c_int, FileHandle>>,
}

pub struct FileHandle {
    fh: u64,
    _path: PathBuf,
    _offset: u64,
}

impl LKLFS {
    pub fn new(sock_path: String, log_path: String) -> Self {
        LKLFS {
            mountpoint: "/".into(),
            socket_path: sock_path,
            log_path: log_path,
            conn: None,
            fds: Mutex::new(HashMap::new()),
        }
    }

    fn init_logger(&self) {
        fern::Dispatch::new()
            .level(log::LevelFilter::Debug)
            .format(|out, message, record| {
                out.finish(format_args!(
                    "[{}][{}] {}",
                    // [TODO] fix this
                    //chrono::Local::now().format("[%Y-%m-%d %H:%M:%S]"), // this hangs
                    record.target(),
                    record.level(),
                    message
                ))
            })
            .chain(fern::log_file(self.log_path.clone()).unwrap())
            .apply()
            .unwrap();

        info!("\n--- ndfuse-shim logger initialized ---");
    }

    fn contains_path(&self, path: &path::Path) -> bool {
        path.starts_with(&self.mountpoint)
    }
}

fn get_abs_path(path: *const c_char) -> PathBuf {
    let path = std::path::Path::new(unsafe { std::ffi::CStr::from_ptr(path).to_str().unwrap() });
    let abs_path = if path.is_absolute() {
        std::path::absolute(path).unwrap()
    } else {
        std::path::absolute(std::env::current_dir().unwrap().join(path)).unwrap()
    };
    abs_path
}

impl LKLFS {
    pub fn init(&mut self) -> Result<(), anyhow::Error> {
        self.init_logger();
        info!("socket_path = {}", self.socket_path);
        info!("log_path = {}", self.log_path);

        info!("connecting to ndfuse-proxy socket({})", self.socket_path);
        match uds::UnixSeqpacketConn::connect(&self.socket_path) {
            Ok(conn) => {
                info!("connected");
                let init_req = Request {
                    kind: RequestKind::Init {},
                };

                match conn.send(&init_req.to_bytes().unwrap()) {
                    Ok(_) => {
                        info!("init request sent successfully");
                    }
                    Err(e) => {
                        error!("failed to send init request: {}", e);
                        return Err(anyhow::anyhow!("failed to send init request: {}", e));
                    }
                }

                let mut buf = [0u8; 1024];
                match conn.recv(&mut buf) {
                    Ok(read_size) => {
                        let (_, init_res) =
                            ipc::get_response!(&buf[0..read_size], ResponseKind::Init)?;
                        self.mountpoint =
                            path::PathBuf::from(init_res.mountpoint).canonicalize()?;
                    }
                    Err(e) => {
                        error!("failed to read init response: {}", e);
                        return Err(anyhow::anyhow!("failed to read init response: {}", e));
                    }
                }
                self.conn = Some(conn);
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!(
                "failed to connect to socket {}: {}",
                self.socket_path,
                e
            )),
        }
    }

    pub fn statx(
        &mut self,
        dirfd: c_int,
        pathname: *const c_char,
        flags: c_int,
        mask: c_uint,
        statxbuf: *mut libc::statx,
    ) -> Option<i64> {
        let path =
            std::path::Path::new(unsafe { std::ffi::CStr::from_ptr(pathname).to_str().unwrap() });
        let abs_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            if dirfd == libc::AT_FDCWD {
                std::env::current_dir().unwrap().join(path)
            } else {
                error!("dirfd={} is not AT_FDCWD", dirfd);
                return None;
            }
        };

        info!("statx: dirfd={} abs_path = {}", dirfd, abs_path.display());

        // check if the path is within the mountpoint
        if !self.contains_path(&abs_path) {
            return None;
        }

        let req_bytes = Request {
            kind: RequestKind::Statx(StatxRequest {
                dirfd: dirfd,
                flags: flags,
                mask: mask,
                abs_path: abs_path.to_str().unwrap().to_string(),
            }),
        }
        .to_bytes()
        .unwrap();

        match self.conn.as_ref().unwrap().send(&req_bytes) {
            Ok(n) => {
                debug!("write size {}", n);
            }
            Err(e) => {
                error!("failed to write to socket: {}", e);
            }
        }

        let mut buf = [0; 1024];
        let (retval, res) = match self.conn.as_mut().unwrap().recv(&mut buf) {
            Ok(read_size) => match ipc::get_response!(&buf[0..read_size], ResponseKind::Statx) {
                Ok(r) => r,
                Err(e) => {
                    error!("failed to read statx response data: {}", e);
                    return None;
                }
            },
            Err(e) => {
                error!("failed to read statx response: {}", e);
                return None;
            }
        };

        if retval == 0 {
            unsafe {
                *statxbuf = res;
            }
        }
        Some(retval)
    }

    pub fn fstat(&mut self, fd: c_int, stat: *mut libc::stat) -> Option<i64> {
        let mut fds = self.fds.lock().unwrap();
        let fh = if let Some(fh) = fds.get_mut(&fd) {
            fh
        } else {
            return None;
        };
        info!("fstat: fd = {}, fh = {}", fd, fh.fh);

        let req_bytes = Request {
            kind: RequestKind::Fstat(FstatRequest { fd: fh.fh as i32 }),
        }
        .to_bytes()
        .unwrap();

        match self.conn.as_ref().unwrap().send(&req_bytes) {
            Ok(n) => {
                debug!("write size {}", n);
            }
            Err(e) => {
                error!("failed to write to socket: {}", e);
            }
        }

        let mut buf = [0; 1024];
        let (retval, res) = match self.conn.as_mut().unwrap().recv(&mut buf) {
            Ok(read_size) => match ipc::get_response!(&buf[0..read_size], ResponseKind::Fstat) {
                Ok(response) => response,
                Err(e) => {
                    error!("failed to parse fstat response data: {}", e);
                    return None;
                }
            },
            Err(e) => {
                error!("failed to read fstat response: {}", e);
                return None;
            }
        };

        if retval == 0 {
            unsafe {
                (*stat).st_dev = res.st_dev;
                (*stat).st_ino = res.st_ino;
                (*stat).st_nlink = res.st_nlink as u64;
                (*stat).st_mode = res.st_mode;
                (*stat).st_uid = res.st_uid;
                (*stat).st_gid = res.st_gid;
                (*stat).st_rdev = res.st_rdev;
                (*stat).st_size = res.st_size;
                (*stat).st_blksize = res.st_blksize as i64;
                (*stat).st_blocks = res.st_blocks as i64;
                (*stat).st_atime = res.st_atime;
                (*stat).st_atime_nsec = res.st_atime_nsec as i64;
                (*stat).st_mtime = res.st_mtime;
                (*stat).st_mtime_nsec = res.st_mtime_nsec as i64;
                (*stat).st_ctime = res.st_ctime;
                (*stat).st_ctime_nsec = res.st_ctime_nsec as i64;
            }
        }
        Some(retval)
    }

    pub fn lgetxattr(
        &mut self,
        _path: *const c_char,
        _name: *const c_char,
        _value: *mut std::ffi::c_void,
        _size: libc::size_t,
    ) -> Option<i64> {
        let abs_path = get_abs_path(_path);
        debug!("lgetxattr: abs_path = {}", abs_path.display());

        // check if the path is within the mountpoint
        if !self.contains_path(&abs_path) {
            return None;
        }

        // [TODO] support xattr
        Some((-libc::ENODATA) as i64)
    }

    pub fn listxattr(
        &mut self,
        path: *const c_char,
        _list: *mut c_char,
        _size: usize,
    ) -> Option<i64> {
        let abs_path = get_abs_path(path);
        debug!("listxattr: abs_path = {}", abs_path.display());

        // check if the path is within the mountpoint
        if !self.contains_path(&abs_path) {
            return None;
        }

        // [TODO] support xattr
        Some(0)
    }

    pub fn open(
        &mut self,
        path: *const c_char,
        flags: c_int,
        mode: Option<libc::mode_t>,
    ) -> Option<i64> {
        let abs_path = get_abs_path(path);

        // check if the path is within the mountpoint
        if !self.contains_path(&abs_path) {
            return None;
        }

        let req_bytes = Request {
            kind: RequestKind::Open(OpenRequest {
                flags: flags as u32,
                mode: mode.unwrap_or(0),
                abs_path: abs_path.to_string_lossy().to_string(),
            }),
        }
        .to_bytes()
        .unwrap();

        info!("req_bytes.len() = {}", req_bytes.len());

        match self.conn.as_ref().unwrap().send(&req_bytes) {
            Ok(n) => {
                debug!("write size {}", n);
            }
            Err(e) => {
                error!("failed to write to socket: {}", e);
            }
        }

        let mut buf = [0; 1024];
        let retval = match self.conn.as_mut().unwrap().recv(&mut buf) {
            Ok(read_size) => {
                match ipc::get_response_unit!(&buf[0..read_size], ResponseKind::Open) {
                    Ok(response) => response,
                    Err(e) => {
                        error!("failed to parse open response data: {}", e);
                        return None;
                    }
                }
            }
            Err(e) => {
                error!("failed to read open response: {}", e);
                return None;
            }
        };

        if retval < 0 {
            return Some(retval);
        }

        let fd = unsafe {
            if let Some(original_syscall) = crate::NEXT_SYS_CALL {
                original_syscall(
                    syscall_numbers::x86_64::SYS_open,
                    std::ffi::CString::new("/dev/null").unwrap().as_ptr() as libc::c_long,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            } else {
                error!("NEXT_SYS_CALL is None");
                return None;
            }
        };
        self.fds.lock().unwrap().insert(
            fd as i32,
            FileHandle {
                fh: retval as u64,
                _path: abs_path,
                _offset: 0,
            },
        );

        Some(fd)
    }

    pub fn close(&mut self, fd: c_int) -> Option<i64> {
        let mut fds = self.fds.lock().unwrap();
        let fh = if let Some(fh) = fds.remove(&fd) {
            fh
        } else {
            return None;
        };
        info!("close: fd = {}, fh = {}", fd, fh.fh);

        let req_bytes = Request {
            kind: RequestKind::Close(CloseRequest { fh: fh.fh }),
        }
        .to_bytes()
        .unwrap();

        if let Err(e) = self.conn.as_ref().unwrap().send(&req_bytes) {
            error!("failed to write close request: {}", e);
            return None;
        }

        let mut buf = [0u8; 1024];
        let retval = match self.conn.as_mut().unwrap().recv(&mut buf) {
            Ok(read_size) => {
                match ipc::get_response_unit!(&buf[0..read_size], ResponseKind::Close) {
                    Ok(response) => response,
                    Err(e) => {
                        error!("failed to parse close response data: {}", e);
                        return None;
                    }
                }
            }
            Err(e) => {
                error!("failed to read close response: {}", e);
                return None;
            }
        };

        // TODO: handle this
        _ = retval;

        unsafe {
            if let Some(original_syscall) = crate::NEXT_SYS_CALL {
                original_syscall(
                    syscall_numbers::x86_64::SYS_close,
                    fd as c_long,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
            } else {
                error!("NEXT_SYS_CALL is None");
                return None;
            }
        };
        Some(0)
    }

    pub fn read(
        &mut self,
        fd: libc::c_int,
        read_buf: *mut std::ffi::c_void,
        size: libc::size_t,
    ) -> Option<i64> {
        let mut fds = self.fds.lock().unwrap();
        let fh = if let Some(fh) = fds.get_mut(&fd) {
            fh
        } else {
            return None;
        };
        info!("read: fd = {}, fh = {}", fd, fh.fh);
        let req_bytes = Request {
            kind: RequestKind::Read(ReadRequest {
                fh: fh.fh,
                size: size as u32,
            }),
        }
        .to_bytes()
        .unwrap();

        info!("req_bytes.len() = {}", req_bytes.len());

        match self.conn.as_ref().unwrap().send(&req_bytes) {
            Ok(n) => {
                debug!("write size {}", n);
            }
            Err(e) => {
                error!("failed to write to socket: {}", e);
            }
        }

        let mut buf = vec![0; size + 200];
        let (retval, res) = match self.conn.as_mut().unwrap().recv(&mut buf) {
            Ok(read_size) => match ipc::get_response!(&buf[0..read_size], ResponseKind::Read) {
                Ok(response) => response,
                Err(e) => {
                    error!("failed to parse read response data: {}", e);
                    return None;
                }
            },
            Err(e) => {
                error!("failed to read read response: {}", e);
                return None;
            }
        };
        if retval <= 0 {
            return Some(retval);
        }
        if retval as usize > res.len() {
            error!(
                "invalid retval: {} > res.len(): {}",
                retval as usize,
                res.len()
            );
            return None;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(res.as_ptr(), read_buf as *mut u8, retval as usize);
        }
        Some(retval)
    }

    pub fn getdents64(
        &mut self,
        fd: c_int,
        dirent: *mut libc::dirent64,
        count: usize,
    ) -> Option<i64> {
        let mut fds = self.fds.lock().unwrap();
        let fh = if let Some(fh) = fds.get_mut(&fd) {
            fh
        } else {
            return None;
        };
        info!("read: fd = {}, fh = {}", fd, fh.fh);
        let req_bytes = Request {
            kind: RequestKind::Getdents64(Getdents64Request {
                fd: fh.fh as i32,
                count: count as u32,
            }),
        }
        .to_bytes()
        .unwrap();

        info!("req_bytes.len() = {}", req_bytes.len());

        match self.conn.as_ref().unwrap().send(&req_bytes) {
            Ok(n) => {
                debug!("write size {}", n);
            }
            Err(e) => {
                error!("failed to write to socket: {}", e);
            }
        }

        let mut buf = vec![0; count + 200];
        let (retval, res) = match self.conn.as_mut().unwrap().recv(&mut buf) {
            Ok(read_size) => match ipc::get_response!(&buf[0..read_size], ResponseKind::Getdents64)
            {
                Ok(response) => response,
                Err(e) => {
                    error!("failed to parse getdents64 response data: {}", e);
                    return None;
                }
            },
            Err(e) => {
                error!("failed to read getdents64 response: {}", e);
                return None;
            }
        };
        if retval <= 0 {
            return Some(retval);
        }
        if retval as usize > res.len() {
            error!(
                "invalid retval: {} > res.len(): {}",
                retval as usize,
                res.len()
            );
            return None;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(res.as_ptr(), dirent as *mut u8, retval as usize);
        }
        Some(retval)
    }
}
