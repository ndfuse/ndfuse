use libc::{c_int, c_uint};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

pub trait BinSerdes: for<'a> Deserialize<'a> + Serialize + Sized {
    fn to_bytes(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        rmp_serde::to_vec(self)
    }

    #[allow(unused)]
    fn from_bytes(bytes: &[u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(bytes)
    }

    fn from_reader<T: std::io::Read>(r: T) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_read(r)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Request {
    pub kind: RequestKind,
}
impl BinSerdes for Request {}

#[derive(Serialize, Deserialize, Debug)]
pub enum RequestKind {
    Init,
    Statx(StatxRequest),
    Fstat(FstatRequest),
    Getdents64(Getdents64Request),
    Open(OpenRequest),
    Read(ReadRequest),
    Close(CloseRequest),
}

#[derive(Debug, Clone, Copy, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum ShimOpcode {
    Init = 1,
    Statx = 2,
    Open = 3,
    Close = 4,
    Read = 5,
    Fstat = 6,
    Getdents64 = 7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum StatusCode {
    OK = 1,
    ERROR = 2,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Response {
    pub opcode: ShimOpcode,
    pub status: StatusCode,
    pub retval: i64,
}
impl BinSerdes for Response {}

#[derive(Serialize, Deserialize, Debug)]
pub struct ErrorResponse {
    pub msg: String,
}
impl BinSerdes for ErrorResponse {}

#[derive(Serialize, Deserialize, Debug)]
pub struct EmptyResponse {}
impl BinSerdes for EmptyResponse {}

#[derive(Serialize, Deserialize, Debug)]
pub struct InitResponse {
    pub mountpoint: String,
}
impl BinSerdes for InitResponse {}

#[derive(Serialize, Deserialize, Debug)]
pub struct StatxRequest {
    pub dirfd: c_int,
    pub flags: c_int,
    pub mask: c_uint,
    pub abs_path: String,
}
impl BinSerdes for StatxRequest {}
impl BinSerdes for libc::statx {}

#[derive(Serialize, Deserialize, Debug)]
pub struct FstatRequest {
    pub fd: i32,
}
impl BinSerdes for FstatRequest {}

// refer to lkl/linux/tools/lkl/include/lkl/asm-generic/stat.h
#[repr(C)]
#[derive(Serialize, Deserialize, Debug)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_mode: u32,
    pub st_nlink: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    #[serde(skip)]
    __pad1: u64,
    pub st_size: i64,
    pub st_blksize: i32,
    #[serde(skip)]
    __pad2: u32,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: u64,
    pub st_mtime: i64,
    pub st_mtime_nsec: u64,
    pub st_ctime: i64,
    pub st_ctime_nsec: u64,
    #[serde(skip)]
    __unused: [c_uint; 2],
}
impl BinSerdes for Stat {}

#[derive(Serialize, Deserialize, Debug)]
pub struct OpenRequest {
    pub flags: u32,
    pub mode: u32,
    pub abs_path: String,
}
impl BinSerdes for OpenRequest {}

#[derive(Serialize, Deserialize, Debug)]
pub struct CloseRequest {
    pub fh: u64,
}
impl BinSerdes for CloseRequest {}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReadRequest {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
}
impl BinSerdes for ReadRequest {}

#[derive(Serialize, Deserialize, Debug)]
pub struct Getdents64Request {
    pub fd: i32,
    pub count: u32,
}
impl BinSerdes for Getdents64Request {}
