use std::io;
use std::error;
use std::fmt;
use libc::c_char;
use libc::gid_t;
use libc::c_long;
use libc::c_ulong;
use hyper;
use rustc_serialize;

/**
 * This is the enum from glibc with the return stati that all implemented NSS methods must use
 */
#[repr(C)]
pub enum nss_status
{
  NSS_STATUS_TRYAGAIN = -2,
  NSS_STATUS_UNAVAIL,
  NSS_STATUS_NOTFOUND,
  NSS_STATUS_SUCCESS,
  NSS_STATUS_RETURN
}

#[repr(C)]
pub struct group
{
    pub gr_name: *mut c_char,
    pub gr_passwd: *mut c_char,
    pub gr_gid: gid_t,
    pub gr_mem: *mut *mut c_char,
}

#[repr(C)]
pub struct spwd
{
    pub sp_namp: *mut c_char,
    pub sp_pwdp: *mut c_char,
    pub sp_lstchg: c_long,
    pub sp_min: c_long,
    pub sp_max: c_long,
    pub sp_warn: c_long,
    pub sp_inact: c_long,
    pub sp_expire: c_long,
    pub sp_flag: c_ulong,
}

#[derive(Debug)]
pub enum AlexandriaSvcError  {
    Io(io::Error),
    Hyper(hyper::error::Error),
    JsonDecode(rustc_serialize::json::DecoderError),
}

impl From<hyper::error::Error> for AlexandriaSvcError {
    fn from(err: hyper::error::Error) -> AlexandriaSvcError {
        AlexandriaSvcError::Hyper(err)
    }
}

impl From<io::Error> for AlexandriaSvcError {
    fn from(err: io::Error) -> AlexandriaSvcError {
        AlexandriaSvcError::Io(err)
    }
}

impl From<rustc_serialize::json::DecoderError> for AlexandriaSvcError {
    fn from(err: rustc_serialize::json::DecoderError) -> AlexandriaSvcError {
        AlexandriaSvcError::JsonDecode(err)
    }
}

impl fmt::Display for AlexandriaSvcError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // Both underlying errors already impl `Display`, so we defer to
            // their implementations.
            AlexandriaSvcError::Io(ref err) => write!(f, "IO error: {}", err),
            AlexandriaSvcError::Hyper(ref err) => write!(f, "HTTP error: {}", err),
            AlexandriaSvcError::JsonDecode(ref err) => write!(f, "JSON decode error: {}", err),
        }
    }
}

impl error::Error for AlexandriaSvcError {
    fn description(&self) -> &str {
        // Both underlying errors already impl `Error`, so we defer to their
        // implementations.
        match *self {
            AlexandriaSvcError::Io(ref err) => err.description(),
            AlexandriaSvcError::Hyper(ref err) => err.description(),
            AlexandriaSvcError::JsonDecode(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            // N.B. Both of these implicitly cast `err` from their concrete
            // types (either `&io::Error` or `&num::ParseIntError`)
            // to a trait object `&Error`. This works because both error types
            // implement `Error`.
            AlexandriaSvcError::Io(ref err) => Some(err),
            AlexandriaSvcError::Hyper(ref err) => Some(err),
            AlexandriaSvcError::JsonDecode(ref err) => Some(err),
        }
    }
}

/*
{
  pw_name: "gary",
  pw_passwd: "x",
  pw_uid: 100,
  pw_gid: 100,
  pw_gecos: "User Information",
  pw_dir: "/home/gary",
  pw_shell: "/bin/bash"
}
*/
#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct AlexandriaPassword {
    pub pw_name: String,
    pub pw_passwd: String,
    pub pw_uid: u32,
    pub pw_gid: u32,
    pub pw_gecos: String,
    pub pw_dir: String,
    pub pw_shell: String,
}

/*
{
  "gr_name": "testgroup1",
  "gr_gid": 6000,
  "gr_passwd": "x",
  "gr_mem": [
    "testuser1",
    "testuser2"
  ]
}
*/
#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct AlexandriaGroup {
    pub gr_name: String,
    pub gr_passwd: String,
    pub gr_gid: u32,
    pub gr_mem: Vec<String>,
}

/*
{
  "sp_pwdp": "$1$BXZIu72k$S7oxt9hBiBl/O3Rm3H4Q30",
  "sp_expire": 0,
  "sp_lstchg": 16034,
  "sp_inact": 0,
  "sp_flag": 0,
  "sp_min": 0,
  "sp_max": 99999,
  "sp_warn": 7,
  "sp_namp": "testuser1"
}
*/
#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct AlexandriaShadow {
    pub sp_namp: String,
    pub sp_pwdp: String,
    pub sp_lstchg: i32,
    pub sp_min: i32,
    pub sp_max: i32,
    pub sp_warn: i32,
    pub sp_inact: i32,
    pub sp_expire: i32,
    pub sp_flag: u32,
}
