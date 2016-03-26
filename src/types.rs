use std::io;
use std::error;
use std::fmt;
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
