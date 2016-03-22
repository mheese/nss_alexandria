use libc::c_int;
use libc::c_char;
use libc::c_void;
use std::ffi::{CString};

/* A reference to the syslog method in glibc */
extern {
    fn syslog(pri: c_int, fmt: *const c_char) -> c_void;
}

/* log will log msg on syslog with INFO priority */
pub fn log(msg: &str) {
    unsafe {
        syslog(6, CString::new(msg).unwrap().as_ptr() );
    }
}
