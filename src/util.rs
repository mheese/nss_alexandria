
use std::ffi::{CString};
use std::ptr::write_bytes;
use libc::c_void;
use libc::c_char;
use libc::c_int;
use libc::size_t;
use libc::passwd;
use libc::strncpy;
use types::AlexandriaPassword;

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

pub fn write_passwd(e: AlexandriaPassword, result: *mut passwd, mut buffer: *mut c_char, buflen: size_t) -> i8 {
    let next_buf = &mut buffer;
    let mut bufleft = buflen;

    unsafe { write_bytes(*next_buf, 0, buflen as usize); }

    let pw_name_len = e.pw_name.len();
    if bufleft <= pw_name_len { return -2; }
    unsafe { (*result).pw_name = strncpy(*next_buf, CString::new(e.pw_name).unwrap().as_ptr(), pw_name_len); }
    unsafe { *next_buf = next_buf.offset(pw_name_len as isize + 1) };
    bufleft -= pw_name_len + 1;

    let pw_passwd_len = e.pw_passwd.len();
    if bufleft <= pw_passwd_len { return -2; }
    unsafe { (*result).pw_passwd = strncpy(*next_buf, CString::new(e.pw_passwd).unwrap().as_ptr(), pw_passwd_len); }
    unsafe { *next_buf = next_buf.offset(pw_passwd_len as isize  + 1) };
    bufleft -= pw_passwd_len + 1;

    // not 100% clear why this MUST be in an unsafe block
    unsafe {
        (*result).pw_uid = e.pw_uid;
        (*result).pw_gid = e.pw_gid;
    }

    let pw_gecos_len = e.pw_gecos.len();
    if bufleft <= pw_gecos_len { return -2; }
    unsafe { (*result).pw_gecos = strncpy(*next_buf, CString::new(e.pw_gecos).unwrap().as_ptr(), pw_gecos_len); }
    unsafe { *next_buf = next_buf.offset(pw_gecos_len as isize + 1) };
    bufleft -= pw_gecos_len + 1;

    let pw_dir_len = e.pw_dir.len();
    if bufleft <= pw_dir_len { return -2; }
    unsafe { (*result).pw_dir = strncpy(*next_buf, CString::new(e.pw_dir).unwrap().as_ptr(), pw_dir_len); }
    unsafe { *next_buf = next_buf.offset(pw_dir_len as isize + 1) };
    bufleft -= pw_dir_len + 1;

    let pw_shell_len = e.pw_shell.len();
    if bufleft <= pw_shell_len { return -2; }
    unsafe { (*result).pw_shell = strncpy(*next_buf, CString::new(e.pw_shell).unwrap().as_ptr(), pw_shell_len); }

    return 1;
}
