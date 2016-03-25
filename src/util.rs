
use std::ffi::{CString};
use std::ptr::write_bytes;
use libc::c_void;
use libc::c_char;
use libc::c_int;
use libc::size_t;
use libc::passwd;
use libc::strncpy;
use libc::ENOMEM;
use libc::ERANGE;
use types::nss_status;
use types::nss_status::NSS_STATUS_TRYAGAIN;
use types::nss_status::NSS_STATUS_SUCCESS;
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

pub fn write_passwd(e: AlexandriaPassword, result: *mut passwd, mut buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    let next_buf = &mut buffer;
    let mut bufleft = buflen;

    // let's carefully craft C strings here:
    // - NSS is expecting ERANGE in errnop only if the buffer is too small
    // - however, we still want to try again, so we do the following for error handling:
    // - NSS_STATUS_TRYAGAIN to retry
    // - ENOMEM for errnop
    // TODO: a macro could make that part shorter

    // pw_name
    let pw_name_len = e.pw_name.len();
    let cstr_pw_name = match CString::new(e.pw_name) {
        Ok(cstr) => cstr,
        Err(_) => {
            unsafe { *errnop = ENOMEM; }
            return NSS_STATUS_TRYAGAIN;
        },
    };

    // pw_passwd
    let pw_passwd_len = e.pw_passwd.len();
    let cstr_pw_passwd = match CString::new(e.pw_passwd) {
        Ok(cstr) => cstr,
        Err(_) => {
            unsafe { *errnop = ENOMEM; }
            return NSS_STATUS_TRYAGAIN;
        }
    };

    // pw_gecos
    let pw_gecos_len = e.pw_gecos.len();
    let cstr_pw_gecos = match CString::new(e.pw_gecos) {
        Ok(cstr) => cstr,
        Err(_) => {
            unsafe { *errnop = ENOMEM; }
            return NSS_STATUS_TRYAGAIN;
        }
    };

    // pw_dir
    let pw_dir_len = e.pw_dir.len();
    let cstr_pw_dir = match CString::new(e.pw_dir) {
        Ok(cstr) => cstr,
        Err(_) => {
            unsafe { *errnop = ENOMEM; }
            return NSS_STATUS_TRYAGAIN;
        }
    };

    // pw_shell
    let pw_shell_len = e.pw_shell.len();
    let cstr_pw_shell = match CString::new(e.pw_shell) {
        Ok(cstr) => cstr,
        Err(_) => {
            unsafe { *errnop = ENOMEM; }
            return NSS_STATUS_TRYAGAIN;
        }
    };

    // clear buffer with NUL bytes
    unsafe { write_bytes(*next_buf, 0, buflen as usize); }

    if bufleft <= pw_name_len {
        // the buffer is not big enough
        // the glibc NSS documentation demands errnop to be ERANGE
        // and to return with NSS_STATUS_TRYAGAIN
        // see: http://www.gnu.org/software/libc/manual/html_node/NSS-Modules-Interface.html#NSS-Modules-Interface
        unsafe { *errnop = ERANGE; }
        return NSS_STATUS_TRYAGAIN;
    }
    unsafe {
        // as_ptr() *MUST* be called inside the unsafe block!
        (*result).pw_name = strncpy(*next_buf, cstr_pw_name.as_ptr(), pw_name_len);
        *next_buf = next_buf.offset(pw_name_len as isize + 1)
    }
    bufleft -= pw_name_len + 1;

    if bufleft <= pw_passwd_len {
        // see above
        unsafe { *errnop = ERANGE; }
        return NSS_STATUS_TRYAGAIN;
    }
    unsafe {
        // as_ptr() *MUST* be called inside the unsafe block!
        (*result).pw_passwd = strncpy(*next_buf, cstr_pw_passwd.as_ptr(), pw_passwd_len);
        *next_buf = next_buf.offset(pw_passwd_len as isize  + 1)
    }
    bufleft -= pw_passwd_len + 1;

    // not 100% clear why this MUST be in an unsafe block
    unsafe {
        (*result).pw_uid = e.pw_uid;
        (*result).pw_gid = e.pw_gid;
    }

    if bufleft <= pw_gecos_len {
        // see above
        unsafe { *errnop = ERANGE; }
        return NSS_STATUS_TRYAGAIN;
    }
    unsafe {
        // as_ptr() *MUST* be called inside the unsafe block!
        (*result).pw_gecos = strncpy(*next_buf, cstr_pw_gecos.as_ptr(), pw_gecos_len);
        *next_buf = next_buf.offset(pw_gecos_len as isize + 1)
    }
    bufleft -= pw_gecos_len + 1;

    if bufleft <= pw_dir_len {
        // see above
        unsafe { *errnop = ERANGE; }
        return NSS_STATUS_TRYAGAIN;
    }
    unsafe {
        // as_ptr() *MUST* be called inside the unsafe block!
        (*result).pw_dir = strncpy(*next_buf, cstr_pw_dir.as_ptr(), pw_dir_len);
        *next_buf = next_buf.offset(pw_dir_len as isize + 1)
    }
    bufleft -= pw_dir_len + 1;

    if bufleft <= pw_shell_len {
        // see above
        unsafe { *errnop = ERANGE; }
        return NSS_STATUS_TRYAGAIN;
    }
    unsafe {
        (*result).pw_shell = strncpy(*next_buf, cstr_pw_shell.as_ptr(), pw_shell_len);
    }

    // successfully written everytying to result and buffer
    // errnop does not need to be set
    return NSS_STATUS_SUCCESS;
}
