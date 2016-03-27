
use std::ffi::{CString};
use std::ptr::write_bytes;
use std::ptr::copy;
use libc::c_void;
use libc::c_char;
use libc::c_int;
use libc::size_t;
use libc::strncpy;
use libc::ENOMEM;
use libc::ERANGE;
use libc::passwd;
use types::group;
use types::spwd;
use types::nss_status;
use types::nss_status::NSS_STATUS_TRYAGAIN;
use types::nss_status::NSS_STATUS_SUCCESS;
use types::AlexandriaPassword;
use types::AlexandriaGroup;
use types::AlexandriaShadow;

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

pub fn write_group(e: AlexandriaGroup, result: *mut group, mut buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    let next_buf = &mut buffer;
    let mut bufleft = buflen;

    // let's carefully craft C strings here:
    // - NSS is expecting ERANGE in errnop only if the buffer is too small
    // - however, we still want to try again, so we do the following for error handling:
    // - NSS_STATUS_TRYAGAIN to retry
    // - ENOMEM for errnop
    // TODO: a macro could make that part shorter

    // gr_name
    let gr_name_len = e.gr_name.len();
    let cstr_gr_name = match CString::new(e.gr_name) {
        Ok(cstr) => cstr,
        Err(_) => {
            unsafe { *errnop = ENOMEM; }
            return NSS_STATUS_TRYAGAIN;
        },
    };

    // gr_passwd
    let gr_passwd_len = e.gr_passwd.len();
    let cstr_gr_passwd = match CString::new(e.gr_passwd) {
        Ok(cstr) => cstr,
        Err(_) => {
            unsafe { *errnop = ENOMEM; }
            return NSS_STATUS_TRYAGAIN;
        }
    };

    // gr_mem
    let cstr_gr_mems_len = e.gr_mem.len();
    let mut cstr_gr_mems: Vec<*mut c_char> = Vec::with_capacity(cstr_gr_mems_len);
    for mem in e.gr_mem {
        let cstr_gr_mem = match CString::new(mem) {
            Ok(cstr) => cstr.into_raw(),
            Err(_) => {
                unsafe { *errnop = ENOMEM; }
                return NSS_STATUS_TRYAGAIN;
            },
        };
        cstr_gr_mems.push(cstr_gr_mem);
    }
    let cstr_gr_mems_cap = cstr_gr_mems.capacity() + 1;

    // clear buffer with NUL bytes
    unsafe { write_bytes(*next_buf, 0, buflen as usize); }

    if bufleft <= gr_name_len {
        // the buffer is not big enough
        // the glibc NSS documentation demands errnop to be ERANGE
        // and to return with NSS_STATUS_TRYAGAIN
        // see: http://www.gnu.org/software/libc/manual/html_node/NSS-Modules-Interface.html#NSS-Modules-Interface
        unsafe { *errnop = ERANGE; }
        return NSS_STATUS_TRYAGAIN;
    }
    unsafe {
        // as_ptr() *MUST* be called inside the unsafe block!
        (*result).gr_name = strncpy(*next_buf, cstr_gr_name.as_ptr(), gr_name_len);
        *next_buf = next_buf.offset(gr_name_len as isize + 1)
    }
    bufleft -= gr_name_len + 1;

    if bufleft <= gr_passwd_len {
        // see above
        unsafe { *errnop = ERANGE; }
        return NSS_STATUS_TRYAGAIN;
    }
    unsafe {
        // as_ptr() *MUST* be called inside the unsafe block!
        (*result).gr_passwd = strncpy(*next_buf, cstr_gr_passwd.as_ptr(), gr_passwd_len);
        *next_buf = next_buf.offset(gr_passwd_len as isize  + 1)
    }
    bufleft -= gr_passwd_len + 1;

    // not 100% clear why this MUST be in an unsafe block
    unsafe {
        (*result).gr_gid = e.gr_gid;
    }

    if bufleft <= cstr_gr_mems_cap {
        unsafe { *errnop = ERANGE; }
        return NSS_STATUS_TRYAGAIN;
    }

    unsafe {
        (*result).gr_mem = *next_buf as *mut *mut c_char;
        copy(cstr_gr_mems.as_ptr(), *next_buf as *mut *mut c_char, cstr_gr_mems_len);
    }

    // successfully written everytying to result and buffer
    // errnop does not need to be set
    return NSS_STATUS_SUCCESS;
}

pub fn write_shadow(e: AlexandriaShadow, result: *mut spwd, mut buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    let next_buf = &mut buffer;
    let mut bufleft = buflen;

    // let's carefully craft C strings here:
    // - NSS is expecting ERANGE in errnop only if the buffer is too small
    // - however, we still want to try again, so we do the following for error handling:
    // - NSS_STATUS_TRYAGAIN to retry
    // - ENOMEM for errnop
    // TODO: a macro could make that part shorter

    // sp_namp
    let sp_namp_len = e.sp_namp.len();
    let cstr_sp_namp = match CString::new(e.sp_namp) {
        Ok(cstr) => cstr,
        Err(_) => {
            unsafe { *errnop = ENOMEM; }
            return NSS_STATUS_TRYAGAIN;
        },
    };

    // sp_pwdp
    let sp_pwdp_len = e.sp_pwdp.len();
    let cstr_sp_pwdp = match CString::new(e.sp_pwdp) {
        Ok(cstr) => cstr,
        Err(_) => {
            unsafe { *errnop = ENOMEM; }
            return NSS_STATUS_TRYAGAIN;
        }
    };

    // clear buffer with NUL bytes
    unsafe { write_bytes(*next_buf, 0, buflen as usize); }

    if bufleft <= sp_namp_len {
        // the buffer is not big enough
        // the glibc NSS documentation demands errnop to be ERANGE
        // and to return with NSS_STATUS_TRYAGAIN
        // see: http://www.gnu.org/software/libc/manual/html_node/NSS-Modules-Interface.html#NSS-Modules-Interface
        unsafe { *errnop = ERANGE; }
        return NSS_STATUS_TRYAGAIN;
    }
    unsafe {
        // as_ptr() *MUST* be called inside the unsafe block!
        (*result).sp_namp = strncpy(*next_buf, cstr_sp_namp.as_ptr(), sp_namp_len);
        *next_buf = next_buf.offset(sp_namp_len as isize + 1)
    }
    bufleft -= sp_namp_len + 1;

    if bufleft <= sp_pwdp_len {
        // see above
        unsafe { *errnop = ERANGE; }
        return NSS_STATUS_TRYAGAIN;
    }
    unsafe {
        // as_ptr() *MUST* be called inside the unsafe block!
        (*result).sp_pwdp = strncpy(*next_buf, cstr_sp_pwdp.as_ptr(), sp_pwdp_len);
        //*next_buf = next_buf.offset(sp_pwdp_len as isize  + 1)
    }
    //bufleft -= sp_pwdp_len + 1;

    unsafe {
        (*result).sp_lstchg = e.sp_lstchg;
        (*result).sp_min = e.sp_min;
        (*result).sp_max = e.sp_max;
        (*result).sp_warn = e.sp_warn;
        (*result).sp_inact = e.sp_inact;
        (*result).sp_expire = e.sp_expire;
        (*result).sp_flag = e.sp_flag;
    }

    // successfully written everytying to result and buffer
    // errnop does not need to be set
    return NSS_STATUS_SUCCESS;
}
