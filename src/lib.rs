#[macro_use]
extern crate lazy_static;
extern crate rustc_serialize;
extern crate hyper;
extern crate libc;

mod types;
mod config;
mod util;

use std::ffi::{CString, CStr};
use libc::c_void;
use libc::c_char;
use libc::c_int;
use libc::size_t;
use libc::uid_t;
use libc::passwd;
use types::AlexandriaPassword;
use util::log;
use std::ptr::write_bytes;
use libc::strncpy;


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

struct PwdList {
    list: Vec<AlexandriaPassword>,
    //index: usize,
}

static mut pw_index: usize = 0;
static mut pw_list: *mut PwdList = 0 as *mut PwdList;

fn get_pw_index() -> usize {
    unsafe {
        return pw_index;
    }
}

fn increment_pw_index() {
    unsafe {
        pw_index = pw_index + 1;
    }
}

// Called to open the passwd file
#[no_mangle]
pub extern "C" fn _nss_alexandria_setpwent(_stayopen: c_int) -> nss_status {
    log("_nss_alexandria_setpwent() - start");
    let entries = types::route_passwd();
    log("_nss_alexandria_setpwent() - got route");
    unsafe {
        let b: Box<PwdList> = Box::new(
            PwdList {
                //index: 0,
                list: entries.clone(),
            }
        );
        log("_nss_alexandria_setpwent() - boxed vals");
        pw_list = Box::into_raw(b);
        log("_nss_alexandria_setpwent() - set static mutable");
    }
    log("_nss_alexandria_setpwent() - end");
    nss_status::NSS_STATUS_SUCCESS
}

// Called to close the passwd file
#[no_mangle]
pub extern "C" fn _nss_alexandria_endpwent() -> nss_status {
    log("_nss_alexandria_endpwent");
    unsafe {
        if !pw_list.is_null() {
            drop(Box::from_raw(pw_list));
        }
        pw_index = 0;
    }
    nss_status::NSS_STATUS_SUCCESS
}

// Called to look up next entry in passwd file
#[no_mangle]
pub extern "C" fn _nss_alexandria_getpwent_r(result: *mut passwd, mut buffer: *mut c_char, buflen: size_t, mut _errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getpwent_r - start");
    unsafe {
        // unfortunately this double check is necessary because glibc calls endpwent and then
        // another getpwent without hesitating
        if pw_list.is_null() {
            // initialize pw_list again
            _nss_alexandria_setpwent(0);

            // now it should be there
            if pw_list.is_null() {
                log("_nss_alexandria_getpwent_r - pw_list == NULL");
                return nss_status::NSS_STATUS_UNAVAIL;
            }
        }
    }
    let s = unsafe { &*pw_list };
    let i = get_pw_index();

    if i >= s.list.len() {
        log("_nss_alexandria_getpwent_r - i >= list.len");
        return nss_status::NSS_STATUS_NOTFOUND;
    }

    let e = s.list[i].clone();
    log(format!("_nss_alexandria_getpwent_r - entry: {:?}", e).as_str());
    let mut _result = unsafe { *result };
    //_result.pw_name = CString::new(e.pw_name).unwrap().into_raw();
    //_result.pw_passwd = CString::new(e.pw_passwd).unwrap().into_raw();
    _result.pw_uid = e.pw_uid;
    _result.pw_gid = e.pw_gid;
    //_result.pw_gecos = CString::new(e.pw_gecos).unwrap().into_raw();
    //_result.pw_dir = CString::new(e.pw_dir).unwrap().into_raw();
    //_result.pw_shell = CString::new(e.pw_shell).unwrap().into_raw();

    //////////////////
    unsafe { write_bytes(buffer, 0, buflen as usize); }

    let next_buf = &mut buffer;
    let mut bufleft = buflen;

    let pw_name_len = e.pw_name.len();
    if bufleft <= pw_name_len { return nss_status::NSS_STATUS_UNAVAIL; }
    unsafe { _result.pw_name = strncpy(*next_buf, CString::new(e.pw_name).unwrap().into_raw(), pw_name_len ); }
    *next_buf = unsafe { next_buf.offset(pw_name_len as isize + 1) };
    bufleft -= pw_name_len + 1;

    let pw_passwd_len = e.pw_passwd.len();
    if bufleft <= pw_passwd_len { return nss_status::NSS_STATUS_UNAVAIL; }
    unsafe { _result.pw_passwd = strncpy(*next_buf, CString::new(e.pw_passwd).unwrap().into_raw(), pw_passwd_len); }
    *next_buf = unsafe { next_buf.offset(pw_passwd_len as isize + 1) };
    bufleft -= pw_passwd_len + 1;

    let pw_gecos_len = e.pw_gecos.len();
    if bufleft <= pw_gecos_len { return nss_status::NSS_STATUS_UNAVAIL; }
    unsafe { _result.pw_gecos = strncpy(*next_buf, CString::new(e.pw_gecos).unwrap().into_raw(), pw_gecos_len); }
    *next_buf = unsafe { next_buf.offset(pw_gecos_len as isize + 1) };
    bufleft -= pw_gecos_len + 1;

    let pw_dir_len = e.pw_dir.len();
    if bufleft <= pw_dir_len { return nss_status::NSS_STATUS_UNAVAIL; }
    unsafe { _result.pw_dir = strncpy(*next_buf, CString::new(e.pw_dir).unwrap().into_raw(), pw_dir_len); }
    *next_buf = unsafe { next_buf.offset(pw_dir_len as isize + 1) };
    bufleft -= pw_dir_len + 1;

    let pw_shell_len = e.pw_shell.len();
    if bufleft <= pw_shell_len { return nss_status::NSS_STATUS_UNAVAIL; }
    unsafe { _result.pw_shell = strncpy(*next_buf, CString::new(e.pw_shell).unwrap().into_raw(), pw_shell_len); }
    *next_buf = unsafe { next_buf.offset(pw_shell_len as isize + 1) };
    bufleft -= pw_shell_len + 1;


/*if (bufleft <= j_strlen(j_pw_name)) return -2;
result->pw_name = strncpy(next_buf, json_string_value(j_pw_name), bufleft);
next_buf += strlen(result->pw_name) + 1;
bufleft  -= strlen(result->pw_name) + 1;

if (bufleft <= j_strlen(j_pw_passwd)) return -2;
result->pw_passwd = strncpy(next_buf, json_string_value(j_pw_passwd), bufleft);
next_buf += strlen(result->pw_passwd) + 1;
bufleft  -= strlen(result->pw_passwd) + 1;

// Yay, ints are so easy!
result->pw_uid = json_integer_value(j_pw_uid);
result->pw_gid = json_integer_value(j_pw_gid);
*/

/////////////////

    log("_nss_alexandria_getpwent_r - incrementing index");
    increment_pw_index();
    log("_nss_alexandria_getpwent_r - end");
    nss_status::NSS_STATUS_SUCCESS
}

// Find a passwd by uid
#[no_mangle]
pub extern "C" fn _nss_alexandria_getpwuid_r(uid: uid_t, mut result: *mut passwd, mut _buffer: *mut c_char, mut _buflen: size_t, mut _errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getpwuid_r");
    unsafe {
        // unfortunately this double check is necessary because glibc calls endpwent and then
        // another getpwent without hesitating
        if pw_list.is_null() {
            // initialize pw_list again
            _nss_alexandria_setpwent(0);

            // now it should be there
            if pw_list.is_null() {
                log("_nss_alexandria_getpwuid_r - pw_list == NULL");
                return nss_status::NSS_STATUS_UNAVAIL;
            }
        }
    }
    let s = unsafe { &*pw_list };
    match s.list.iter().find( |x| x.pw_uid == uid ) {
        None => nss_status::NSS_STATUS_UNAVAIL,
        Some(e) => {
            unsafe {
                let b: Box<passwd> = Box::new(types::entry_to_passwd(e.clone()));
                result = Box::into_raw(b);
            }
            nss_status::NSS_STATUS_SUCCESS
        },
    }
}

// Find a passwd by name
#[no_mangle]
pub extern "C" fn _nss_alexandria_getpwnam_r(name: *const c_char, mut result: *mut passwd, mut _buffer: *mut c_char, mut _buflen: size_t, mut _errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getpwnam_r");
    unsafe {
        // unfortunately this double check is necessary because glibc calls endpwent and then
        // another getpwent without hesitating
        if pw_list.is_null() {
            // initialize pw_list again
            _nss_alexandria_setpwent(0);

            // now it should be there
            if pw_list.is_null() {
                log("_nss_alexandria_getpwuid_r - pw_list == NULL");
                return nss_status::NSS_STATUS_UNAVAIL;
            }
        }
    }
    let s = unsafe { &*pw_list };
    let tmp_name = unsafe { CStr::from_ptr(name).to_str().unwrap() };
    let n = String::from(tmp_name);
    match s.list.iter().find( |x| x.pw_name == n ) {
        None => nss_status::NSS_STATUS_UNAVAIL,
        Some(e) => {
            unsafe {
                let b: Box<passwd> = Box::new(types::entry_to_passwd(e.clone()));
                result = Box::into_raw(b);
            }
            nss_status::NSS_STATUS_SUCCESS
        },
    }
}
