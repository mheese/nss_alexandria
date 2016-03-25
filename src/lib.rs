#[macro_use]
extern crate lazy_static;
extern crate rustc_serialize;
extern crate hyper;
extern crate libc;

mod types;
mod config;
mod util;
mod routes;

use std::ffi::{CStr};
use libc::c_char;
use libc::c_int;
use libc::size_t;
use libc::uid_t;
use libc::passwd;
use types::nss_status;
use types::AlexandriaPassword;
use util::log;


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
    let entries = routes::passwd();
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
pub extern "C" fn _nss_alexandria_getpwent_r(result: *mut passwd, buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
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

    util::write_passwd(e, result, buffer, buflen, errnop);

    log("_nss_alexandria_getpwent_r - incrementing index");
    increment_pw_index();
    log("_nss_alexandria_getpwent_r - end");
    nss_status::NSS_STATUS_SUCCESS
}

// Find a passwd by uid
#[no_mangle]
pub extern "C" fn _nss_alexandria_getpwuid_r(uid: uid_t, result: *mut passwd, buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getpwuid_r");

    match routes::passwd_uid(uid) {
        None => nss_status::NSS_STATUS_NOTFOUND,
        Some(entry) => {
            util::write_passwd(entry, result, buffer, buflen, errnop);
            nss_status::NSS_STATUS_SUCCESS
        },
    }

}

// Find a passwd by name
#[no_mangle]
pub extern "C" fn _nss_alexandria_getpwnam_r(name: *const c_char, result: *mut passwd, buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getpwnam_r");
    let cname = unsafe { CStr::from_ptr(name) };
    match routes::passwd_name(cname.to_str().unwrap()) {
        None => nss_status::NSS_STATUS_NOTFOUND,
        Some(entry) => {
            util::write_passwd(entry, result, buffer, buflen, errnop);
            nss_status::NSS_STATUS_SUCCESS
        }
    }
}
