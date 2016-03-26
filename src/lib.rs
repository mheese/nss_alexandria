#![feature(static_mutex)]
#[macro_use]

extern crate rustc_serialize;
extern crate hyper;
extern crate libc;

mod types;
mod config;
mod util;
mod routes;

use std::ffi::{CStr};
use std::sync::{StaticMutex, MUTEX_INIT};
use libc::c_char;
use libc::c_int;
use libc::size_t;
use libc::uid_t;
use libc::passwd;
use libc::ENOENT;
use libc::EAGAIN;
use types::nss_status;
use types::nss_status::NSS_STATUS_UNAVAIL;
use types::nss_status::NSS_STATUS_NOTFOUND;
use types::nss_status::NSS_STATUS_SUCCESS;
use types::nss_status::NSS_STATUS_TRYAGAIN;
use types::AlexandriaPassword;
use util::log;

// This struct keeps the state for the _nss_alexandria_getpwent_r function
// It stores/caches the previously retrieved list and then increments the index here
struct PwdList {
    list: Vec<AlexandriaPassword>,
    index: usize,
}
impl PwdList {
    fn get_current_entry(&self) -> Option<&AlexandriaPassword> {
        let i = self.get_index();
        if self.list.is_empty() || i >= self.list.len() {
            None
        } else {
            Some(&self.list[i])
        }
    }

    fn get_index(&self) -> usize {
        self.index
    }

    fn increment_index(&mut self) {
        self.index = self.get_index() + 1;
    }
}

// This is global C-style library state for the _nss_alexandria_getpwent_r function
// We use a StaticMutex to lock the library
static LIB_LOCK: StaticMutex = MUTEX_INIT;
static mut PW_LIST: *mut PwdList = 0 as *mut PwdList;


// Called to open the passwd file
#[no_mangle]
pub extern "C" fn _nss_alexandria_setpwent(_stayopen: c_int) -> nss_status {
    log("_nss_alexandria_setpwent()");

    let entries = routes::passwd();

    unsafe {
        let _locked = match LIB_LOCK.try_lock() {
            Ok(s) => s,
            Err(_) => {
                return NSS_STATUS_TRYAGAIN;
            }
        };

        let b: Box<PwdList> = Box::new(
            PwdList {
                index: 0,
                list: entries.clone(),
            }
        );

        PW_LIST = Box::into_raw(b);
    }

    NSS_STATUS_SUCCESS
}

// Called to close the passwd file
#[no_mangle]
pub extern "C" fn _nss_alexandria_endpwent() -> nss_status {
    log("_nss_alexandria_endpwent");
    unsafe {
        let _locked = match LIB_LOCK.try_lock() {
            Ok(s) => s,
            Err(_) => {
                return NSS_STATUS_TRYAGAIN;
            }
        };

        if !PW_LIST.is_null() {
            drop(Box::from_raw(PW_LIST));
        }
    }

    NSS_STATUS_SUCCESS
}

// Called to look up next entry in passwd file
#[no_mangle]
pub extern "C" fn _nss_alexandria_getpwent_r(result: *mut passwd, buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getpwent_r");

    // ensure the global library state is there
    unsafe {
        // unfortunately this double check is necessary because glibc might call endpwent and then
        // another getpwent without hesitating
        if PW_LIST.is_null() {
            // initialize PW_LIST again
            _nss_alexandria_setpwent(0);

            // now it should be there
            if PW_LIST.is_null() {
                *errnop = ENOENT;
                return NSS_STATUS_UNAVAIL;
            }
        }
    }

    // Acquire LIB_LOCK, or fail utterly, but don't block
    let _locked = match LIB_LOCK.try_lock() {
        Ok(s) => s,
        Err(_) => {
            unsafe { *errnop = EAGAIN; }
            return NSS_STATUS_TRYAGAIN;
        }
    };

    let mut pwl = unsafe { &mut *PW_LIST };

    // cloning is the only reasonable way to go here
    let e = match pwl.get_current_entry() {
        Some(e) => e.clone(),
        None => {
            unsafe { *errnop = ENOENT; }
            return NSS_STATUS_NOTFOUND;
        },
    };

    // on successful write_passwd, increment index first
    match util::write_passwd(e, result, buffer, buflen, errnop) {
        NSS_STATUS_SUCCESS => {
            pwl.increment_index();
            NSS_STATUS_SUCCESS
        },
        status => status
    }
}

// Find a passwd by uid
#[no_mangle]
pub extern "C" fn _nss_alexandria_getpwuid_r(uid: uid_t, result: *mut passwd, buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getpwuid_r");

    match routes::passwd_uid(uid) {
        None => {
            unsafe { *errnop = ENOENT; }
            NSS_STATUS_NOTFOUND
        },
        Some(entry) => util::write_passwd(entry, result, buffer, buflen, errnop),
    }

}

// Find a passwd by name
#[no_mangle]
pub extern "C" fn _nss_alexandria_getpwnam_r(name: *const c_char, result: *mut passwd, buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getpwnam_r");

    let cname = unsafe { CStr::from_ptr(name) };

    match routes::passwd_name(cname.to_str().unwrap()) {
        None => {
            unsafe { *errnop = ENOENT; }
            NSS_STATUS_NOTFOUND
        },
        Some(entry) => util::write_passwd(entry, result, buffer, buflen, errnop),
    }
}
