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
use libc::gid_t;
use libc::ENOENT;
use libc::EAGAIN;
use libc::passwd;
use types::group;
use types::spwd;
use types::nss_status;
use types::nss_status::NSS_STATUS_UNAVAIL;
use types::nss_status::NSS_STATUS_NOTFOUND;
use types::nss_status::NSS_STATUS_SUCCESS;
use types::nss_status::NSS_STATUS_TRYAGAIN;
use types::AlexandriaPassword;
use types::AlexandriaGroup;
use types::AlexandriaShadow;
use util::log;

// This struct keeps the state for the _nss_alexandria_getpwent_r function
// It stores/caches the previously retrieved list and then increments the index here
struct DbList<T> {
    list: Vec<T>,
    index: usize,
}
impl<T> DbList<T> {
    fn get_current_entry(&self) -> Option<&T> {
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
static PWD_LIB_LOCK: StaticMutex = MUTEX_INIT;
static mut PWD_LIST: *mut DbList<AlexandriaPassword> = 0 as *mut DbList<AlexandriaPassword>;
static GRP_LIB_LOCK: StaticMutex = MUTEX_INIT;
static mut GRP_LIST: *mut DbList<AlexandriaGroup> = 0 as *mut DbList<AlexandriaGroup>;
static SPWD_LIB_LOCK: StaticMutex = MUTEX_INIT;
static mut SPWD_LIST: *mut DbList<AlexandriaShadow> = 0 as *mut DbList<AlexandriaShadow>;

// Called to open the passwd file
#[no_mangle]
pub extern "C" fn _nss_alexandria_setpwent(_stayopen: c_int) -> nss_status {
    log("_nss_alexandria_setpwent()");

    let entries = match routes::passwd() {
        Ok(entries) => entries,
        Err(e) => {
            log(format!("_nss_alexandria_setpwent(): error retrieving passwd list from Alexandria service: {}", e).as_str());
            return NSS_STATUS_TRYAGAIN;
        },
    };

    unsafe {
        let _locked = match PWD_LIB_LOCK.try_lock() {
            Ok(s) => s,
            Err(_) => {
                return NSS_STATUS_TRYAGAIN;
            }
        };

        let b: Box<DbList<AlexandriaPassword>> = Box::new(
            DbList {
                index: 0,
                list: entries.clone(),
            }
        );

        PWD_LIST = Box::into_raw(b);
    }

    NSS_STATUS_SUCCESS
}

// Called to close the passwd file
#[no_mangle]
pub extern "C" fn _nss_alexandria_endpwent() -> nss_status {
    log("_nss_alexandria_endpwent");
    unsafe {
        let _locked = match PWD_LIB_LOCK.try_lock() {
            Ok(s) => s,
            Err(_) => {
                return NSS_STATUS_TRYAGAIN;
            }
        };

        if !PWD_LIST.is_null() {
            drop(Box::from_raw(PWD_LIST));
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
        if PWD_LIST.is_null() {
            // initialize PWD_LIST again
            _nss_alexandria_setpwent(0);

            // now it should be there
            if PWD_LIST.is_null() {
                *errnop = ENOENT;
                return NSS_STATUS_UNAVAIL;
            }
        }
    }

    // Acquire PWD_LIB_LOCK, or fail utterly, but don't block
    let _locked = match PWD_LIB_LOCK.try_lock() {
        Ok(s) => s,
        Err(_) => {
            unsafe { *errnop = EAGAIN; }
            return NSS_STATUS_TRYAGAIN;
        }
    };

    let mut pwl = unsafe { &mut *PWD_LIST };

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
        Err(e) => {
            log(format!("_nss_alexandria_getpwuid_r(): error retrieving passwd entry from Alexandria service: {}", e).as_str());
            unsafe { *errnop = EAGAIN; }
            NSS_STATUS_TRYAGAIN
        },
        Ok(possible_entry) => match possible_entry {
            None => {
                unsafe { *errnop = ENOENT; }
                NSS_STATUS_NOTFOUND
            },
            Some(entry) => util::write_passwd(entry, result, buffer, buflen, errnop),
        },
    }

}

// Find a passwd by name
#[no_mangle]
pub extern "C" fn _nss_alexandria_getpwnam_r(name: *const c_char, result: *mut passwd, buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getpwnam_r");

    let cname = unsafe { CStr::from_ptr(name) };

    match routes::passwd_name(cname.to_str().unwrap()) {
        Err(e) => {
            log(format!("_nss_alexandria_getpwnam_r(): error retrieving passwd entry from Alexandria service: {}", e).as_str());
            unsafe { *errnop = EAGAIN; }
            NSS_STATUS_TRYAGAIN
        },
        Ok(possible_entry) => match possible_entry {
            None => {
                unsafe { *errnop = ENOENT; }
                NSS_STATUS_NOTFOUND
            },
            Some(entry) => util::write_passwd(entry, result, buffer, buflen, errnop),
        },
    }
}

#[no_mangle]
pub extern "C" fn _nss_alexandria_setgrent(_stayopen: c_int) -> nss_status {
    log("_nss_alexandria_setgrent()");

    let entries = match routes::group() {
        Ok(entries) => entries,
        Err(e) => {
            log(format!("_nss_alexandria_setgrent(): error retrieving group list from Alexandria service: {}", e).as_str());
            return NSS_STATUS_TRYAGAIN;
        },
    };

    unsafe {
        let _locked = match GRP_LIB_LOCK.try_lock() {
            Ok(s) => s,
            Err(_) => {
                return NSS_STATUS_TRYAGAIN;
            }
        };

        let b: Box<DbList<AlexandriaGroup>> = Box::new(
            DbList {
                index: 0,
                list: entries.clone(),
            }
        );

        GRP_LIST = Box::into_raw(b);
    }

    NSS_STATUS_SUCCESS
}

// Called to close the passwd file
#[no_mangle]
pub extern "C" fn _nss_alexandria_endgrent() -> nss_status {
    log("_nss_alexandria_endgrent");
    unsafe {
        let _locked = match GRP_LIB_LOCK.try_lock() {
            Ok(s) => s,
            Err(_) => {
                return NSS_STATUS_TRYAGAIN;
            }
        };

        if !GRP_LIST.is_null() {
            drop(Box::from_raw(GRP_LIST));
        }
    }

    NSS_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn _nss_alexandria_getgrent_r(result: *mut group, buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getgrent_r");

    // ensure the global library state is there
    unsafe {
        // unfortunately this double check is necessary because glibc might call endpwent and then
        // another getpwent without hesitating
        if GRP_LIST.is_null() {
            // initialize GRP_LIST again
            _nss_alexandria_setgrent(0);

            // now it should be there
            if GRP_LIST.is_null() {
                *errnop = ENOENT;
                return NSS_STATUS_UNAVAIL;
            }
        }
    }

    // Acquire GRP_LIB_LOCK, or fail utterly, but don't block
    let _locked = match GRP_LIB_LOCK.try_lock() {
        Ok(s) => s,
        Err(_) => {
            unsafe { *errnop = EAGAIN; }
            return NSS_STATUS_TRYAGAIN;
        }
    };

    let mut grpl = unsafe { &mut *GRP_LIST };

    // cloning is the only reasonable way to go here
    let e = match grpl.get_current_entry() {
        Some(e) => e.clone(),
        None => {
            unsafe { *errnop = ENOENT; }
            return NSS_STATUS_NOTFOUND;
        },
    };

    // on successful write_passwd, increment index first
    match util::write_group(e, result, buffer, buflen, errnop) {
        NSS_STATUS_SUCCESS => {
            grpl.increment_index();
            NSS_STATUS_SUCCESS
        },
        status => status
    }
}

// Find a group by gid
#[no_mangle]
pub extern "C" fn _nss_alexandria_getgrgid_r(gid: gid_t, result: *mut group, buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getgrgid_r");

    match routes::group_gid(gid) {
        Err(e) => {
            log(format!("_nss_alexandria_getgrgid_r(): error retrieving group entry from Alexandria service: {}", e).as_str());
            unsafe { *errnop = EAGAIN; }
            NSS_STATUS_TRYAGAIN
        },
        Ok(possible_entry) => match possible_entry {
            None => {
                unsafe { *errnop = ENOENT; }
                NSS_STATUS_NOTFOUND
            },
            Some(entry) => util::write_group(entry, result, buffer, buflen, errnop),
        },
    }

}

#[no_mangle]
pub extern "C" fn _nss_alexandria_getgrnam_r(name: *const c_char, result: *mut group, buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getgrnam_r");

    let cname = unsafe { CStr::from_ptr(name) };

    match routes::group_name(cname.to_str().unwrap()) {
        Err(e) => {
            log(format!("_nss_alexandria_getprnam_r(): error retrieving group entry from Alexandria service: {}", e).as_str());
            unsafe { *errnop = EAGAIN; }
            NSS_STATUS_TRYAGAIN
        },
        Ok(possible_entry) => match possible_entry {
            None => {
                unsafe { *errnop = ENOENT; }
                NSS_STATUS_NOTFOUND
            },
            Some(entry) => util::write_group(entry, result, buffer, buflen, errnop),
        },
    }
}

#[no_mangle]
pub extern "C" fn _nss_alexandria_setspent(_stayopen: c_int) -> nss_status {
    log("_nss_alexandria_setspent()");

    let entries = match routes::shadow() {
        Ok(entries) => entries,
        Err(e) => {
            log(format!("_nss_alexandria_setspent(): error retrieving shadow list from Alexandria service: {}", e).as_str());
            return NSS_STATUS_TRYAGAIN;
        },
    };

    unsafe {
        let _locked = match SPWD_LIB_LOCK.try_lock() {
            Ok(s) => s,
            Err(_) => {
                return NSS_STATUS_TRYAGAIN;
            }
        };

        let b: Box<DbList<AlexandriaShadow>> = Box::new(
            DbList {
                index: 0,
                list: entries.clone(),
            }
        );

        SPWD_LIST = Box::into_raw(b);
    }

    NSS_STATUS_SUCCESS
}

// Called to close the passwd file
#[no_mangle]
pub extern "C" fn _nss_alexandria_endspent() -> nss_status {
    log("_nss_alexandria_endspent");
    unsafe {
        let _locked = match SPWD_LIB_LOCK.try_lock() {
            Ok(s) => s,
            Err(_) => {
                return NSS_STATUS_TRYAGAIN;
            }
        };

        if !SPWD_LIST.is_null() {
            drop(Box::from_raw(SPWD_LIST));
        }
    }

    NSS_STATUS_SUCCESS
}

#[no_mangle]
pub extern "C" fn _nss_alexandria_getspent_r(result: *mut spwd, buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getspent_r");

    // ensure the global library state is there
    unsafe {
        // unfortunately this double check is necessary because glibc might call endpwent and then
        // another getpwent without hesitating
        if SPWD_LIST.is_null() {
            // initialize SPWD_LIST again
            _nss_alexandria_setspent(0);

            // now it should be there
            if SPWD_LIST.is_null() {
                *errnop = ENOENT;
                return NSS_STATUS_UNAVAIL;
            }
        }
    }

    // Acquire SPWD_LIB_LOCK, or fail utterly, but don't block
    let _locked = match SPWD_LIB_LOCK.try_lock() {
        Ok(s) => s,
        Err(_) => {
            unsafe { *errnop = EAGAIN; }
            return NSS_STATUS_TRYAGAIN;
        }
    };

    let mut spwdl = unsafe { &mut *SPWD_LIST };

    // cloning is the only reasonable way to go here
    let e = match spwdl.get_current_entry() {
        Some(e) => e.clone(),
        None => {
            unsafe { *errnop = ENOENT; }
            return NSS_STATUS_NOTFOUND;
        },
    };

    // on successful write_passwd, increment index first
    match util::write_shadow(e, result, buffer, buflen, errnop) {
        NSS_STATUS_SUCCESS => {
            spwdl.increment_index();
            NSS_STATUS_SUCCESS
        },
        status => status
    }
}

#[no_mangle]
pub extern "C" fn _nss_alexandria_getspnam_r(name: *const c_char, result: *mut spwd, buffer: *mut c_char, buflen: size_t, mut errnop: *mut c_int) -> nss_status {
    log("_nss_alexandria_getspnam_r");

    let cname = unsafe { CStr::from_ptr(name) };

    match routes::shadow_name(cname.to_str().unwrap()) {
        Err(e) => {
            log(format!("_nss_alexandria_getspnam_r(): error retrieving shadow entry from Alexandria service: {}", e).as_str());
            unsafe { *errnop = EAGAIN; }
            NSS_STATUS_TRYAGAIN
        },
        Ok(possible_entry) => match possible_entry {
            None => {
                unsafe { *errnop = ENOENT; }
                NSS_STATUS_NOTFOUND
            },
            Some(entry) => util::write_shadow(entry, result, buffer, buflen, errnop),
        },
    }
}
