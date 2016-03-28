// Copyright (C) 2016 Marcus Heese
//
// This file is part of nss_alexandria.
//
// nss_alexandria is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// nss_alexandria is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with nss_alexandria.  If not, see <http://www.gnu.org/licenses/>.

use std::io::Read;
use std::time::Duration;
use libc::uid_t;
use libc::gid_t;
use libc::geteuid;
use hyper::{Client};
use hyper::status::StatusCode;
use hyperlocal::{DomainUrl, UnixSocketConnector};
use rustc_serialize::json;
use config::PASSWD_URL;
use config::GROUP_URL;
use config::SHADOW_URL;
use config::HTTP_READ_TIMEOUT_MS;
use config::HTTP_WRITE_TIMEOUT_MS;
use config::{SOCKET_PATH, SOCKET_PATH_PRIV};
use types::AlexandriaGroup;
use types::AlexandriaPassword;
use types::AlexandriaShadow;
use types::AlexandriaSvcError;


pub fn passwd() -> Result<Vec<AlexandriaPassword>, AlexandriaSvcError> {
    let client = {
        let mut c = Client::with_connector(UnixSocketConnector);
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };

    let mut response = try!(client.get(DomainUrl::new(SOCKET_PATH, PASSWD_URL)).send());
    if response.status == StatusCode::NotFound {
        return Ok(vec![]);
    }
    let mut response_body = String::new();
    let _num_bytes_read = try!(response.read_to_string(&mut response_body));
    let entries: Vec<AlexandriaPassword> = try!(json::decode(&response_body));

    Ok(entries)
}

pub fn passwd_uid(uid: uid_t) -> Result<Option<AlexandriaPassword>, AlexandriaSvcError> {
    let client = {
        let mut c = Client::with_connector(UnixSocketConnector);
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };
    let url = format!("{}?uid={}", PASSWD_URL, uid);
    let mut response = try!(client.get(DomainUrl::new(SOCKET_PATH, url.as_str())).send());
    if response.status == StatusCode::NotFound {
        return Ok(None)
    }
    let mut response_body = String::new();
    let _num_bytes_read = try!(response.read_to_string(&mut response_body));
    let entry: AlexandriaPassword = try!(json::decode(&response_body));
    Ok(Some(entry))
}

pub fn passwd_name(name: &str) -> Result<Option<AlexandriaPassword>, AlexandriaSvcError> {
    let client = {
        let mut c = Client::with_connector(UnixSocketConnector);
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };
    let url = format!("{}?name={}", PASSWD_URL, name);
    let mut response = try!(client.get(DomainUrl::new(SOCKET_PATH, url.as_str())).send());
    if response.status == StatusCode::NotFound {
        return Ok(None)
    }
    let mut response_body = String::new();
    let _num_bytes_read = try!(response.read_to_string(&mut response_body));
    let entry: AlexandriaPassword = try!(json::decode(&response_body));
    Ok(Some(entry))
}

pub fn group() -> Result<Vec<AlexandriaGroup>, AlexandriaSvcError> {
    let client = {
        let mut c = Client::with_connector(UnixSocketConnector);
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };

    let mut response = try!(client.get(DomainUrl::new(SOCKET_PATH, GROUP_URL)).send());
    if response.status == StatusCode::NotFound {
        return Ok(vec![]);
    }
    let mut response_body = String::new();
    let _num_bytes_read = try!(response.read_to_string(&mut response_body));
    let entries: Vec<AlexandriaGroup> = try!(json::decode(&response_body));

    Ok(entries)
}

pub fn group_gid(gid: gid_t) -> Result<Option<AlexandriaGroup>, AlexandriaSvcError> {
    let client = {
        let mut c = Client::with_connector(UnixSocketConnector);
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };
    let url = format!("{}?gid={}", GROUP_URL, gid);
    let mut response = try!(client.get(DomainUrl::new(SOCKET_PATH, url.as_str())).send());
    if response.status == StatusCode::NotFound {
        return Ok(None)
    }
    let mut response_body = String::new();
    let _num_bytes_read = try!(response.read_to_string(&mut response_body));
    let entry: AlexandriaGroup = try!(json::decode(&response_body));
    Ok(Some(entry))
}

pub fn group_name(name: &str) -> Result<Option<AlexandriaGroup>, AlexandriaSvcError> {
    let client = {
        let mut c = Client::with_connector(UnixSocketConnector);
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };
    let url = format!("{}?name={}", GROUP_URL, name);
    let mut response = try!(client.get(DomainUrl::new(SOCKET_PATH, url.as_str())).send());
    if response.status == StatusCode::NotFound {
        return Ok(None)
    }
    let mut response_body = String::new();
    let _num_bytes_read = try!(response.read_to_string(&mut response_body));
    let entry: AlexandriaGroup = try!(json::decode(&response_body));
    Ok(Some(entry))
}

pub fn shadow() -> Result<Vec<AlexandriaShadow>, AlexandriaSvcError> {
    // shadow route is only allowed with an effective UID of 0 (root)
    // return empty otherwise
    // NOTE: the *real* security is implemented by using a different socket which must have the
    //       permissions set to 700. This is just to short-circuit and not return with an error.
    let euid = unsafe { geteuid() };
    if euid != 0 {
        return Ok(vec![]);
    }

    let client = {
        let mut c = Client::with_connector(UnixSocketConnector);
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };

    let mut response = try!(client.get(DomainUrl::new(SOCKET_PATH_PRIV, SHADOW_URL)).send());
    if response.status == StatusCode::NotFound {
        return Ok(vec![]);
    }
    let mut response_body = String::new();
    let _num_bytes_read = try!(response.read_to_string(&mut response_body));
    let entries: Vec<AlexandriaShadow> = try!(json::decode(&response_body));

    Ok(entries)
}

pub fn shadow_name(name: &str) -> Result<Option<AlexandriaShadow>, AlexandriaSvcError> {
    // shadow route is only allowed with an effective UID of 0 (root)
    // return empty otherwise
    // NOTE: the *real* security is implemented by using a different socket which must have the
    //       permissions set to 700. This is just to short-circuit and not return with an error.
    let euid = unsafe { geteuid() };
    if  euid != 0 {
        return Ok(None);
    }

    let client = {
        let mut c = Client::with_connector(UnixSocketConnector);
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };
    let url = format!("{}?name={}", SHADOW_URL, name);
    let mut response = try!(client.get(DomainUrl::new(SOCKET_PATH_PRIV, url.as_str())).send());
    if response.status == StatusCode::NotFound {
        return Ok(None)
    }
    let mut response_body = String::new();
    let _num_bytes_read = try!(response.read_to_string(&mut response_body));
    let entry: AlexandriaShadow = try!(json::decode(&response_body));
    Ok(Some(entry))
}
