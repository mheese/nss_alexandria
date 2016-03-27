use std::io::Read;
use std::time::Duration;
use libc::uid_t;
use libc::gid_t;
use hyper::{Client};
use hyper::status::StatusCode;
use rustc_serialize::json;
use config::PASSWD_URL;
use config::GROUP_URL;
use config::SHADOW_URL;
use config::HTTP_READ_TIMEOUT_MS;
use config::HTTP_WRITE_TIMEOUT_MS;
use types::AlexandriaGroup;
use types::AlexandriaPassword;
use types::AlexandriaShadow;
use types::AlexandriaSvcError;


pub fn passwd() -> Result<Vec<AlexandriaPassword>, AlexandriaSvcError> {
    let client = {
        let mut c = Client::new();
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };

    let mut response = try!(client.get(PASSWD_URL).send());
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
        let mut c = Client::new();
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };
    let url = format!("{}?uid={}", PASSWD_URL, uid);
    let mut response = try!(client.get(url.as_str()).send());
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
        let mut c = Client::new();
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };
    let url = format!("{}?name={}", PASSWD_URL, name);
    let mut response = try!(client.get(url.as_str()).send());
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
        let mut c = Client::new();
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };

    let mut response = try!(client.get(GROUP_URL).send());
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
        let mut c = Client::new();
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };
    let url = format!("{}?gid={}", GROUP_URL, gid);
    let mut response = try!(client.get(url.as_str()).send());
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
        let mut c = Client::new();
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };
    let url = format!("{}?name={}", GROUP_URL, name);
    let mut response = try!(client.get(url.as_str()).send());
    if response.status == StatusCode::NotFound {
        return Ok(None)
    }
    let mut response_body = String::new();
    let _num_bytes_read = try!(response.read_to_string(&mut response_body));
    let entry: AlexandriaGroup = try!(json::decode(&response_body));
    Ok(Some(entry))
}

pub fn shadow() -> Result<Vec<AlexandriaShadow>, AlexandriaSvcError> {
    let client = {
        let mut c = Client::new();
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };

    let mut response = try!(client.get(SHADOW_URL).send());
    if response.status == StatusCode::NotFound {
        return Ok(vec![]);
    }
    let mut response_body = String::new();
    let _num_bytes_read = try!(response.read_to_string(&mut response_body));
    let entries: Vec<AlexandriaShadow> = try!(json::decode(&response_body));

    Ok(entries)
}

pub fn shadow_name(name: &str) -> Result<Option<AlexandriaShadow>, AlexandriaSvcError> {
    let client = {
        let mut c = Client::new();
        c.set_read_timeout(Some(Duration::from_millis(HTTP_READ_TIMEOUT_MS)));
        c.set_write_timeout(Some(Duration::from_millis(HTTP_WRITE_TIMEOUT_MS)));
        c
    };
    let url = format!("{}?name={}", SHADOW_URL, name);
    let mut response = try!(client.get(url.as_str()).send());
    if response.status == StatusCode::NotFound {
        return Ok(None)
    }
    let mut response_body = String::new();
    let _num_bytes_read = try!(response.read_to_string(&mut response_body));
    let entry: AlexandriaShadow = try!(json::decode(&response_body));
    Ok(Some(entry))
}
