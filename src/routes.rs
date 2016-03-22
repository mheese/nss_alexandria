use rustc_serialize::json;
use std::io::Read;
use hyper::{Client};
use config::PASSWD_URL;
use util::log;
use types::AlexandriaPassword;
use libc::uid_t;


pub fn passwd() -> Vec<AlexandriaPassword> {
    let client = Client::new();
    if let Ok(mut response) = client.get(PASSWD_URL).send() {
        let mut response_str = String::new();
        if let Ok(_) = response.read_to_string(&mut response_str) {
            let entries: Vec<AlexandriaPassword> = json::decode(&response_str).unwrap_or_else(|_|
                vec![]
            );
            log(format!("routes::passwd(): entries length: {}", entries.len()).as_str());
            log(response_str.as_str());
            return entries;
        }
    }
    return vec![];
}

pub fn passwd_uid(uid: uid_t) -> Option<AlexandriaPassword> {
    let url = format!("{}?uid={}", PASSWD_URL, uid);
    let client = Client::new();
    if let Ok(mut response) = client.get(url.as_str()).send() {
        let mut response_str = String::new();
        if let Ok(_) = response.read_to_string(&mut response_str) {
            return match json::decode(&response_str) {
                Ok(entry) => Some(entry),
                Err(_) => None,
            }
            //return
        }
    }
    return None;
}

pub fn passwd_name(name: &str) -> Option<AlexandriaPassword> {
    let url = format!("{}?name={}", PASSWD_URL, name);
    let client = Client::new();
    if let Ok(mut response) = client.get(url.as_str()).send() {
        let mut response_str = String::new();
        if let Ok(_) = response.read_to_string(&mut response_str) {
            return match json::decode(&response_str) {
                Ok(entry) => Some(entry),
                Err(_) => None,
            }
            //return
        }
    }
    return None;
}
