use rustc_serialize::json;
use std::io::Read;
use hyper::{Client};
use config::PASSWD_URL_LIST;
use util::log;

/*
{
  pw_name: "gary",
  pw_passwd: "x",
  pw_uid: 100,
  pw_gid: 100,
  pw_gecos: "User Information",
  pw_dir: "/home/gary",
  pw_shell: "/bin/bash"
}
*/
#[derive(RustcEncodable, RustcDecodable, Clone, Debug)]
pub struct AlexandriaPassword {
    pub pw_name: String,
    pub pw_passwd: String,
    pub pw_uid: u32,
    pub pw_gid: u32,
    pub pw_gecos: String,
    pub pw_dir: String,
    pub pw_shell: String,
}

/*
pub fn str_to_mut_char(str: String) -> *mut c_char {
    let bytes: Vec<u8> = (str + "\0").into_bytes();
    let mut cchars: Vec<c_char> = bytes.iter().map(|&x| x as c_char).collect();
    return cchars.as_mut_ptr();
}

pub fn entry_to_passwd(entry: AlexandriaPassword) -> passwd {
    return passwd {
        pw_name: CString::new(entry.pw_name).unwrap().into_raw(),
        pw_passwd: CString::new(entry.pw_passwd).unwrap().into_raw(),
        pw_uid: entry.pw_uid,
        pw_gid: entry.pw_gid,
        pw_gecos: CString::new(entry.pw_gecos).unwrap().into_raw(),
        pw_dir: CString::new(entry.pw_dir).unwrap().into_raw(),
        pw_shell: CString::new(entry.pw_shell).unwrap().into_raw(),
    }
}*/

pub fn route_passwd() -> Vec<AlexandriaPassword> {
    let client = Client::new();
    if let Ok(mut response) = client.get(PASSWD_URL_LIST).send() {
        let mut response_str = String::new();
        if let Ok(_) = response.read_to_string(&mut response_str) {
            let entries: Vec<AlexandriaPassword> = json::decode(&response_str).unwrap_or_else(|_|
                vec![]
            );
            log(format!("entries length: {}", entries.len()).as_str());
            log(response_str.as_str());
            return entries;
        }
    }
    return vec![];
}
