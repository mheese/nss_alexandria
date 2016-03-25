
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
