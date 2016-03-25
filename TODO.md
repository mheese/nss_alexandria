TODOs
-----

- cleanup PwdList
- use mutex on PwdList

- routes need to return error on failure, so that we can return with NSS_STATUS_TRYAGAIN and EAGAIN
- check that routes abort if service not up

- DONE: write_passwd() should return nss_status directly
- DONE: write_passwd() should write errnop
- DONE: write_passwd() CString get rid of unwraps() and handle error properly
- DONE: write_passwd() when bufleft check fails, return NSS_STATUS_TRYAGAIN and set errnop to ERANGE
- write_passwd() make unsafe blocks easier to read

- remove logging once satisfied