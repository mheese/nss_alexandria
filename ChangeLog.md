### v0.2.0

*GOALS:*
- implement group database
- implement shadow database

These were the features/things implemented and bugs fixed for this version:
- DONE: convert PwdList to DbList<T>
- DONE: refactor PW_LIST to PWD_LIST
- DONE: refactor LIB_LOCK to PWD_LIBLOCK
- DONE: implement AlexandriaGroup type
- DONE: implement AlexandriaShadow type
- DONE: implement C group type (because currently not in libc)
- DONE: implement C shadow type (because currently not in libc)
- DONE: implement write_group
- DONE: implement write_shadow
- DONE: implement group route
- DONE: implement group_uid route
- DONE: implement group_name route
- DONE: implement shadow route
- DONE: implement shadow_name route
- DONE: implement all nss_alexandria C functions for group DB
- DONE: implement all nss_alexandria C functions for shadow DB
- DONE: bump version in Cargo.toml
- DONE: add GPL v3 preamble to all files and add license file

### v0.1.0

*GOALS:*
- implement passwd database

These were the features/things implemented and bugs fixed for this version:
- DONE: cleanup PwdList
- DONE: use mutex on PwdList

- DONE: routes need to return error on failure, so that we can return with NSS_STATUS_TRYAGAIN and EAGAIN
- DONE: check that routes abort if service not up

- DONE: write_passwd() should return nss_status directly
- DONE: write_passwd() should write errnop
- DONE: write_passwd() CString get rid of unwraps() and handle error properly
- DONE: write_passwd() when bufleft check fails, return NSS_STATUS_TRYAGAIN and set errnop to ERANGE
- DONE: write_passwd() make unsafe blocks easier to read

- DONE: remove logging once satisfied
