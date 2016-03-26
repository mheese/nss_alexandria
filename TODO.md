## TODOs

### for v0.2.0: *group and shadow dbs*
*GOALS:*
- implement group database
- implement shadow database

*Items:*
- DONE: convert PwdList to DbList<T>
- DONE: refactor PW_LIST to PWD_LIST
- DONE: refactor LIB_LOCK to PWD_LIBLOCK
- DONE: implement AlexandriaGroup type
- DONE: implement AlexandriaShadow type
- DONE: implement C group type (because currently not in libc)
- DONE: implement C shadow type (because currently not in libc)
- DONE: implement write_group
- implement write_shadow
- DONE: implement group route
- DONE: implement group_uid route
- DONE: implement group_name route
- implement shadow route
- implement shadow_name route
- implement all nss_alexandria C functions
- DONE: bump version in Cargo.toml
- add GPL v3 preamble to all files

### for v0.3.0: *move to unix sockets*
- move HTTP service requests to UNIX sockets
- implement own socket files for different databases
- shadow database needs 2 socket types:
  1. private (root and suid/guid of socket file only) can read it and therefore retrieve shadow entries
  2. "public" (users with the calling UID can query their own entry (maybe not even the actual shadow entry))

long-term: *move to D-BUS ?*
- use D-BUS instead of own UNIX sockets (that's what it is good for in the end)
