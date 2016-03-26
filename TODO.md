## TODOs

### for v0.2.0: *group and shadow dbs*
*GOALS:*
- implement group database
- implement shadow database

*Items:*
- convert PwdList to DbList<T>
- DONE: refactor PW_LIST to PWD_LIST
- refactor LIB_LOCK to PWD_LIBLOCK
- implement AlexandriaGroup type
- implement AlexandriaShadow type
- implement write_group
- implement write_shadow
- implement group route
- implement group_uid route
- implement group_name route
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
