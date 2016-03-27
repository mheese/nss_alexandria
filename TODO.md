## TODOs

### for v0.3.0: *move to unix sockets*
- BUG: research and fix why sudo crashes libc now
- move HTTP service requests to UNIX sockets
- implement own socket files for different databases
- shadow database needs 2 socket types:
  1. private (root and suid/guid of socket file only) can read it and therefore retrieve shadow entries
  2. "public" (users with the calling UID can query their own entry (maybe not even the actual shadow entry))

long-term: *move to D-BUS ?*
- use D-BUS instead of own UNIX sockets (that's what it is good for in the end)
