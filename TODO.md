## TODOs

### for v0.3.0: *move to unix sockets*
- DONE: BUG: research and fix why sudo crashes libc now
- DONE: move HTTP service requests to UNIX sockets
- DONE: shadow needs own socket with root only access

long-term: *move to D-BUS ?*
- use D-BUS instead of own UNIX sockets (that's what it is good for in the end)
