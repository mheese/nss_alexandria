## TODOs

### for v0.4.0: *refactoring and bug fixes*
- refactor routes.rs - heavy code deduplication can be done
- refactor util.rs
  - lots of buffer calculation can be done in the beginning of each function
  - lesser checks necessary later on
  - switch to rust-style memory copy functions where possible
  - and therefore eliminate libc strncpy if possible
- fix bugs that come up while developing alexandriad

### for v0.5.0: *TBD*
- the current 0.3.0 allows us to develop alexandriad which is more important

## long-term considerations
- use D-BUS instead of own UNIX sockets with HTTP
