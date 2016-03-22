#!/bin/bash

set -o xtrace
cargo rustc --release -- -Clink-args="-shared -Wl,-soname,libnss_alexandria.so.2"
