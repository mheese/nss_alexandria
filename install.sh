#!/bin/bash

set -o xtrace
install -v -m 755 target/release/libnss_alexandria.so /lib64/libnss_alexandria.so.2
