#!/bin/bash

# Copyright (C) 2016 Marcus Heese
#
# This file is part of nss_alexandria.
#
# nss_alexandria is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# nss_alexandria is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with nss_alexandria.  If not, see <http://www.gnu.org/licenses/>.

set -o xtrace
install -v -m 755 target/release/libnss_alexandria.so /lib64/libnss_alexandria.so.2
