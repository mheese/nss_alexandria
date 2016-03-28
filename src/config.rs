// Copyright (C) 2016 Marcus Heese
//
// This file is part of nss_alexandria.
//
// nss_alexandria is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// nss_alexandria is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with nss_alexandria.  If not, see <http://www.gnu.org/licenses/>.

pub const SOCKET_PATH: &'static str = "/var/lib/alexandria/nss.sock";
pub const SOCKET_PATH_PRIV: &'static str = "/var/lib/alexandria/nss_priv.sock";
pub const PASSWD_URL: &'static str = "/passwd";
pub const GROUP_URL: &'static str = "/group";
pub const SHADOW_URL: &'static str = "/shadow";
pub const HTTP_READ_TIMEOUT_MS: u64 = 100;
pub const HTTP_WRITE_TIMEOUT_MS: u64 = 100;
