// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Miscellaneous utilities for low-level networking.

pub use pnet_base::{core_net, MacAddr, ParseMacAddrErr};
pub use pnet_packet::util::{checksum, ipv4_checksum, ipv6_checksum, Octets};
