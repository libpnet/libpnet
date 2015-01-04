// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate libc;

pub const SOL_PACKET: libc::c_int = 263;
pub const PACKET_ADD_MEMBERSHIP: libc::c_int = 1;
pub const PACKET_MR_PROMISC: libc::c_int = 1;

// man 7 packet
pub struct packet_mreq {
    pub mr_ifindex: libc::c_int,
    pub mr_type: libc::c_ushort,
    pub mr_alen: libc::c_ushort,
    pub mr_address: [libc::c_uchar; 8]
}

