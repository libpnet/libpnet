// Copyright (c) 2023 Stephen Doyle
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A VXLAN packet abstraction.

use alloc::vec::Vec;

use pnet_macros::packet;
use pnet_macros_support::types::*;

/// Virtual eXtensible Local Area Network (VXLAN)
///
/// See [RFC 7348](https://datatracker.ietf.org/doc/html/rfc7348)
///
/// VXLAN Header:
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |R|R|R|R|I|R|R|R|            Reserved                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                VXLAN Network Identifier (VNI) |   Reserved    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[packet]
pub struct Vxlan {
    pub flags: u8,
    pub reserved1: u24be,
    pub vni: u24be,
    pub reserved2: u8,
    #[payload]
    pub payload: Vec<u8>,
}

#[test]
fn vxlan_packet_test() {
    let mut packet = [0u8;8];
    {
        let mut vxlan_header = MutableVxlanPacket::new(&mut packet[..]).unwrap();
        vxlan_header.set_flags(0x08);
        assert_eq!(vxlan_header.get_flags(), 0x08);
        vxlan_header.set_vni(0x123456);
        assert_eq!(vxlan_header.get_vni(), 0x123456);
    }

    let ref_packet = [
        0x08, // I flag
        0x00, 0x00, 0x00, // Reserved
        0x12, 0x34, 0x56, // VNI
        0x00 // Reserved
    ];
    assert_eq!(&ref_packet[..], &packet[..]);
}
