// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![feature(custom_attribute, plugin, slice_bytes, vec_push_all)]
#![plugin(pnet_macros_plugin)]

extern crate pnet;
extern crate pnet_macros_support;

use pnet_macros_support::types::*;

#[packet]
pub struct PacketWithPayload {
    banana: u8,
    #[length_fn = "length_fn"]
    var_length: Vec<u8>,
    #[payload]
    payload: Vec<u8>,
}

#[packet]
pub struct PacketWithU16 {
    length: u8,
    #[length = "length"]
    data: Vec<u16be>,
    #[payload]
    payload: Vec<u8>,
}

fn length_fn(_: &PacketWithPayloadPacket) -> usize {
    unimplemented!()
}

fn main() {

    // Test if we can add data to the u16be
    let mut packet = [0u8; 7];
    {
        let mut p = MutablePacketWithU16Packet::new(&mut packet[..]).unwrap();
        p.set_length(6);
        p.set_data(&vec![0x0001, 0x1223, 0x3ff4]);
    }

    let ref_packet = [0x06, /* length */
                      0x00, 0x01,
                      0x12, 0x23,
                      0x3f, 0xf4];

    assert_eq!(&ref_packet[..], &packet[..]);

}
