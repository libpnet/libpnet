// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate pnet_macros;
extern crate pnet_macros_support;
use pnet_macros::packet;
#[packet]
pub struct PacketWithPayload {
    banana: u8,
    length: u8,
    header_length: u8,
    #[length_fn = "length_fn"]
    packet_option: Vec<PacketOption>,
    #[payload]
    payload: Vec<u8>,
}

#[packet]
pub struct PacketOption {
    pineapple: u8,
    length: u8,
    #[length_fn = "option_length_fn"]
    #[payload]
    payload: Vec<u8>,
}

fn length_fn(packet_with_payload: &PacketWithPayloadPacket) -> usize {
    packet_with_payload.get_header_length() as usize - 2
}

fn option_length_fn(packet_option: &PacketOptionPacket) -> usize {
    packet_option.get_length() as usize - 2
}

fn main() {
    let data = [1, 8, 5, 6, 3, 1, 9, 10];
    let packet = PacketWithPayloadPacket::new(&data[..]).unwrap();

    let packet_option = packet.get_packet_option();
    assert_eq!(packet_option.first().unwrap().pineapple, 6);
    assert_eq!(packet_option.first().unwrap().length, 3);
}
