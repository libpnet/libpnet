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
pub struct ByteAligned {
    banana: u8,
    #[payload]
    payload: Vec<u8>,
}


#[packet]
pub struct ByteAlignedWithVariableLength {
    banana: u16be,
    #[length_fn = "length_fn1"]
    #[payload]
    payload: Vec<u8>,
}

fn length_fn1(_: &ByteAlignedWithVariableLengthPacket) -> usize {
    unimplemented!()
}


#[packet]
pub struct ByteAlignedWithVariableLengthAndPayload {
    banana: u32be,
    #[length_fn = "length_fn2"]
    var_length: Vec<u8>,
    #[payload]
    payload: Vec<u8>,
}

fn length_fn2(_: &ByteAlignedWithVariableLengthAndPayloadPacket) -> usize {
    unimplemented!()
}


#[packet]
pub struct NonByteAligned {
    banana: u3,
    tomato: u5,
    #[payload]
    payload: Vec<u8>,
}


#[packet]
pub struct NonByteAlignedWithVariableLength {
    banana: u11be,
    tomato: u21be,
    #[length_fn = "length_fn3"]
    #[payload]
    payload: Vec<u8>,
}

fn length_fn3(_: &NonByteAlignedWithVariableLengthPacket) -> usize {
    unimplemented!()
}


#[packet]
pub struct NonByteAlignedWithVariableLengthAndPayload {
    banana: u7,
    tomato: u9be,
    #[length_fn = "length_fn4"]
    var_length: Vec<u8>,
    #[payload]
    payload: Vec<u8>,
}

fn length_fn4(_: &NonByteAlignedWithVariableLengthAndPayloadPacket) -> usize {
    unimplemented!()
}


fn main() {
    assert_eq!(ByteAlignedPacket::minimum_packet_size(), 1);
    assert_eq!(ByteAlignedWithVariableLengthPacket::minimum_packet_size(),
               2);
    assert_eq!(ByteAlignedWithVariableLengthAndPayloadPacket::minimum_packet_size(),
               4);
    assert_eq!(NonByteAlignedPacket::minimum_packet_size(), 1);
    assert_eq!(NonByteAlignedWithVariableLengthPacket::minimum_packet_size(),
               4);
    assert_eq!(NonByteAlignedWithVariableLengthAndPayloadPacket::minimum_packet_size(),
               2);
}
