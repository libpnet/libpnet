// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![feature(custom_attribute, plugin, slice_bytes, vec_push_all)]
#![plugin(pnet_macros)]

extern crate pnet;

#[packet]
pub struct Key {
    banana: u8,
    #[length = "banana"]
    #[payload]
    payload: Vec<u8>
}

#[packet]
pub struct AnotherKey {
    banana: u8,
    #[length = "banana + 7"]
    #[payload]
    payload: Vec<u8>
}

fn main() {
    let key_payload = vec![1, 2, 3, 4];
    let key = Key {
        banana: key_payload.len() as u8,
        payload: key_payload
    };
    assert_eq!(KeyPacket::packet_size(&key), 5);


    let another_key_payload = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let another_key = AnotherKey {
        banana: (another_key_payload.len() - 7) as u8,
        payload: another_key_payload
    };
    assert_eq!(AnotherKeyPacket::packet_size(&another_key), 11);
}
