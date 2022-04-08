// Copyright (c) 2022 Yureka <yuka@yuka.dev>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate pnet_macros;
extern crate pnet_macros_support;
use pnet_macros::packet;
use pnet_macros_support::types::*;

#[packet]
pub struct Test {
    banana: u2,
    apple: u4,
    potato: u6,
    the_rest: u20be,
    #[payload]
    payload: Vec<u8>,
}

fn main() {
    let test = Test {
        banana: 0b10,
        apple: 0b1010,
        potato: 0b101010,
        the_rest: 0b10101010101010101010,
        payload: vec![],
    };

    let mut buf = vec![0; TestPacket::packet_size(&test)];
    let mut packet = MutableTestPacket::new(&mut buf).unwrap();
    packet.populate(&test);
    assert_eq!(packet.get_banana(), test.banana);
    assert_eq!(packet.get_apple(), test.apple);
    assert_eq!(packet.get_potato(), test.potato);
    assert_eq!(packet.get_the_rest(), test.the_rest);
}
