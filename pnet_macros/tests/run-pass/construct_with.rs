// Copyright (c) 2021 Pierre Chifflier <chifflier@wzdftpd.net>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate pnet_macros;
extern crate pnet_macros_support;
use pnet_macros::packet;
use pnet_macros_support::packet::PrimitiveValues;

#[derive(Clone, Copy, Debug)]
pub struct Toto{
    dummy: u16,
}

impl PrimitiveValues for Toto {
    type T = (u16,);
    fn to_primitive_values(&self) -> (u16,) {
        (self.dummy,)
    }
}

impl Toto {
    pub fn new(dummy: u16) -> Self {
        Toto{ dummy }
    }
}

#[packet]
pub struct PacketU16 {
    #[construct_with(u16)]
    banana: Toto,
    #[payload]
    payload: Vec<u8>,
}

fn main() {}
