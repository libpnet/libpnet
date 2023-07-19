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

#[derive(Clone, Debug)]
pub struct Toto{
    dummy: u16,
}

#[packet]
pub struct PacketU16 {
    #[construct_with()] //~ ERROR #[construct_with] must have at least one argument
    banana: Toto,
    #[payload]
    payload: Vec<u8>,
}

#[packet]
pub struct PacketU16B {
    #[construct_with("test")] //~ ERROR #[construct_with] should be of the form #[construct_with(<primitive types>)]
    banana: Toto,
    #[payload]
    payload: Vec<u8>,
}

#[packet]
pub struct PacketU16C {
    #[construct_with(::foo:bar)] //~ ERROR #[construct_with] should be of the form #[construct_with(<primitive types>)]
    banana: Toto,
    #[payload]
    payload: Vec<u8>,
}

#[packet]
pub struct PacketU16D {
    #[construct_with(Vec<u8>)] //~ ERROR #[construct_with] should be of the form #[construct_with(<primitive types>)]
    banana: Toto,
    #[payload]
    payload: Vec<u8>,
}

#[packet]
pub struct PacketU16E {
    #[construct_with(test)] //~ ERROR arguments to #[construct_with] must be primitives
    banana: Toto,
    #[payload]
    payload: Vec<u8>,
}


fn main() {}
