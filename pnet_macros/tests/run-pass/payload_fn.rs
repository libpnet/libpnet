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
    #[payload]
    payload: Vec<u8>,
}

fn main() {}
