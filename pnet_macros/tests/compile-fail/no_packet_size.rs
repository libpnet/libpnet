// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// error-pattern: error: no associated item named `packet_size` found for type `NoPacketSizeFn` in the current scope

#![feature(custom_attribute, plugin)]
#![plugin(pnet_macros)]

extern crate pnet;

#[packet]
pub struct NoPacketSizeFn {
    banana: u8,
    #[payload]
    payload: Vec<u8>
}

fn main() {
    let no_packet_size_fn = NoPacketSizeFn {
        banana: 7,
        payload: vec![1, 2, 3, 4]
    };
    let packet_size = NoPacketSizeFn::packet_size(&no_packet_size_fn);
}
