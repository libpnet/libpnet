// Copyright (c) 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![feature(custom_attribute, plugin)]
#![plugin(pnet_macros)]

extern crate pnet;

#[packet]
pub struct PacketWithPayload {
    #[length_fn = ""]
    #[payload]
    payload1: Vec<u8>,  //~ NOTE first payload defined here
    #[payload]
    payload2: Vec<u8>   //~ ERROR packet may not have multiple payloads
}


