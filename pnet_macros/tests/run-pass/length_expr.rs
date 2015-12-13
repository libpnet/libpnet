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

fn main() {}
