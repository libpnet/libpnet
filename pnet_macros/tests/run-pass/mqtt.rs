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
pub struct Mqtt {
    source: u16be,
    destination: u16be,
    #[length_fn="mqtt_options_length"]
    options: Vec<u8>,
    t: u8,
    #[payload]
    payload: Vec<u8>,
}

fn mqtt_options_length(_: &MqttPacket) -> usize {
    0
}

fn main() {}
