// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![feature(phase)]
#[phase(plugin, link)] extern crate pnet;

extern crate time;

use pnet::datalink::{datalink_channel, Layer2};
use pnet::util::get_network_interfaces;

use std::os;

fn main() {
    let ref interface_name = os::args()[1];

    // Find the network interface with the provided name
    let interfaces = get_network_interfaces();
    let interface = interfaces.iter()
                              .filter(|iface| iface.name == *interface_name)
                              .next()
                              .unwrap();

    // Create a channel to receive on
    let (_, mut rx) = match datalink_channel(interface, 0, 4096, Layer2) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("rs_benchmark: unable to create channel: {}", e)
    };

    let mut i = 0u;
    let mut timestamps = Vec::with_capacity(201);
    timestamps.push(time::precise_time_ns() / 1_000);
    pfor!(_ in rx.iter() {
        i += 1;
        if i == 1_000_000 {
            timestamps.push(time::precise_time_ns() / 1_000);
            if timestamps.len() == 201 {
                break;
            }
            i = 0;
        }
    } on Err(e) {
        println!("rs_benchmark: unable to receive packet: {}", e);
    })

    // We received 1_000_000 packets in ((b - a) * 1_000_000) seconds.
    for (a, b) in timestamps.iter().zip(timestamps.tail().iter()) {
        println!("{}", *b - *a);
    }
}

