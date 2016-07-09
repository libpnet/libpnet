// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.


extern crate pnet;
extern crate time;

use pnet::datalink;
use pnet::util::NetworkInterface;

use std::env;

fn main() {
    use pnet::datalink::Channel::Ethernet;

    let iface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter()
                              .filter(interface_names_match)
                              .next()
                              .unwrap();

    // Create a channel to receive on
    let mut rx = match datalink::channel(&interface, &Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => panic!("rs_sender: unhandled channel type"),
        Err(e) => panic!("rs_benchmark: unable to create channel: {}", e)
    };

    let mut i = 0usize;
    let mut timestamps = Vec::with_capacity(201);
    timestamps.push(time::precise_time_ns() / 1_000);

    let mut iter = rx.iter();
    loop {
        match iter.next() {
            Ok(_) => {
                i += 1;
                if i == 1_000_000 {
                    timestamps.push(time::precise_time_ns() / 1_000);
                    if timestamps.len() == 201 {
                        break;
                    }
                    i = 0;
                }
            },
            Err(e) => {
                println!("rs_benchmark: unable to receive packet: {}", e);
            }
        }
    }

    // We received 1_000_000 packets in ((b - a) * 1_000_000) seconds.
    for (a, b) in timestamps.iter().zip(timestamps.iter().skip(1)) {
        println!("{}", *b - *a);
    }
}
