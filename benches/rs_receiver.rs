// Copyright (c) 2014, 2015, 2022 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate pnet_datalink;
extern crate time;

use std::env;
use time::OffsetDateTime;

fn main() {
    use pnet_datalink::Channel::Ethernet;

    let iface_name = env::args().nth(1).unwrap();

    // Find the network interface with the provided name
    let interfaces = pnet_datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == iface_name)
        .next()
        .unwrap();

    // Create a channel to receive on
    let mut rx = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => panic!("rs_sender: unhandled channel type"),
        Err(e) => panic!("rs_sender: unable to create channel: {}", e),
    };

    let mut i = 0usize;
    let mut timestamps = Vec::with_capacity(201);
    timestamps.push(OffsetDateTime::now_utc().unix_timestamp());

    loop {
        match rx.next() {
            Ok(_) => {
                i += 1;
                if i == 1_000_000 {
                    timestamps.push(OffsetDateTime::now_utc().unix_timestamp());
                    if timestamps.len() == 201 {
                        break;
                    }
                    i = 0;
                }
            }
            Err(e) => {
                println!("rs_sender: unable to receive packet: {}", e);
            }
        }
    }

    // We received 1_000_000 packets in ((b - a) * 1_000_000) seconds.
    for (a, b) in timestamps.iter().zip(timestamps.iter().skip(1)) {
        println!("{}", *b - *a);
    }
}
