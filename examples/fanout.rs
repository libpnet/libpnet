// Copyright (c) 2018 Berkus Decker <berkus+github@metta.systems>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// This example shows simple packet_fanout processing under linux.
/// PACKET_FANOUT in linux allows to offload packet processing to multiple threads.
/// See [man 7 packet](http://man7.org/linux/man-pages/man7/packet.7.html) for more details.
extern crate pnet;
extern crate pnet_datalink;

use std::io::{self, Write};
use std::process;

#[cfg(not(target_os = "linux"))]
fn main() {
    writeln!(io::stderr(), "fanout is only supported on Linux").unwrap();
    process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    use pnet::datalink::Channel::Ethernet;
    use pnet::datalink::{self, Config, FanoutOption, FanoutType, NetworkInterface};
    use std::env;
    use std::thread;

    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(io::stderr(), "USAGE: fanout <NETWORK INTERFACE> [hash|*round-robin*|cpu|rollover|rnd|qm|cbpf|ebpf] [group-id:123]").unwrap();
            process::exit(1);
        }
    };
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::linux::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    let fanout_type = match env::args().nth(2) {
        Some(n) => match n.to_lowercase().as_str() {
            "hash" => FanoutType::HASH,
            "round-robin" => FanoutType::LB,
            "cpu" => FanoutType::CPU,
            "rollover" => FanoutType::ROLLOVER,
            "rnd" => FanoutType::RND,
            "qm" => FanoutType::QM,
            "cbpf" => FanoutType::CBPF,
            "ebpf" => FanoutType::EBPF,
            _ => panic!("Unsupported fanout type, use one of hash, round-robin, cpu, rollover, rnd, qm, cbpf or ebpf")
        },
        None => FanoutType::LB,
    };

    let group_id = match env::args().nth(3) {
        Some(n) => n.parse::<u16>().unwrap(),
        None => 123,
    };

    let mut config: Config = Default::default();
    config.linux_fanout = Some(FanoutOption {
        group_id: group_id,
        fanout_type: fanout_type,
        defrag: true,
        rollover: false,
    });

    let mut threads = vec![];
    for x in 0..3 {
        let itf = interface.clone();
        let thread = thread::Builder::new()
            .name(format!("thread{}", x))
            .spawn(move || {
                // Create a channel to receive on
                let (_, mut rx) = match datalink::channel(&itf, config) {
                    Ok(Ethernet(tx, rx)) => (tx, rx),
                    Ok(_) => panic!("packetdump: unhandled channel type"),
                    Err(e) => panic!("packetdump: unable to create channel: {}", e),
                };

                let handle = thread::current();

                loop {
                    match rx.next() {
                        Ok(_packet) => {
                            writeln!(
                                io::stdout(),
                                "Received packet on thread {:?}",
                                handle.name()
                            )
                            .unwrap();
                        }
                        Err(e) => panic!("packetdump: unable to receive packet: {}", e),
                    }
                }
            })
            .unwrap();
        threads.push(thread);
    }

    for t in threads {
        t.join().unwrap();
    }
}
