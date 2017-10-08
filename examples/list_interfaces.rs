// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// This examples simply print all interfaces to stdout

extern crate pnet_datalink;

fn main() {
    for interface in pnet_datalink::interfaces() {
        let mac = interface.mac.map(|mac| mac.to_string()).unwrap_or("N/A".to_owned());
        println!("{}:", interface.name);
        println!("  index: {}", interface.index);
        println!("  flags: {}", interface.flags);
        println!("  MAC: {}", mac);
        println!("  IPs:");
        for ip in interface.ips {
            println!("    {:?}", ip);
        }
    }
}
