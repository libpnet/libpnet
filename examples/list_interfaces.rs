// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// This example prints detailed information about all network interfaces
extern crate pnet_datalink;

fn main() {
    let interfaces = pnet_datalink::interfaces();

    println!("Found {} network interface(s):\n", interfaces.len());

    for (i, interface) in interfaces.iter().enumerate() {
        println!("Interface #{}", i + 1);
        println!("  Device Name: {}", interface.name);
        println!("  Description: {}", interface.description);
        println!("  Index: {}", interface.index);

        // Show MAC address
        match interface.mac {
            Some(mac) => println!("  MAC Address: {}", mac),
            None => println!("  MAC Address: Not Available"),
        }

        // Show flags
        println!("  Flags: 0x{:X}", interface.flags);

        // Show status flags if available
        let mut status_flags = Vec::new();
        if interface.is_up() {
            status_flags.push("UP");
        }
        if interface.is_broadcast() {
            status_flags.push("BROADCAST");
        }
        if interface.is_loopback() {
            status_flags.push("LOOPBACK");
        }
        if interface.is_point_to_point() {
            status_flags.push("POINT_TO_POINT");
        }
        if interface.is_multicast() {
            status_flags.push("MULTICAST");
        }

        #[cfg(unix)]
        {
            if interface.is_running() {
                status_flags.push("RUNNING");
            }
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if interface.is_lower_up() {
                status_flags.push("LOWER_UP");
            }
            if interface.is_dormant() {
                status_flags.push("DORMANT");
            }
        }

        if !status_flags.is_empty() {
            println!("  Status: {}", status_flags.join(", "));
        } else {
            println!("  Status: None");
        }

        // Show IP addresses
        if interface.ips.is_empty() {
            println!("  IP Addresses: None");
        } else {
            println!("  IP Addresses:");
            for ip in &interface.ips {
                if ip.is_ipv4() {
                    println!("    IPv4: {}", ip);
                } else {
                    println!("    IPv6: {}", ip);
                }
            }
        }

        println!("  ---");
    }
}
