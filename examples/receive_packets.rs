// Copyright (c) 2024 
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Minimal packet receiver that captures UDP and ICMP packets and prints metadata in real time

extern crate pnet;
extern crate pnet_datalink;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, Config};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: {} <interface_name>", args[0]);
        println!("\nAvailable interfaces:");
        for interface in datalink::interfaces() {
            println!("  {}", interface.name);
        }
        return;
    }

    let interface_name = &args[1];

    // Find the network interface
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == *interface_name)
        .unwrap_or_else(|| {
            println!("Interface '{}' not found", interface_name);
            process::exit(1);
        });

    println!("Listening on interface: {}", interface.name);
    println!("Capturing UDP and ICMP packets... (Press Ctrl+C to stop)\n");

    let config = Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: true,
        socket_fd: None,
    };

    // Create a datalink channel
    let (_tx, mut rx) = match datalink::channel(&interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            println!("Unhandled channel type");
            return;
        }
        Err(e) => {
            println!("Failed to create datalink channel: {}", e);
            return;
        }
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    handle_ethernet_packet(&ethernet_packet);
                }
            }
            Err(e) => {
                println!("Failed to receive packet: {}", e);
                break;
            }
        }
    }
}

fn handle_ethernet_packet(ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
                handle_ipv4_packet(&ipv4_packet);
            }
        }
        _ => {} // Ignore other protocols
    }
}

fn handle_ipv4_packet(ipv4: &Ipv4Packet) {
    let src_ip = ipv4.get_source();
    let dst_ip = ipv4.get_destination();
    
    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Udp => {
            if let Some(udp_packet) = UdpPacket::new(ipv4.payload()) {
                println!("UDP: {}:{} -> {}:{} [len:{}]",
                    src_ip, udp_packet.get_source(),
                    dst_ip, udp_packet.get_destination(),
                    udp_packet.get_length());
            }
        }
        IpNextHeaderProtocols::Icmp => {
            if let Some(icmp_packet) = IcmpPacket::new(ipv4.payload()) {
                println!("ICMP: {} -> {} [type:{:?} code:{:?}]",
                    src_ip, dst_ip,
                    icmp_packet.get_icmp_type(),
                    icmp_packet.get_icmp_code());
            }
        }
        _ => {} // Ignore other protocols
    }
}