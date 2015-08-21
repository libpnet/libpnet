// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// FIXME Remove before 1.0
#![feature(ip_addr)]

/// This example shows a basic packet logger using libpnet

extern crate pnet;

use std::env;
use std::net::{IpAddr};

use pnet::packet::{Packet};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet};
use pnet::packet::ipv6::{Ipv6Packet};
use pnet::packet::udp::{UdpPacket};

use pnet::datalink::{datalink_channel};
use pnet::datalink::DataLinkChannelType::{Layer2};

use pnet::util::{NetworkInterface, get_network_interfaces};

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        println!("[{}]: UDP Packet: {}:{} > {}:{}; length: {}", interface_name, source,
                        udp.get_source(), destination, udp.get_destination(), udp.get_length());
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    // Since we only look at source and destination ports, and these are located in the same
    // place in both TCP and UDP headers, we cheat here
    let udp = UdpPacket::new(packet);
    if let Some(udp) = udp {
        println!("[{}]: TCP Packet: {}:{} > {}:{}; length: {}", interface_name, source,
                    udp.get_source(), destination, udp.get_destination(), packet.len());
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn handle_transport_protocol(interface_name: &str, source: IpAddr, destination: IpAddr,
                             protocol: IpNextHeaderProtocol, packet: &[u8]) {
    match protocol {
        IpNextHeaderProtocols::Udp  => handle_udp_packet(interface_name, source, destination, packet),
        IpNextHeaderProtocols::Tcp  => handle_tcp_packet(interface_name, source, destination, packet),
        _ => println!("[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                interface_name,
                match source { IpAddr::V4(..) => "IPv4", _ => "IPv6" },
                source,
                destination,
                protocol,
                packet.len())

    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(interface_name,
                                  IpAddr::V4(header.get_source()),
                                  IpAddr::V4(header.get_destination()),
                                  header.get_next_level_protocol(),
                                  header.payload());
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(interface_name,
                                  IpAddr::V6(header.get_source()),
                                  IpAddr::V6(header.get_destination()),
                                  header.get_next_level_protocol(),
                                  header.payload());
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_arp_packet(interface_name: &str, ethernet: &EthernetPacket) {
    println!("[{}]: ARP packet: {} > {}; length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.packet().len())

}

fn handle_packet(interface_name: &str, ethernet: &EthernetPacket) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => handle_ipv4_packet(interface_name, ethernet),
        EtherTypes::Ipv6 => handle_ipv6_packet(interface_name, ethernet),
        EtherTypes::Arp  => handle_arp_packet(interface_name, ethernet),
        _                => println!("[{}]: Unknown packet: {} > {}; ethertype: {:?} length: {}",
                                        interface_name,
                                        ethernet.get_source(),
                                        ethernet.get_destination(),
                                        ethernet.get_ethertype(),
                                        ethernet.packet().len())
    }
}

fn main() {
    let iface_name = env::args().nth(1).unwrap();
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = get_network_interfaces();
    let interface = interfaces.into_iter()
                              .filter(interface_names_match)
                              .next()
                              .unwrap();

    // Create a channel to receive on
    let (_, mut rx) = match datalink_channel(&interface, 0, 4096, Layer2) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("packetdump: unable to create channel: {}", e)
    };

    let mut iter = rx.iter();
    loop {
        match iter.next() {
            Ok(packet) => handle_packet(&interface.name[..], &packet),
            Err(e) => panic!("packetdump: unable to receive packet: {}", e)
        }
    }
}
