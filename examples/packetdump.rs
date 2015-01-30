// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// FIXME Remove before 1.0
#![feature(core, os)]

/// This example shows a basic packet logger using libpnet

extern crate pnet;

use std::old_io::net::ip::{IpAddr, Ipv4Addr};
use std::os;

use pnet::packet::{Packet};
use pnet::packet::ethernet::{EthernetHeader, EthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Header, Ipv4Packet};
use pnet::packet::ipv6::{Ipv6Header, Ipv6Packet};
use pnet::packet::udp::{UdpHeader, UdpPacket};

use pnet::datalink::{datalink_channel};
use pnet::datalink::DataLinkChannelType::{Layer2};

use pnet::util::{NetworkInterface, get_network_interfaces};

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let udp = UdpHeader::new(packet);

    if packet.len() < 8 {
        println!("[{}]: Malformed UDP Packet", interface_name);
    } else {
        println!("[{}]: UDP Packet: {}:{} > {}:{}; length: {}", interface_name, source,
                        udp.get_source(), destination, udp.get_destination(), udp.get_length());
    }
}

fn handle_tcp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    // Since we only look at source and destination ports, and these are located in the same
    // place in both TCP and UDP headers, we cheat here
    let udp = UdpHeader::new(packet);
    if packet.len() < 8 {
        println!("[{}]: Malformed TCP Packet", interface_name);
    } else {
        println!("[{}]: TCP Packet: {}:{} > {}:{}; length: {}", interface_name, source,
                    udp.get_source(), destination, udp.get_destination(), packet.len());
    }
}

fn handle_transport_protocol(interface_name: &str, source: IpAddr, destination: IpAddr,
                             protocol: IpNextHeaderProtocol, packet: &[u8]) {
    match protocol {
        IpNextHeaderProtocols::Udp  => handle_udp_packet(interface_name, source, destination, packet),
        IpNextHeaderProtocols::Tcp  => handle_tcp_packet(interface_name, source, destination, packet),
        _ => println!("[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                interface_name,
                match source { Ipv4Addr(..) => "IPv4", _ => "IPv6" },
                source,
                destination,
                protocol,
                packet.len())

    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetHeader) {
    let header = Ipv4Header::new(ethernet.payload());
    handle_transport_protocol(interface_name,
                              header.get_source(),
                              header.get_destination(),
                              header.get_next_level_protocol(),
                              header.payload());
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetHeader) {
    let header = Ipv6Header::new(ethernet.payload());
    handle_transport_protocol(interface_name,
                              header.get_source(),
                              header.get_destination(),
                              header.get_next_header(),
                              header.payload());
}

fn handle_arp_packet(interface_name: &str, ethernet: &EthernetHeader) {
    println!("[{}]: ARP packet: {} > {}; length: {}",
            interface_name,
            ethernet.get_source(),
            ethernet.get_destination(),
            ethernet.packet().len())

}

fn handle_packet(interface_name: &str, ethernet: &EthernetHeader) {
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
    let interface_names_match = |&: iface: &NetworkInterface| iface.name == os::args()[1];

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
            Ok(packet) => handle_packet(interface.name.as_slice(), &packet),
            Err(e) => panic!("packetdump: unable to receive packet: {}", e)
        }
    }
}
