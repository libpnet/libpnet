// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// FIXME Remove before 1.0
#![allow(unstable)]

extern crate pnet;

use pnet::datalink::{datalink_channel};
use pnet::datalink::DataLinkChannelType::Layer2;
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetHeader, EthernetHeader};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Header};
use pnet::packet::udp::{MutableUdpHeader};
use pnet::util::get_network_interfaces;

use std::old_io::net::ip::Ipv4Addr;
use std::os;

static IPV4_HEADER_LEN: usize = 20;
static UDP_HEADER_LEN: usize = 8;
static TEST_DATA_LEN: usize = 5;

pub fn build_ipv4_header(packet: &mut [u8]) -> MutableIpv4Header {
    let mut ip_header = MutableIpv4Header::new(packet);

    let total_len = (IPV4_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN) as u16;

    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(total_len);
    ip_header.set_ttl(4);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
    ip_header.set_source(Ipv4Addr(127, 0, 0, 1));
    ip_header.set_destination(Ipv4Addr(127, 0, 0, 1));
    ip_header.checksum();

    ip_header
}

pub fn build_udp_header(packet: &mut [u8]) -> MutableUdpHeader {
    let mut udp_header = MutableUdpHeader::new(packet);

    udp_header.set_source(1234); // Arbitary port number
    udp_header.set_destination(1234);
    udp_header.set_length((UDP_HEADER_LEN + TEST_DATA_LEN) as u16);

    udp_header
}

pub fn build_udp4_packet(packet: &mut [u8], msg: &str) {
    let mut ip_header = build_ipv4_header(packet);
    let source = ip_header.get_source();
    let destination = ip_header.get_destination();
    let mut udp_header = build_udp_header(ip_header.payload_mut());

    {
        let data = udp_header.payload_mut();
        data[0] = msg.char_at(0) as u8;
        data[1] = msg.char_at(1) as u8;
        data[2] = msg.char_at(2) as u8;
        data[3] = msg.char_at(3) as u8;
        data[4] = msg.char_at(4) as u8;
    }

    udp_header.checksum(source, destination, IpNextHeaderProtocols::Udp);
}

fn main() {
    let ref interface_name = os::args()[1];
    let destination = os::args()[2].as_slice().parse().unwrap();
    // Find the network interface with the provided name
    let interfaces = get_network_interfaces();
    let interface = interfaces.iter()
                              .filter(|iface| iface.name == *interface_name)
                              .next()
                              .unwrap();

    // Create a channel to send on
    let (mut tx, _) = match datalink_channel(interface, 64, 0, Layer2) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("rs_sender: unable to create channel: {}", e)
    };

    let mut buffer = [0u8; 64];
    let mut mut_ethernet_header = MutableEthernetHeader::new(buffer.as_mut_slice());
    {
        mut_ethernet_header.set_destination(destination);
        mut_ethernet_header.set_source(interface.mac_address());
        mut_ethernet_header.set_ethertype(EtherTypes::Ipv4);
        build_udp4_packet(mut_ethernet_header.payload_mut(), "rmesg");
    }

    let ethernet_header = EthernetHeader::new(mut_ethernet_header.packet());

    loop {
        tx.send_to(ethernet_header, None);
    }
}

