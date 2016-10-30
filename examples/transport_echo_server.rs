// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate pnet;

/// A simple echo server for packets using a test protocol

use std::iter::repeat;

use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::MutableUdpPacket;
use pnet::transport::{transport_channel, udp_packet_iter};
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::TransportChannelType::Layer4;

fn main() {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Test1));

    // Create a new transport channel, dealing with layer 4 packets on a test protocol
    // It has a receive buffer of 4096 bytes.
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            panic!("An error occurred when creating the transport channel: {}",
                   e)
        }
    };

    // We treat received packets as if they were UDP packets
    let mut iter = udp_packet_iter(&mut rx);
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                // Allocate enough space for a new packet
                let mut vec: Vec<u8> = repeat(0u8).take(packet.packet().len()).collect();
                let mut new_packet = MutableUdpPacket::new(&mut vec[..]).unwrap();

                // Create a clone of the original packet
                new_packet.clone_from(&packet);

                // Switch the source and destination ports
                new_packet.set_source(packet.get_destination());
                new_packet.set_destination(packet.get_source());

                // Send the packet
                match tx.send_to(new_packet, addr) {
                    Ok(n) => assert_eq!(n, packet.packet().len()),
                    Err(e) => panic!("failed to send packet: {}", e),
                }
            }
            Err(e) => {
                // If an error occurs, we can handle it here
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
