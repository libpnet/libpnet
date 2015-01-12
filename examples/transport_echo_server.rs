// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[macro_use] extern crate pnet;

/// A simple echo server for packets using a test protocol

use std::iter::repeat;

use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::{MutableUdpHeader, UdpPacket};
use pnet::transport::{transport_channel, udp_header_iter};
use pnet::transport::TransportProtocol::{Ipv4};
use pnet::transport::TransportChannelType::{Layer4};

fn main() {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Test1));

    // Create a new transport channel, dealing with layer 4 packets on a test protocol
    // It has a receive buffer of 4096 bytes.
    let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("An error occurred when creating the transport channel: {}", e)
    };

    // pfor works just like an ordinary for loop, but has additional syntax for
    // handling errors
    //
    // We treat received packets as if they were UDP packets
    pfor!((packet, addr), udp_header_iter(&mut rx), {
        // Allocate enough space for a new packet
        let mut vec: Vec<u8> = repeat(0u8).take(packet.packet().len()).collect();
        let mut new_packet = MutableUdpHeader::new(vec.as_mut_slice());

        // Create a clone of the original packet
        new_packet.clone_from(packet);

        // Switch the source and destination ports
        new_packet.set_source(packet.get_destination());
        new_packet.set_destination(packet.get_source());

        // Send the packet
        match tx.send_to(new_packet, addr) {
            Ok(n) => assert_eq!(n, packet.packet().len()),
            Err(e) => panic!("failed to send packet: {}", e)
        }
    } on Err(e) {
        // If an error occurs, we can handle it here. Note that this is handled
        // within the loop - if you wish to exit the loop you must `break` or
        // `return` as appropriate, otherwise it will keep executing.
        panic!("An error occurred while reading: {}", e);
    });
}

