// Copyright (c) 2015 David Stainton <dstainton415@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TCP packet abstraction

use packet::Packet;
use packet::ip::IpNextHeaderProtocol;

use pnet_macros::types::*;

use std::net::{Ipv4Addr, Ipv6Addr};

/// Represents a TCP Packet
#[packet]
pub struct Tcp {
    source: u16be,
    destination: u16be,
    length: u16be,
    checksum: u16be,
    #[payload]
    payload: Vec<u8>
}

/// Calculate the checksum for a packet built on IPv4
pub fn ipv4_checksum<'a>(packet: &TcpPacket<'a>,
                         ipv4_source: Ipv4Addr,
                         ipv4_destination: Ipv4Addr,
                         next_level_protocol: IpNextHeaderProtocol)
-> u16be {
    let IpNextHeaderProtocol(next_level_protocol) = next_level_protocol;
    let mut sum = 0u32;

    // Checksum pseudo-header
    // IPv4 source
    match ipv4_source.octets() {
        [a, b, c, d] => {
            sum = sum + ((a as u32) << 8 | b as u32);
            sum = sum + ((c as u32) << 8 | d as u32);
        }
    }

    // IPv4 destination
    match ipv4_destination.octets() {
        [a, b, c, d] => {
            sum = sum + ((a as u32) << 8 | b as u32);
            sum = sum + ((c as u32) << 8 | d as u32);
        }
    }

    // IPv4 Next level protocol
    sum = sum + next_level_protocol as u32;

    // TCP Length
    sum = sum + ((packet.packet()[4] as u32) << 8 |
                  packet.packet()[5] as u32);

    // Checksum TCP header/packet
    let mut i = 0;
    let len = packet.get_length() as usize;
    while i < len && i + 1 < packet.packet().len() {
        let word = (packet.packet()[i] as u32) << 8 | packet.packet()[i + 1] as u32;
        sum = sum + word;
        i = i + 2;
    }
    // If the length is odd, make sure to checksum the final byte
    if len & 1 != 0 && len <= packet.packet().len() {
        sum = sum + ((packet.packet()[len - 1] as u32) << 8);
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    return !sum as u16;
}


#[test]
fn tcp_header_ipv4_test() {
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::MutableIpv4Packet;

    let mut packet = [0u8; 20 + 8 + 4];
    let ipv4_source = Ipv4Addr::new(192, 168, 0, 1);
    let ipv4_destination = Ipv4Addr::new(192, 168, 0, 199);
    let next_level_protocol = IpNextHeaderProtocols::Tcp;
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(next_level_protocol);
        ip_header.set_source(ipv4_source);
        ip_header.set_destination(ipv4_destination);
    }

    // Set data
    packet[20 + 8 + 0] = 't' as u8;
    packet[20 + 8 + 1] = 'e' as u8;
    packet[20 + 8 + 2] = 's' as u8;
    packet[20 + 8 + 3] = 't' as u8;

    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[20..]).unwrap();
        tcp_header.set_source(12345);
        assert_eq!(tcp_header.get_source(), 12345);

        tcp_header.set_destination(54321);
        assert_eq!(tcp_header.get_destination(), 54321);

        tcp_header.set_length(8 + 4);
        assert_eq!(tcp_header.get_length(), 8 + 4);

        let checksum = ipv4_checksum(&tcp_header.to_immutable(),
                                     ipv4_source,
                                     ipv4_destination,
                                     next_level_protocol);
        tcp_header.set_checksum(checksum);
        assert_eq!(tcp_header.get_checksum(), 0x9183);
    }

    let ref_packet = [0x30, 0x39, /* source */
                     0xd4, 0x31, /* destination */
                     0x00, 0x0c, /* length */
                     0x91, 0x83  /* checksum*/];
    assert_eq!(&ref_packet[..], &packet[20 .. 28]);
}


/// Calculate the checksum for a packet built on IPv6
pub fn ipv6_checksum<'a>(packet: &TcpPacket<'a>,
                         ipv6_source: Ipv6Addr,
                         ipv6_destination: Ipv6Addr,
                         next_header: IpNextHeaderProtocol) -> u16be {
    let IpNextHeaderProtocol(next_header) = next_header;
    let mut sum = 0u32;

    // Checksum pseudo-header
    // IPv6 source
    match ipv6_source.segments() {
        [a, b, c, d, e, f, g, h] => {
            sum = sum + a as u32;
            sum = sum + b as u32;
            sum = sum + c as u32;
            sum = sum + d as u32;
            sum = sum + e as u32;
            sum = sum + f as u32;
            sum = sum + g as u32;
            sum = sum + h as u32;
        }
    }

    // IPv6 destination
    match ipv6_destination.segments() {
        [a, b, c, d, e, f, g, h] => {
            sum = sum + a as u32;
            sum = sum + b as u32;
            sum = sum + c as u32;
            sum = sum + d as u32;
            sum = sum + e as u32;
            sum = sum + f as u32;
            sum = sum + g as u32;
            sum = sum + h as u32;
        }
    }

    // IPv6 Next header
    sum = sum + next_header as u32;

    // TCPP Length
    sum = sum + packet.get_length() as u32;

    // Checksum TCP header/packet
    let mut i = 0;
    let len = packet.get_length() as usize;
    while i < len && i + 1 < packet.packet().len() {
        let word = (packet.packet()[i] as u32) << 8 | packet.packet()[i + 1] as u32;
        sum = sum + word;
        i = i + 2;
    }
    // If the length is odd, make sure to checksum the final byte
    if len & 1 != 0 && len <= packet.packet().len() {
        sum = sum + (packet.packet()[len - 1] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    return !sum as u16;
}


#[test]
fn tcp_header_ipv6_test() {
    use packet::ip::{IpNextHeaderProtocols};
    use packet::ipv6::{MutableIpv6Packet};

    let mut packet = [0u8; 40 + 8 + 4];
    let next_header = IpNextHeaderProtocols::Tcp;
    let ipv6_source = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    let ipv6_destination = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    {
        let mut ip_header = MutableIpv6Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_header(next_header);
        ip_header.set_source(ipv6_source);
        ip_header.set_destination(ipv6_destination);
    }

    // Set data
    packet[40 + 8 + 0] = 't' as u8;
    packet[40 + 8 + 1] = 'e' as u8;
    packet[40 + 8 + 2] = 's' as u8;
    packet[40 + 8 + 3] = 't' as u8;

    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[40..]).unwrap();
        tcp_header.set_source(12345);
        assert_eq!(tcp_header.get_source(), 12345);

        tcp_header.set_destination(54321);
        assert_eq!(tcp_header.get_destination(), 54321);

        tcp_header.set_length(8 + 4);
        assert_eq!(tcp_header.get_length(), 8 + 4);

        let checksum = ipv6_checksum(&tcp_header.to_immutable(),
                                     ipv6_source,
                                     ipv6_destination,
                                     next_header);
        tcp_header.set_checksum(checksum);
        assert_eq!(tcp_header.get_checksum(), 0x139b);
    }

    let ref_packet = [0x30, 0x39, /* source */
                     0xd4, 0x31, /* destination */
                     0x00, 0x0c, /* length */
                     0x13, 0x9b  /* checksum*/];
    assert_eq!(&ref_packet[..], &packet[40 .. 48]);
}
