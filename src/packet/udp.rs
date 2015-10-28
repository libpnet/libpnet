// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! UDP packet abstraction

use packet::Packet;
use packet::ip::IpNextHeaderProtocol;

use pnet_macros::types::*;

use std::net::{Ipv4Addr, Ipv6Addr};

/// Represents an UDP Packet
#[packet]
pub struct Udp {
    source: u16be,
    destination: u16be,
    length: u16be,
    checksum: u16be,
    #[payload]
    payload: Vec<u8>
}

/// Calculate the checksum for a packet built on IPv4
pub fn ipv4_checksum(packet: &UdpPacket,
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
            sum += (a as u32) << 8 | b as u32;
            sum += (c as u32) << 8 | d as u32;
        }
    }

    // IPv4 destination
    match ipv4_destination.octets() {
        [a, b, c, d] => {
            sum += (a as u32) << 8 | b as u32;
            sum += (c as u32) << 8 | d as u32;
        }
    }

    // IPv4 Next level protocol
    sum += next_level_protocol as u32;

    // UDP Length
    sum += (packet.packet()[4] as u32) << 8 | packet.packet()[5] as u32;

    // Checksum UDP header/packet
    let mut i = 0;
    let len = packet.get_length() as usize;
    while i < len && i + 1 < packet.packet().len() {
        sum += (packet.packet()[i] as u32) << 8 | packet.packet()[i + 1] as u32;
        i += 2;
    }
    // If the length is odd, make sure to checksum the final byte
    if len & 1 != 0 && len <= packet.packet().len() {
        sum += (packet.packet()[len - 1] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    !sum as u16
}

#[test]
fn udp_header_ipv4_test() {
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::MutableIpv4Packet;

    let mut packet = [0u8; 20 + 8 + 4];
    let ipv4_source = Ipv4Addr::new(192, 168, 0, 1);
    let ipv4_destination = Ipv4Addr::new(192, 168, 0, 199);
    let next_level_protocol = IpNextHeaderProtocols::Udp;
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(next_level_protocol);
        ip_header.set_source(ipv4_source);
        ip_header.set_destination(ipv4_destination);
    }

    // Set data
    packet[20 + 8    ] = 't' as u8;
    packet[20 + 8 + 1] = 'e' as u8;
    packet[20 + 8 + 2] = 's' as u8;
    packet[20 + 8 + 3] = 't' as u8;

    {
        let mut udp_header = MutableUdpPacket::new(&mut packet[20..]).unwrap();
        udp_header.set_source(12345);
        assert_eq!(udp_header.get_source(), 12345);

        udp_header.set_destination(54321);
        assert_eq!(udp_header.get_destination(), 54321);

        udp_header.set_length(8 + 4);
        assert_eq!(udp_header.get_length(), 8 + 4);

        let checksum = ipv4_checksum(&udp_header.to_immutable(),
                                     ipv4_source,
                                     ipv4_destination,
                                     next_level_protocol);
        udp_header.set_checksum(checksum);
        assert_eq!(udp_header.get_checksum(), 0x9178);
    }

    let ref_packet = [0x30, 0x39, /* source */
                     0xd4, 0x31, /* destination */
                     0x00, 0x0c, /* length */
                     0x91, 0x78  /* checksum*/];
    assert_eq!(&ref_packet[..], &packet[20 .. 28]);
}


/// Calculate the checksum for a packet built on IPv6
pub fn ipv6_checksum(packet: &UdpPacket,
                     ipv6_source: Ipv6Addr,
                     ipv6_destination: Ipv6Addr,
                     next_header: IpNextHeaderProtocol) -> u16be {
    let IpNextHeaderProtocol(next_header) = next_header;
    let mut sum = 0u32;

    // Checksum pseudo-header
    // IPv6 source
    match ipv6_source.segments() {
        [a, b, c, d, e, f, g, h] => {
            sum += a as u32;
            sum += b as u32;
            sum += c as u32;
            sum += d as u32;
            sum += e as u32;
            sum += f as u32;
            sum += g as u32;
            sum += h as u32;
        }
    }

    // IPv6 destination
    match ipv6_destination.segments() {
        [a, b, c, d, e, f, g, h] => {
            sum += a as u32;
            sum += b as u32;
            sum += c as u32;
            sum += d as u32;
            sum += e as u32;
            sum += f as u32;
            sum += g as u32;
            sum += h as u32;
        }
    }

    // IPv6 Next header
    sum += next_header as u32;

    // UDP Length
    sum += packet.get_length() as u32;

    // Checksum UDP header/packet
    let mut i = 0;
    let len = packet.get_length() as usize;
    while i < len && i + 1 < packet.packet().len() {
        sum += (packet.packet()[i] as u32) << 8 | packet.packet()[i + 1] as u32;
        i += 2;
    }
    // If the length is odd, make sure to checksum the final byte
    if len & 1 != 0 && len <= packet.packet().len() {
        sum += (packet.packet()[len - 1] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }

    !sum as u16
}

#[test]
fn udp_header_ipv6_test() {
    use packet::ip::IpNextHeaderProtocols;
    use packet::ipv6::MutableIpv6Packet;

    let mut packet = [0u8; 40 + 8 + 4];
    let next_header = IpNextHeaderProtocols::Udp;
    let ipv6_source = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    let ipv6_destination = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    {
        let mut ip_header = MutableIpv6Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_header(next_header);
        ip_header.set_source(ipv6_source);
        ip_header.set_destination(ipv6_destination);
    }

    // Set data
    packet[40 + 8    ] = 't' as u8;
    packet[40 + 8 + 1] = 'e' as u8;
    packet[40 + 8 + 2] = 's' as u8;
    packet[40 + 8 + 3] = 't' as u8;

    {
        let mut udp_header = MutableUdpPacket::new(&mut packet[40..]).unwrap();
        udp_header.set_source(12345);
        assert_eq!(udp_header.get_source(), 12345);

        udp_header.set_destination(54321);
        assert_eq!(udp_header.get_destination(), 54321);

        udp_header.set_length(8 + 4);
        assert_eq!(udp_header.get_length(), 8 + 4);

        let checksum = ipv6_checksum(&udp_header.to_immutable(),
                                     ipv6_source,
                                     ipv6_destination,
                                     next_header);
        udp_header.set_checksum(checksum);
        assert_eq!(udp_header.get_checksum(), 0x1390);
    }

    let ref_packet = [0x30, 0x39, /* source */
                     0xd4, 0x31, /* destination */
                     0x00, 0x0c, /* length */
                     0x13, 0x90  /* checksum*/];
    assert_eq!(&ref_packet[..], &packet[40 .. 48]);
}

