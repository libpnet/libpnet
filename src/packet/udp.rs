// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! UDP packet abstraction

use packet::{Packet, PseudoHeader};
use pnet_macros_support::types::*;
use util::rfc1071_checksum;


/// Represents an UDP Packet
#[packet]
pub struct Udp {
    source: u16be,
    destination: u16be,
    length: u16be,
    checksum: u16be,
    #[payload]
    payload: Vec<u8>,
}

fn checksum<T: PseudoHeader>(udp_packet: &UdpPacket, ip_packet: &T) -> u16 {
    let pseudo_header = ip_packet.get_pseudo_header(Some(udp_packet.get_length() as u32));
    rfc1071_checksum(udp_packet.packet(), Some(&pseudo_header[..]))
}

#[test]
fn udp_header_ipv4_test() {
    // use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use std::net::Ipv4Addr;

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
    packet[20 + 8] = 't' as u8;
    packet[20 + 8 + 1] = 'e' as u8;
    packet[20 + 8 + 2] = 's' as u8;
    packet[20 + 8 + 3] = 't' as u8;

    {
        let (raw_ip_header, raw_udp_packet) = packet.split_at_mut(20);
        let mut udp_header = MutableUdpPacket::new(&mut raw_udp_packet[..]).unwrap();
        udp_header.set_source(12345);
        assert_eq!(udp_header.get_source(), 12345);

        udp_header.set_destination(54321);
        assert_eq!(udp_header.get_destination(), 54321);

        udp_header.set_length(8 + 4);
        assert_eq!(udp_header.get_length(), 8 + 4);

        let ip_header = Ipv4Packet::new(&raw_ip_header[..]).unwrap();
        let csum = checksum(&udp_header.to_immutable(), &ip_header);
        udp_header.set_checksum(csum);

        assert_eq!(udp_header.get_checksum(), 0x9178);
    }

    let ref_packet = [0x30, 0x39, /* source */
                      0xd4, 0x31, /* destination */
                      0x00, 0x0c, /* length */
                      0x91, 0x78  /* checksum */];
    assert_eq!(&ref_packet[..], &packet[20..28]);
}

#[test]
fn udp_header_ipv6_test() {
    use packet::ip::IpNextHeaderProtocols;
    use packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
    use std::net::Ipv6Addr;

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
    packet[40 + 8] = 't' as u8;
    packet[40 + 8 + 1] = 'e' as u8;
    packet[40 + 8 + 2] = 's' as u8;
    packet[40 + 8 + 3] = 't' as u8;

    {
        let (raw_ip_header, raw_udp_packet) = packet.split_at_mut(40);
        let mut udp_header = MutableUdpPacket::new(&mut raw_udp_packet[..]).unwrap();
        udp_header.set_source(12345);
        assert_eq!(udp_header.get_source(), 12345);

        udp_header.set_destination(54321);
        assert_eq!(udp_header.get_destination(), 54321);

        udp_header.set_length(8 + 4);
        assert_eq!(udp_header.get_length(), 8 + 4);

        let ip_header = Ipv6Packet::new(&raw_ip_header[..]).unwrap();
        let csum = checksum(&udp_header.to_immutable(), &ip_header);
        udp_header.set_checksum(csum);
        assert_eq!(udp_header.get_checksum(), 0x1390);
    }

    let ref_packet = [0x30, 0x39, /* source */
                      0xd4, 0x31, /* destination */
                      0x00, 0x0c, /* length */
                      0x13, 0x90  /* checksum */];
    assert_eq!(&ref_packet[..], &packet[40..48]);
}
