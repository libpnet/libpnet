// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A UDP packet abstraction.

use crate::Packet;
use crate::ip::IpNextHeaderProtocols;

use pnet_macros::packet;
use pnet_macros_support::types::*;

use std::net::{Ipv4Addr, Ipv6Addr};
use crate::util;

/// Represents a UDP Packet.
#[packet]
pub struct Udp {
    pub source: u16be,
    pub destination: u16be,
    pub length: u16be,
    pub checksum: u16be,
    #[payload]
    pub payload: Vec<u8>,
}

/// Calculate a checksum for a packet built on IPv4.
pub fn ipv4_checksum(packet: &UdpPacket, source: &Ipv4Addr, destination: &Ipv4Addr) -> u16be {
    ipv4_checksum_adv(packet, &[], source, destination)
}

/// Calculate a checksum for a packet built on IPv4. Advanced version which
/// accepts an extra slice of data that will be included in the checksum
/// as being part of the data portion of the packet.
///
/// If `packet` contains an odd number of bytes the last byte will not be
/// counted as the first byte of a word together with the first byte of
/// `extra_data`.
pub fn ipv4_checksum_adv(packet: &UdpPacket,
                         extra_data: &[u8],
                         source: &Ipv4Addr,
                         destination: &Ipv4Addr)
    -> u16be {
    util::ipv4_checksum(packet.packet(),
                        3,
                        extra_data,
                        source,
                        destination,
                        IpNextHeaderProtocols::Udp)
}

#[test]
fn udp_header_ipv4_test() {
    use crate::ip::IpNextHeaderProtocols;
    use crate::ipv4::MutableIpv4Packet;

    let mut packet = [0u8; 20 + 8 + 4];
    let ipv4_source = Ipv4Addr::new(192, 168, 0, 1);
    let ipv4_destination = Ipv4Addr::new(192, 168, 0, 199);
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip_header.set_source(ipv4_source);
        ip_header.set_destination(ipv4_destination);
    }

    // Set data
    packet[20 + 8] = 't' as u8;
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

        let checksum = ipv4_checksum(&udp_header.to_immutable(), &ipv4_source, &ipv4_destination);
        udp_header.set_checksum(checksum);
        assert_eq!(udp_header.get_checksum(), 0x9178);
    }

    let ref_packet = [0x30, 0x39, /* source */
                      0xd4, 0x31, /* destination */
                      0x00, 0x0c, /* length */
                      0x91, 0x78  /* checksum */];
    assert_eq!(&ref_packet[..], &packet[20..28]);
}


/// Calculate a checksum for a packet built on IPv6.
pub fn ipv6_checksum(packet: &UdpPacket, source: &Ipv6Addr, destination: &Ipv6Addr) -> u16be {
    ipv6_checksum_adv(packet, &[], source, destination)
}

/// Calculate the checksum for a packet built on IPv6. Advanced version which
/// accepts an extra slice of data that will be included in the checksum
/// as being part of the data portion of the packet.
///
/// If `packet` contains an odd number of bytes the last byte will not be
/// counted as the first byte of a word together with the first byte of
/// `extra_data`.
pub fn ipv6_checksum_adv(packet: &UdpPacket,
                         extra_data: &[u8],
                         source: &Ipv6Addr,
                         destination: &Ipv6Addr)
    -> u16be {
    util::ipv6_checksum(packet.packet(),
                        3,
                        extra_data,
                        source,
                        destination,
                        IpNextHeaderProtocols::Udp)
}

#[test]
fn udp_header_ipv6_test() {
    use crate::ip::IpNextHeaderProtocols;
    use crate::ipv6::MutableIpv6Packet;

    let mut packet = [0u8; 40 + 8 + 4];
    let ipv6_source = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    let ipv6_destination = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    {
        let mut ip_header = MutableIpv6Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_header(IpNextHeaderProtocols::Udp);
        ip_header.set_source(ipv6_source);
        ip_header.set_destination(ipv6_destination);
    }

    // Set data
    packet[40 + 8] = 't' as u8;
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

        let checksum = ipv6_checksum(&udp_header.to_immutable(), &ipv6_source, &ipv6_destination);
        udp_header.set_checksum(checksum);
        assert_eq!(udp_header.get_checksum(), 0x1390);
    }

    let ref_packet = [0x30, 0x39, /* source */
                      0xd4, 0x31, /* destination */
                      0x00, 0x0c, /* length */
                      0x13, 0x90  /* checksum */];
    assert_eq!(&ref_packet[..], &packet[40..48]);
}
