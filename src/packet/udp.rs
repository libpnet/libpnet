// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! UDP packet abstraction

use std::fmt;
use std::io::net::ip::{IpAddr, Ipv4Addr, Ipv6Addr};

use packet::{Packet, MutablePacket};
use packet::ip::{IpNextHeaderProtocol};

/// Structure representing a UDP header
pub struct UdpHeader<'p> {
    packet: &'p [u8],
}
impl<'p> Copy for UdpHeader<'p> {}

impl<'p> PartialEq for UdpHeader<'p> {
    fn eq(&self, other: &UdpHeader) -> bool {
        if self.packet.len() != other.packet.len() {
            return false;
        }
        for (b1, b2) in self.packet.iter().zip(other.packet.iter()) {
            if b1 != b2 {
                return false;
            }
        }
        return true;
    }
}
impl<'p> Eq for UdpHeader<'p> {}

impl<'p> fmt::Debug for UdpHeader<'p> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,
               "UdpHeader {{ source: {}, destination: {}, length: {}, checksum: {} }}",
                self.get_source(),
                self.get_destination(),
                self.get_length(),
                self.get_checksum()
        )
    }
}

impl<'p> fmt::Debug for MutableUdpHeader<'p> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,
               "MutableUdpHeader {{ source: {}, destination: {}, length: {}, checksum: {} }}",
                self.get_source(),
                self.get_destination(),
                self.get_length(),
                self.get_checksum()
        )
    }
}

/// Structure representing a mutable UDP header
pub struct MutableUdpHeader<'p> {
    packet: &'p mut [u8],
}

impl<'a> Packet for UdpHeader<'a> {
    #[inline(always)]
    fn packet<'p>(&'p self) -> &'p [u8] { self.packet }

    #[inline(always)]
    fn payload<'p>(&'p self) -> &'p [u8] { &self.packet[8..] }
}

impl<'a> Packet for MutableUdpHeader<'a> {
    #[inline(always)]
    fn packet<'p>(&'p self) -> &'p [u8] { self.packet.as_slice() }

    #[inline(always)]
    fn payload<'p>(&'p self) -> &'p [u8] { &self.packet[8..] }
}

impl<'a> MutablePacket for MutableUdpHeader<'a> {
    #[inline(always)]
    fn packet_mut<'p>(&'p mut self) -> &'p mut [u8] { self.packet.as_mut_slice() }

    #[inline(always)]
    fn payload_mut<'p>(&'p mut self) -> &'p mut [u8] { &mut self.packet[8..] }
}

/// Trait implemented by anything which provides an interface to read UDP
/// packets
pub trait UdpPacket : Packet {
    /// Get the source port for the packet
    fn get_source(&self) -> u16 {
        let s1 = (self.packet()[0] as u16) << 8;
        let s2 = self.packet()[1] as u16;
        s1 | s2
    }

    /// Get the destination port for the packet
    fn get_destination(&self) -> u16 {
        let d1 = (self.packet()[2] as u16) << 8;
        let d2 = self.packet()[3] as u16;
        d1 | d2
    }

    /// Get the length field for the packet
    fn get_length(&self) -> u16 {
        let l1 = (self.packet()[4] as u16) << 8;
        let l2 = self.packet()[5] as u16;
        l1 | l2
    }

    /// Get the checksum field for the packet
    fn get_checksum(&self) -> u16 {
        let c1 = (self.packet()[6] as u16) << 8;
        let c2 = self.packet()[7] as u16;
        c1 | c2
    }

    /// Calculate the checksum for a packet built on IPv4
    fn calculate_ipv4_checksum(&self,
                               ipv4_source: IpAddr,
                               ipv4_destination: IpAddr,
                               next_level_protocol: IpNextHeaderProtocol)
        -> u16 {
        let IpNextHeaderProtocol(next_level_protocol) = next_level_protocol;
        let mut sum = 0u32;

        // Checksum pseudo-header
        // IPv4 source
        match ipv4_source {
            Ipv4Addr(a, b, c, d) => {
                sum = sum + ((a as u32) << 8 | b as u32);
                sum = sum + ((c as u32) << 8 | d as u32);
            },
            _ => ()
        }

        // IPv4 destination
        match ipv4_destination {
            Ipv4Addr(a, b, c, d) => {
                sum = sum + ((a as u32) << 8 | b as u32);
                sum = sum + ((c as u32) << 8 | d as u32);
            },
            _ => ()
        }

        // IPv4 Next level protocol
        sum = sum + next_level_protocol as u32;

        // UDP Length
        sum = sum + ((self.packet()[4] as u32) << 8 |
                      self.packet()[5] as u32);

        // Checksum UDP header/packet
        let mut i = 0;
        let len = self.get_length() as usize;
        while i < len && i + 1 < self.packet().len() {
            let word = (self.packet()[i] as u32) << 8 | self.packet()[i + 1] as u32;
            sum = sum + word;
            i = i + 2;
        }
        // If the length is odd, make sure to checksum the final byte
        if len & 1 != 0 && len <= self.packet().len() {
            sum = sum + ((self.packet()[len - 1] as u32) << 8);
        }
        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        return !sum as u16;
    }

    /// Calculate the checksum for a packet built on IPv6
    fn calculate_ipv6_checksum(&self, ipv6_source: IpAddr, ipv6_destination: IpAddr,
                               next_header: IpNextHeaderProtocol) -> u16 {
        let IpNextHeaderProtocol(next_header) = next_header;
        let mut sum = 0u32;

        // Checksum pseudo-header
        // IPv6 source
        match ipv6_source {
            Ipv6Addr(a, b, c, d, e, f, g, h) => {
                sum = sum + a as u32;
                sum = sum + b as u32;
                sum = sum + c as u32;
                sum = sum + d as u32;
                sum = sum + e as u32;
                sum = sum + f as u32;
                sum = sum + g as u32;
                sum = sum + h as u32;
            },
            _ => ()
        }

        // IPv6 destination
        match ipv6_destination {
            Ipv6Addr(a, b, c, d, e, f, g, h) => {
                sum = sum + a as u32;
                sum = sum + b as u32;
                sum = sum + c as u32;
                sum = sum + d as u32;
                sum = sum + e as u32;
                sum = sum + f as u32;
                sum = sum + g as u32;
                sum = sum + h as u32;
            },
            _ => ()
        }

        // IPv6 Next header
        sum = sum + next_header as u32;

        // UDP Length
        sum = sum + self.get_length() as u32;

        // Checksum UDP header/packet
        let mut i = 0;
        let len = self.get_length() as usize;
        while i < len && i + 1 < self.packet().len() {
            let word = (self.packet()[i] as u32) << 8 | self.packet()[i + 1] as u32;
            sum = sum + word;
            i = i + 2;
        }
        // If the length is odd, make sure to checksum the final byte
        if len & 1 != 0 && len <= self.packet().len() {
            sum = sum + (self.packet()[len - 1] as u32) << 8;
        }

        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }

        return !sum as u16;
    }

    /// Calculate a checksum regardless of IP version
    fn calculate_checksum(&self, source: IpAddr, destination: IpAddr,
                          next_header: IpNextHeaderProtocol)
        -> u16 {
        match source {
            Ipv4Addr(..) => self.calculate_ipv4_checksum(source, destination, next_header),
            Ipv6Addr(..) => self.calculate_ipv6_checksum(source, destination, next_header),
        }
    }

}

impl<'p> UdpPacket for UdpHeader<'p> {}
impl<'p> UdpPacket for MutableUdpHeader<'p> {}

impl<'p> UdpHeader<'p> {
    /// Construct a new UDP header backed by the given buffer with
    /// the provided offset
    pub fn new(packet: &'p [u8]) -> UdpHeader<'p> {
        UdpHeader { packet: packet }
    }
}

impl<'p> MutableUdpHeader<'p> {
    /// Construct a new mutable UDP header backed by the given buffer with
    /// the provided offset
    pub fn new(packet: &'p mut [u8]) -> MutableUdpHeader<'p> {
        MutableUdpHeader { packet: packet }
    }

    /// Set the source port for the packet
    pub fn set_source(&mut self, port: u16) {
        self.packet[0] = (port >> 8) as u8;
        self.packet[1] = (port & 0xFF) as u8;
    }

    /// Set the destination port for the packet
    pub fn set_destination(&mut self, port: u16) {
        self.packet[2] = (port >> 8) as u8;
        self.packet[3] = (port & 0xFF) as u8;
    }

    /// Set the length field for the packet
    pub fn set_length(&mut self, len: u16) {
        self.packet[4] = (len >> 8) as u8;
        self.packet[5] = (len & 0xFF) as u8;
    }

    /// Set the checksum field for the packet
    pub fn set_checksum(&mut self, checksum: u16) {
        self.packet[6] = (checksum >> 8) as u8;
        self.packet[7] = (checksum & 0xFF) as u8;
    }

    /// Calculate a checksum for the packet, then set the field
    pub fn checksum(&mut self, source: IpAddr, destination: IpAddr,
                               next_header: IpNextHeaderProtocol) {
        let checksum = self.calculate_checksum(source, destination, next_header);

        // RFC 768, a checksum of zero is transmitted as all ones
        if checksum != 0 {
            self.set_checksum(checksum);
        } else {
            self.set_checksum(0xFFFF);
        }
    }
}

#[test]
fn udp_header_ipv4_test() {
    use packet::ip::{IpNextHeaderProtocols};
    use packet::ipv4::{MutableIpv4Header, Ipv4Packet};

    let mut packet = [0u8; 20 + 8 + 4];
    let ipv4_source = Ipv4Addr(192, 168, 0, 1);
    let ipv4_destination = Ipv4Addr(192, 168, 0, 199);
    let next_level_protocol = IpNextHeaderProtocols::Udp;
    {
        let mut ip_header = MutableIpv4Header::new(packet.as_mut_slice());
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
        let mut udp_header = MutableUdpHeader::new(&mut packet.as_mut_slice()[20..]);
        udp_header.set_source(12345);
        assert_eq!(udp_header.get_source(), 12345);

        udp_header.set_destination(54321);
        assert_eq!(udp_header.get_destination(), 54321);

        udp_header.set_length(8 + 4);
        assert_eq!(udp_header.get_length(), 8 + 4);

        udp_header.checksum(ipv4_source, ipv4_destination, next_level_protocol);
        assert_eq!(udp_header.get_checksum(), 0x9178);
    }

    let ref_packet = [0x30, 0x39, /* source */
                     0xd4, 0x31, /* destination */
                     0x00, 0x0c, /* length */
                     0x91, 0x78  /* checksum*/];
    assert_eq!(ref_packet.as_slice(), &packet[20 .. 28]);
}

#[test]
fn udp_header_ipv6_test() {
    use packet::ip::{IpNextHeaderProtocols};
    use packet::ipv6::{MutableIpv6Header, Ipv6Packet};

    let mut packet = [0u8; 40 + 8 + 4];
    let next_header = IpNextHeaderProtocols::Udp;
    let ipv6_source = Ipv6Addr(0, 0, 0, 0, 0, 0, 0, 1);
    let ipv6_destination = Ipv6Addr(0, 0, 0, 0, 0, 0, 0, 1);
    {
        let mut ip_header = MutableIpv6Header::new(packet.as_mut_slice());
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
        let mut udp_header = MutableUdpHeader::new(&mut packet.as_mut_slice()[40..]);
        udp_header.set_source(12345);
        assert_eq!(udp_header.get_source(), 12345);

        udp_header.set_destination(54321);
        assert_eq!(udp_header.get_destination(), 54321);

        udp_header.set_length(8 + 4);
        assert_eq!(udp_header.get_length(), 8 + 4);

        udp_header.checksum(ipv6_source, ipv6_destination, next_header);
        assert_eq!(udp_header.get_checksum(), 0x1390);
    }

    let ref_packet = [0x30, 0x39, /* source */
                     0xd4, 0x31, /* destination */
                     0x00, 0x0c, /* length */
                     0x13, 0x90  /* checksum*/];
    assert_eq!(ref_packet.as_slice(), &packet[40 .. 48]);
}

