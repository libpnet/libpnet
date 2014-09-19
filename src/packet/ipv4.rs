// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! IPv4 packet abstraction

use std::fmt;
use std::io::net::ip::{IpAddr, Ipv4Addr};

use packet::{Packet, MutablePacket};
use packet::ip::IpNextHeaderProtocol;

/// Structure representing an IPv4 header
pub struct Ipv4Header<'p> {
    packet: &'p [u8],
}

// FIXME This should probably be a macro
impl<'p> PartialEq for Ipv4Header<'p> {
    fn eq(&self, other: &Ipv4Header) -> bool {
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
impl<'p> Eq for Ipv4Header<'p> {}

impl<'p> fmt::Show for Ipv4Header<'p> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,
               "Ipv4Header {{ version: {}, header length: {}, dscp: {}, ecn: {}, \
                              total length: {}, identification: {}, flags: {}, \
                              fragment offset: {}, ttl: {}, protocol: {}, checksum: {}, \
                              source: {}, destination: {} }}",
                self.get_version(),
                self.get_header_length(),
                self.get_dscp(),
                self.get_ecn(),
                self.get_total_length(),
                self.get_identification(),
                self.get_flags(),
                self.get_fragment_offset(),
                self.get_ttl(),
                self.get_next_level_protocol(),
                self.get_checksum(),
                self.get_source(),
                self.get_destination()
        )
    }
}

impl<'p> fmt::Show for MutableIpv4Header<'p> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,
               "MutableIpv4Header {{ version: {}, header length: {}, dscp: {}, ecn: {}, \
                              total length: {}, identification: {}, flags: {}, \
                              fragment offset: {}, ttl: {}, protocol: {}, checksum: {}, \
                              source: {}, destination: {} }}",
                self.get_version(),
                self.get_header_length(),
                self.get_dscp(),
                self.get_ecn(),
                self.get_total_length(),
                self.get_identification(),
                self.get_flags(),
                self.get_fragment_offset(),
                self.get_ttl(),
                self.get_next_level_protocol(),
                self.get_checksum(),
                self.get_source(),
                self.get_destination()
        )
    }
}

/// Structure representing a mutable IPv4 header
pub struct MutableIpv4Header<'p> {
    packet: &'p mut [u8],
}

impl<'p> Packet for Ipv4Header<'p> {
    #[inline(always)]
    fn packet<'p>(&'p self) -> &'p [u8] { self.packet }

    #[inline(always)]
    fn payload<'p>(&'p self) -> &'p [u8] { self.packet.slice_from(20) /* FIXME */ }
}

impl<'p> Packet for MutableIpv4Header<'p> {
    #[inline(always)]
    fn packet<'p>(&'p self) -> &'p [u8] { self.packet.as_slice() }

    #[inline(always)]
    fn payload<'p>(&'p self) -> &'p [u8] { self.packet.slice_from(20) /* FIXME */ }
}

impl<'p> MutablePacket for MutableIpv4Header<'p> {
    #[inline(always)]
    fn mut_packet<'p>(&'p mut self) -> &'p mut [u8] { self.packet.as_mut_slice() }

    #[inline(always)]
    fn mut_payload<'p>(&'p mut self) -> &'p mut [u8] { self.packet.slice_from_mut(20) /* FIXME */ }
}

/// Trait implemented by anything which provides an interface to read IPv4
/// packets
pub trait Ipv4Packet : Packet {
    /// Get the version of the IPv4 packet. Should return 4.
    fn get_version(&self) -> u8 {
        self.packet()[0] >> 4
    }

    /// Get the header length field of the packet
    fn get_header_length(&self) -> u8 {
        self.packet()[0] & 0xF
    }

    /// Get the DSCP field of the packet
    fn get_dscp(&self) -> u8 {
        (self.packet()[1] & 0xFC) >> 2
    }

    /// Get the ECN field of the packet
    fn get_ecn(&self) -> u8 {
        self.packet()[1] & 3
    }

    /// Get the total length of the packet
    fn get_total_length(&self) -> u16 {
        let b1 = self.packet()[2] as u16 << 8;
        let b2 = self.packet()[3] as u16;
        b1 | b2
    }

    /// Get the identification field for the packet
    fn get_identification(&self) -> u16 {
        let b1 = self.packet()[4] as u16 << 8;
        let b2 = self.packet()[5] as u16;
        b1 | b2
    }

    /// Get the flags for the packet
    fn get_flags(&self) -> u8 {
        self.packet()[6] >> 5
    }

    /// Get the fragment offset for the packet
    fn get_fragment_offset(&self) -> u16 {
        let b1 = (self.packet()[6] & 0x1F) as u16 << 8;
        let b2 = self.packet()[7] as u16;
        b1 | b2
    }

    /// Get the TTL for the packet
    fn get_ttl(&self) -> u8 {
        self.packet()[8]
    }

    /// Get the next level protocol for the packet
    fn get_next_level_protocol(&self) -> IpNextHeaderProtocol {
        IpNextHeaderProtocol(self.packet()[9])
    }

    /// Get the checksum field for the packet
    fn get_checksum(&self) -> u16 {
        let cs1 = self.packet()[10] as u16 << 8;
        let cs2 = self.packet()[11] as u16;
        cs1 | cs2
    }

    /// Get the source IP address for the packet
    fn get_source(&self) -> IpAddr {
        Ipv4Addr(self.packet()[12],
                 self.packet()[13],
                 self.packet()[14],
                 self.packet()[15])
    }

    /// Get the destination field for the packet
    fn get_destination(&self) -> IpAddr {
        Ipv4Addr(self.packet()[16],
                 self.packet()[17],
                 self.packet()[18],
                 self.packet()[19])
    }

    /// Calculate the checksum for the packet
    fn calculate_checksum(&mut self) -> u16 {
        let len = self.get_header_length() as uint * 4;
        let mut sum = 0u32;
        let mut i = 0;
        while i < len {
            let word = self.packet()[i] as u32 << 8 | self.packet()[i + 1] as u32;
            sum = sum + word;
            i = i + 2;
        }
        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }
        return !sum as u16;
    }
}

impl<'p> Ipv4Packet for Ipv4Header<'p> {}
impl<'p> Ipv4Packet for MutableIpv4Header<'p> {}

impl<'p> Ipv4Header<'p> {
    /// Construct a new IPv4 header backed by the given buffer with
    /// the provided offset
    pub fn new(packet: &'p [u8]) -> Ipv4Header<'p> {
        Ipv4Header { packet: packet }
    }
}
impl<'p> MutableIpv4Header<'p> {
    /// Construct a new mutable IPv4 header backed by the given buffer with
    /// the provided offset
    pub fn new(packet: &'p mut [u8]) -> MutableIpv4Header<'p> {
        MutableIpv4Header { packet: packet }
    }

    /// Set the version field for the packet
    pub fn set_version(&mut self, version: u8) {
        let ver = version << 4;
        self.packet[0] = (self.packet[0] & 0x0F) | ver;
    }

    /// Set the header length field for the packet
    pub fn set_header_length(&mut self, ihl: u8) {
        let len = ihl & 0xF;
        self.packet[0] = (self.packet[0] & 0xF0) | len;
    }

    /// Set the DSCP field for the packet
    pub fn set_dscp(&mut self, dscp: u8) {
        let cp = dscp & 0xFC;
        self.packet[1] = (self.packet[1] & 3) | (cp << 2);
    }

    /// Set the ECN field for the packet
    pub fn set_ecn(&mut self, ecn: u8) {
        let cn = ecn & 3;
        self.packet[1] = (self.packet[1] & 0xFC) | cn;
    }

    /// Set the total length field for the packet
    pub fn set_total_length(&mut self, len: u16) {
        self.packet[2] = (len >> 8) as u8;
        self.packet[3] = (len & 0xFF) as u8;
    }

    /// Set the identification field for the packet
    pub fn set_identification(&mut self, identification: u16) {
        self.packet[4] = (identification >> 8) as u8;
        self.packet[5] = (identification & 0x00FF) as u8;
    }

    /// Set the flags field for the packet
    pub fn set_flags(&mut self, flags: u8) {
        let fs = (flags & 7) << 5;
        self.packet[6] = (self.packet[6] & 0x1F) | fs;
    }

    /// Set the fragment offset field for the packet
    pub fn set_fragment_offset(&mut self, offset: u16) {
        let fo = offset & 0x1FFF;
        self.packet[6] = (self.packet[6] & 0xE0) | ((fo & 0xFF00) >> 8) as u8;
        self.packet[7] = (fo & 0xFF) as u8;
    }

    /// Set the TTL field for the packet
    pub fn set_ttl(&mut self, ttl: u8) {
        self.packet[8] = ttl;
    }

    /// Set the next level protocol field for the packet
    pub fn set_next_level_protocol(&mut self,
                                   IpNextHeaderProtocol(protocol): IpNextHeaderProtocol) {
        self.packet[9] = protocol;
    }

    /// Set the checksum field for the packet
    pub fn set_checksum(&mut self, checksum: u16) {
        let cs1 = ((checksum & 0xFF00) >> 8) as u8;
        let cs2 = (checksum & 0x00FF) as u8;
        self.packet[10] = cs1;
        self.packet[11] = cs2;
    }

    /// Set the source address for the packet
    pub fn set_source(&mut self, ip: IpAddr) {
        match ip {
            Ipv4Addr(a, b, c, d) => {
                self.packet[12] = a;
                self.packet[13] = b;
                self.packet[14] = c;
                self.packet[15] = d;
            },
            _ => ()
        }
    }

    /// Set the destination field for the packet
    pub fn set_destination(&mut self, ip: IpAddr) {
        match ip {
            Ipv4Addr(a, b, c, d) => {
                self.packet[16] = a;
                self.packet[17] = b;
                self.packet[18] = c;
                self.packet[19] = d;
            },
            _ => ()
        }
    }

    /// Calculate the checksum of the packet and then set the field to the value
    /// calculated
    pub fn checksum(&mut self) {
        let checksum = self.calculate_checksum();
        self.set_checksum(checksum);
    }
}

#[test]
fn ipv4_header_test() {
    use packet::ip::IpNextHeaderProtocols;

    let mut packet = [0u8, ..20];
    {
        let mut ip_header = MutableIpv4Header::new(packet.as_mut_slice());
        ip_header.set_version(4);
        assert_eq!(ip_header.get_version(), 4);

        ip_header.set_header_length(5);
        assert_eq!(ip_header.get_header_length(), 5);

        ip_header.set_dscp(4);
        assert_eq!(ip_header.get_dscp(), 4);

        ip_header.set_ecn(1);
        assert_eq!(ip_header.get_ecn(), 1);

        ip_header.set_total_length(115);
        assert_eq!(ip_header.get_total_length(), 115);

        ip_header.set_identification(257);
        assert_eq!(ip_header.get_identification(), 257);

        ip_header.set_flags(2);
        assert_eq!(ip_header.get_flags(), 2);

        ip_header.set_fragment_offset(257);
        assert_eq!(ip_header.get_fragment_offset(), 257);

        ip_header.set_ttl(64);
        assert_eq!(ip_header.get_ttl(), 64);

        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        assert_eq!(ip_header.get_next_level_protocol(), IpNextHeaderProtocols::Udp);

        ip_header.set_source(Ipv4Addr(192, 168, 0, 1));
        assert_eq!(ip_header.get_source(), Ipv4Addr(192, 168, 0, 1));

        ip_header.set_destination(Ipv4Addr(192, 168, 0, 199));
        assert_eq!(ip_header.get_destination(), Ipv4Addr(192, 168, 0, 199));

        ip_header.checksum();
        assert_eq!(ip_header.get_checksum(), 0xb64e);
    }

    let ref_packet = [0x45,           /* ver/ihl */
                     0x11,           /* dscp/ecn */
                     0x00, 0x73,     /* total len */
                     0x01, 0x01,     /* identification */
                     0x41, 0x01,     /* flags/frag offset */
                     0x40,           /* ttl */
                     0x11,           /* proto */
                     0xb6, 0x4e,     /* checksum */
                     0xc0, 0xa8, 0x00, 0x01, /* source ip */
                     0xc0, 0xa8, 0x00, 0xc7  /* dest ip */];
    assert_eq!(ref_packet.as_slice(), packet.as_slice());
}

