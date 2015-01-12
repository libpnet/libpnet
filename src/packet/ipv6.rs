// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! IPv6 packet abstraction

use std::fmt;
use std::io::net::ip::{IpAddr, Ipv6Addr};

use packet::{Packet, MutablePacket};
use packet::ip::IpNextHeaderProtocol;

/// Structure representing an IPv6 header
pub struct Ipv6Header<'p> {
    packet: &'p [u8],
}
impl<'p> Copy for Ipv6Header<'p> {}

/// Structure representing a mutable IPv6 header
pub struct MutableIpv6Header<'p> {
    packet: &'p mut [u8],
}

impl<'p> fmt::Show for Ipv6Header<'p> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,
               "Ipv6Header {{ version: {}, traffic class: {}, flow label: {}, \
                              payload length: {}, next header: {:?}, hop limit: {}, source: {}, \
                              destination: {} }}",
                self.get_version(),
                self.get_traffic_class(),
                self.get_flow_label(),
                self.get_payload_length(),
                self.get_next_header(),
                self.get_hop_limit(),
                self.get_source(),
                self.get_destination()
        )
    }
}

impl<'p> fmt::Show for MutableIpv6Header<'p> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,
               "MutableIpv6Header {{ version: {}, traffic class: {}, flow label: {}, \
                              payload length: {}, next header: {:?}, hop limit: {}, source: {}, \
                              destination: {} }}",
                self.get_version(),
                self.get_traffic_class(),
                self.get_flow_label(),
                self.get_payload_length(),
                self.get_next_header(),
                self.get_hop_limit(),
                self.get_source(),
                self.get_destination()
        )
    }
}

impl<'a> Packet for Ipv6Header<'a> {
    #[inline(always)]
    fn packet<'p>(&'p self) -> &'p [u8] { self.packet }

    #[inline(always)]
    fn payload<'p>(&'p self) -> &'p [u8] { self.packet.slice_from(40) }
}

impl<'a> Packet for MutableIpv6Header<'a> {
    #[inline(always)]
    fn packet<'p>(&'p self) -> &'p [u8] { self.packet.as_slice() }

    #[inline(always)]
    fn payload<'p>(&'p self) -> &'p [u8] { self.packet.slice_from(40) }
}

impl<'a> MutablePacket for MutableIpv6Header<'a> {
    #[inline(always)]
    fn packet_mut<'p>(&'p mut self) -> &'p mut [u8] { self.packet.as_mut_slice() }

    #[inline(always)]
    fn payload_mut<'p>(&'p mut self) -> &'p mut [u8] { self.packet.slice_from_mut(40) }
}

/// Trait implemented by anything which provides an interface to read IPv6
/// packets
pub trait Ipv6Packet : Packet {
    /// Get the version field for the packet. Should usually be 6.
    fn get_version(&self) -> u8 {
        self.packet()[0] >> 4
    }

    /// Get the traffic class field for the packet
    fn get_traffic_class(&self) -> u8 {
        let tc1 = (self.packet()[0] & 0x0F) << 4;
        let tc2 = self.packet()[1] >> 4;
        tc1 | tc2
    }

    /// Get the flow label field for the packet
    fn get_flow_label(&self) -> u32 {
        let fl1 = (self.packet()[1] as u32 & 0xF) << 16;
        let fl2 = (self.packet()[2] as u32) << 8;
        let fl3 =  self.packet()[3] as u32;
        fl1 | fl2 | fl3
    }

    /// Get the payload length field for the packet
    fn get_payload_length(&self) -> u16 {
        let len1 = (self.packet()[4] as u16) << 8;
        let len2 = self.packet()[5] as u16;
        len1 | len2
    }

    /// Get the next header field for the packet
    fn get_next_header(&self) -> IpNextHeaderProtocol {
        IpNextHeaderProtocol(self.packet()[6])
    }

    /// Get the hop limit field for the packet
    fn get_hop_limit(&self) -> u8 {
        self.packet()[7]
    }

    /// Get the source IP address for the packet
    fn get_source(&self) -> IpAddr {
        let packet = self.packet();

        let a = ((packet[ 8] as u16) << 8) | packet[ 9] as u16;
        let b = ((packet[10] as u16) << 8) | packet[11] as u16;
        let c = ((packet[12] as u16) << 8) | packet[13] as u16;
        let d = ((packet[14] as u16) << 8) | packet[15] as u16;
        let e = ((packet[16] as u16) << 8) | packet[17] as u16;
        let f = ((packet[18] as u16) << 8) | packet[19] as u16;
        let g = ((packet[20] as u16) << 8) | packet[21] as u16;
        let h = ((packet[22] as u16) << 8) | packet[23] as u16;

        Ipv6Addr(a, b, c, d, e, f, g, h)
    }

    /// Get the destination IP address for the packet
    fn get_destination(&self) -> IpAddr {
        let packet = self.packet();

        let a = ((packet[24] as u16) << 8) | packet[25] as u16;
        let b = ((packet[26] as u16) << 8) | packet[27] as u16;
        let c = ((packet[28] as u16) << 8) | packet[29] as u16;
        let d = ((packet[30] as u16) << 8) | packet[31] as u16;
        let e = ((packet[32] as u16) << 8) | packet[33] as u16;
        let f = ((packet[34] as u16) << 8) | packet[35] as u16;
        let g = ((packet[36] as u16) << 8) | packet[37] as u16;
        let h = ((packet[38] as u16) << 8) | packet[39] as u16;

        Ipv6Addr(a, b, c, d, e, f, g, h)
    }
}

impl<'p> Ipv6Packet for Ipv6Header<'p> {}
impl<'p> Ipv6Packet for MutableIpv6Header<'p> {}

impl<'p> Ipv6Header<'p> {
    /// Construct a new IPv6 header backed by the given buffer with
    /// the provided offset
    pub fn new(packet: &'p [u8]) -> Ipv6Header<'p> {
        Ipv6Header { packet: packet }
    }
}

impl<'p> MutableIpv6Header<'p> {
    /// Construct a new mutable IPv6 header backed by the given buffer with
    /// the provided offset
    pub fn new(packet: &'p mut [u8]) -> MutableIpv6Header<'p> {
        MutableIpv6Header { packet: packet }
    }

    /// Set the version field for the packet
    pub fn set_version(&mut self, version: u8) {
        let ver = version << 4;
        self.packet[0] = (self.packet[0] & 0x0F) | ver;
    }

    /// Set the traffic class field for the packet
    pub fn set_traffic_class(&mut self, tc: u8) {
        self.packet[0] = (self.packet[0] & 0xF0) | (tc >> 4);
        self.packet[1] = ((tc & 0x0F) << 4) | ((self.packet[1] & 0xF0) >> 4);
    }

    /// Set the flow label field for the packet
    pub fn set_flow_label(&mut self, label: u32) {
        let lbl = ((label & 0xF0000) >> 16) as u8;
        self.packet[1] = (self.packet[1] & 0xF0) | lbl;
        self.packet[2] = ((label & 0xFF00) >> 8) as u8;
        self.packet[3] = (label & 0x00FF) as u8;
    }

    /// Set the payload length field for the packet
    pub fn set_payload_length(&mut self, len: u16) {
        self.packet[4] = (len >> 8) as u8;
        self.packet[5] = (len & 0xFF) as u8;
    }

    /// Set the next header field for the packet
    pub fn set_next_header(&mut self, IpNextHeaderProtocol(protocol): IpNextHeaderProtocol) {
        self.packet[6] = protocol;
    }

    /// Set the hop limit field for the packet
    pub fn set_hop_limit(&mut self, limit: u8) {
        self.packet[7] = limit;
    }

    /// Set the source IP address for the packet
    pub fn set_source(&mut self, ip: IpAddr) {
        match ip {
            Ipv6Addr(a, b, c, d, e, f, g, h) => {
                self.packet[ 8] = (a >> 8) as u8;
                self.packet[ 9] = (a & 0xFF) as u8;
                self.packet[10] = (b >> 8) as u8;
                self.packet[11] = (b & 0xFF) as u8;;
                self.packet[12] = (c >> 8) as u8;
                self.packet[13] = (c & 0xFF) as u8;;
                self.packet[14] = (d >> 8) as u8;
                self.packet[15] = (d & 0xFF) as u8;;
                self.packet[16] = (e >> 8) as u8;
                self.packet[17] = (e & 0xFF) as u8;;
                self.packet[18] = (f >> 8) as u8;
                self.packet[19] = (f & 0xFF) as u8;;
                self.packet[20] = (g >> 8) as u8;
                self.packet[21] = (g & 0xFF) as u8;;
                self.packet[22] = (h >> 8) as u8;
                self.packet[23] = (h & 0xFF) as u8;
            },
            _ => ()
        }
    }

    /// Set the destination IP address for the packet
    pub fn set_destination(&mut self, ip: IpAddr) {
        match ip {
            Ipv6Addr(a, b, c, d, e, f, g, h) => {
                self.packet[24] = (a >> 8) as u8;
                self.packet[25] = (a & 0xFF) as u8;
                self.packet[26] = (b >> 8) as u8;
                self.packet[27] = (b & 0xFF) as u8;;
                self.packet[28] = (c >> 8) as u8;
                self.packet[29] = (c & 0xFF) as u8;;
                self.packet[30] = (d >> 8) as u8;
                self.packet[31] = (d & 0xFF) as u8;;
                self.packet[32] = (e >> 8) as u8;
                self.packet[33] = (e & 0xFF) as u8;;
                self.packet[34] = (f >> 8) as u8;
                self.packet[35] = (f & 0xFF) as u8;;
                self.packet[36] = (g >> 8) as u8;
                self.packet[37] = (g & 0xFF) as u8;;
                self.packet[38] = (h >> 8) as u8;
                self.packet[39] = (h & 0xFF) as u8;
            },
            _ => ()
        }
    }
}

#[test]
fn ipv6_header_test() {
    use packet::ip::IpNextHeaderProtocols;
    let mut packet = [0u8; 40];
    {
        let mut ip_header = MutableIpv6Header::new(packet.as_mut_slice());
        ip_header.set_version(6);
        assert_eq!(ip_header.get_version(), 6);

        ip_header.set_traffic_class(17);
        assert_eq!(ip_header.get_traffic_class(), 17);

        ip_header.set_flow_label(0x10101);
        assert_eq!(ip_header.get_flow_label(), 0x10101);

        ip_header.set_payload_length(0x0101);
        assert_eq!(ip_header.get_payload_length(), 0x0101);

        ip_header.set_next_header(IpNextHeaderProtocols::Udp);
        assert_eq!(ip_header.get_next_header(), IpNextHeaderProtocols::Udp);

        ip_header.set_hop_limit(1);
        assert_eq!(ip_header.get_hop_limit(), 1);

        let source = Ipv6Addr(0x110, 0x1001, 0x110, 0x1001, 0x110, 0x1001, 0x110, 0x1001);
        ip_header.set_source(source);
        assert_eq!(ip_header.get_source(), source);

        let dest = Ipv6Addr(0x110, 0x1001, 0x110, 0x1001, 0x110, 0x1001, 0x110, 0x1001);
        ip_header.set_destination(dest);
        assert_eq!(ip_header.get_destination(), dest);
    }

    let ref_packet = [0x61,           /* ver/traffic class */
                     0x11,           /* traffic class/flow label */
                     0x01, 0x01,     /* flow label */
                     0x01, 0x01,     /* payload length */
                     0x11,           /* next header */
                     0x01,           /* hop limit */
                     0x01, 0x10,     /* source ip */
                     0x10, 0x01,
                     0x01, 0x10,
                     0x10, 0x01,
                     0x01, 0x10,
                     0x10, 0x01,
                     0x01, 0x10,
                     0x10, 0x01,
                     0x01, 0x10,    /* dest ip */
                     0x10, 0x01,
                     0x01, 0x10,
                     0x10, 0x01,
                     0x01, 0x10,
                     0x10, 0x01,
                     0x01, 0x10,
                     0x10, 0x01];
    assert_eq!(ref_packet.as_slice(), packet.as_slice());
}

