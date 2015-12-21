// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! IPv6 packet abstraction

use packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use packet::{PseudoHeader, PrimitiveValues};
use pnet_macros_support::types::*;

use std::net::Ipv6Addr;

/// Represents an IPv6 Packet
#[packet]
pub struct Ipv6 {
    version: u4,
    traffic_class: u8,
    flow_label: u20be,
    payload_length: u16be,
    #[construct_with(u8)]
    next_header: IpNextHeaderProtocol,
    hop_limit: u8,
    #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
    source: Ipv6Addr,
    #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
    destination: Ipv6Addr,
    #[payload]
    payload: Vec<u8>,
}

/// Represents an IPv6 Packet pseudo header
#[packet]
pub struct Ipv6PseudoHeader {
    #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
    source: Ipv6Addr,
    /// RFC 2460:
    /// If the IPv6 packet contains a Routing header, the Destination Address used in the
    /// pseudo-header is that of the final destination. At the originating node, that address will
    /// be in the last element of the Routing header; at the recipient(s), that address will be in
    /// the Destination Address field of the IPv6 header.
    #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
    destination: Ipv6Addr,
    /// RFC 2460: 
    /// The Upper-Layer Packet Length in the pseudo-header is the length of the
    /// upper-layer header and data (e.g., TCP header plus TCP data). Some upper-layer protocols
    /// carry their own length information (e.g., the Length field in the UDP header); for such
    /// protocols, that is the length used in the pseudo- header. Other protocols (such as TCP) do
    /// not carry their own length information, in which case the length used in the pseudo-header
    /// is the Payload Length from the IPv6 header, minus the length of any extension headers
    /// present between the IPv6 header and the upper-layer header.
    inner_packet_length: u32be,
    zeros: u24be,
    /// RFC 2460:
    /// The Next Header value in the pseudo-header identifies the upper-layer protocol (e.g., 6 for
    /// TCP, or 17 for UDP). It will differ from the Next Header value in the IPv6 header if there
    /// are extension headers between the IPv6 header and the upper-layer header.
    #[construct_with(u8)]
    next_level_protocol: IpNextHeaderProtocol,
    #[payload]
    payload: Vec<u8>,
}

pub struct Ipv6HeaderIter<'p, 'h> {
    packet: &'p Ipv6Packet<'p>,
    current_header: Ipv6Packet<'h>,
}

impl<'p, 'h> Iterator for Ipv6HeaderIter<'p, 'h> {
    type Item = &'h Ipv6Packet<'h>;
    fn next(&mut self) -> Option<&'h Ipv6Packet<'h>> {
        match self.current_header.get_next_header() {
            IpNextHeaderProtocols::Hopopt |
            IpNextHeaderProtocols::Ipv6 |
            IpNextHeaderProtocols::Ipv6Route | 
            IpNextHeaderProtocols::Ipv6Frag |
            IpNextHeaderProtocols::Ipv6Icmp |
            IpNextHeaderProtocols::Ipv6Opts => {
                self.current_header = Ipv6Packet::new(self.current_header.payload()).unwrap(); // is it ok to unwrap here?
                Some(self.current_header)
            },
            _ => None,
        };
    }
}

impl<'p> PseudoHeader for Ipv6Packet<'p> {
    // might need other argument for next header value in case of header extensions.
    fn get_pseudo_header(&self, inner_packet_length: Option<u32>) -> Vec<u8> {
        let mut pseudo_header_buf: Vec<u8> = vec![0, 40];
        {
            let mut pseudo_header = MutableIpv6PseudoHeaderPacket::new(&mut pseudo_header_buf[..]).unwrap();
            pseudo_header.set_source(self.get_source());
            // FIXME: not sure which header I should take for this one...
            pseudo_header.set_destination(self.get_destination());
            // Get the next_level_protocol and inner_packet_length from the last ipv6 header
            loop {
                if let Some(header) = self.next() {
                    pseudo_header.set_next_level_protocol(header.get_next_header());
                    pseudo_header.set_inner_packet_length(header.get_payload_length() as u32);
                } else {
                    break;
                }
            }
            if let Some(inner_packet_length) = inner_packet_length {
                pseudo_header.set_inner_packet_length(inner_packet_length as u32);
            } 
        }
        pseudo_header_buf
    }
}

#[test]
fn ipv6_header_test() {
    use packet::ip::IpNextHeaderProtocols;
    let mut packet = [0u8; 40];
    {
        let mut ip_header = MutableIpv6Packet::new(&mut packet[..]).unwrap();
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

        let source = Ipv6Addr::new(0x110, 0x1001, 0x110, 0x1001, 0x110, 0x1001, 0x110, 0x1001);
        ip_header.set_source(source);
        assert_eq!(ip_header.get_source(), source);

        let dest = Ipv6Addr::new(0x110, 0x1001, 0x110, 0x1001, 0x110, 0x1001, 0x110, 0x1001);
        ip_header.set_destination(dest);
        assert_eq!(ip_header.get_destination(), dest);
    }

    let ref_packet = [0x61,           /* ver/traffic class */
                      0x11,           /* traffic class/flow label */
                      0x01, 0x01,     /* flow label */
                      0x01, 0x01,     /* payload length */
                      0x11,           /* next header */
                      0x01,           /* hop limit */
                      /* source ip */
                      0x01, 0x10, 0x10, 0x01,
                      0x01, 0x10, 0x10, 0x01,
                      0x01, 0x10, 0x10, 0x01,
                      0x01, 0x10, 0x10, 0x01,
                      /* dest ip */
                      0x01, 0x10, 0x10, 0x01,
                      0x01, 0x10, 0x10, 0x01,
                      0x01, 0x10, 0x10, 0x01,
                      0x01, 0x10, 0x10, 0x01];
    assert_eq!(&ref_packet[..], &packet[..]);
}
