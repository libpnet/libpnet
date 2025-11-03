// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! An IPv6 packet abstraction.

use crate::ip::IpNextHeaderProtocol;

use alloc::vec::Vec;

use pnet_macros::packet;
use pnet_macros_support::types::*;

use core::net::Ipv6Addr;

/// Represents an IPv6 Packet.
#[packet]
pub struct Ipv6 {
    pub version: u4,
    pub traffic_class: u8,
    pub flow_label: u20be,
    pub payload_length: u16be,
    #[construct_with(u8)]
    pub next_header: IpNextHeaderProtocol,
    pub hop_limit: u8,
    #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
    pub source: Ipv6Addr,
    #[construct_with(u16, u16, u16, u16, u16, u16, u16, u16)]
    pub destination: Ipv6Addr,
    #[length = "payload_length"]
    #[payload]
    pub payload: Vec<u8>,
}

impl<'p> ExtensionIterable<'p> {
    pub fn new(buf: &[u8]) -> ExtensionIterable<'_> {
        ExtensionIterable { buf: buf }
    }
}

/// Represents an IPv6 Extension.
#[packet]
pub struct Extension {
    #[construct_with(u8)]
    pub next_header: IpNextHeaderProtocol,
    pub hdr_ext_len: u8,
    #[length_fn = "ipv6_extension_length"]
    #[payload]
    pub options: Vec<u8>,
}

fn ipv6_extension_length(ext: &ExtensionPacket) -> usize {
    ext.get_hdr_ext_len() as usize * 8 + 8 - 2
}

/// Represents an IPv6 Hop-by-Hop Options.
pub type HopByHop = Extension;
/// A structure enabling manipulation of on the wire packets.
pub type HopByHopPacket<'p> = ExtensionPacket<'p>;
/// A structure enabling manipulation of on the wire packets.
pub type MutableHopByHopPacket<'p> = MutableExtensionPacket<'p>;

/// Represents an IPv6 Routing Extension.
#[packet]
pub struct Routing {
    #[construct_with(u8)]
    pub next_header: IpNextHeaderProtocol,
    pub hdr_ext_len: u8,
    pub routing_type: u8,
    pub segments_left: u8,
    #[length_fn = "routing_extension_length"]
    #[payload]
    pub data: Vec<u8>,
}

fn routing_extension_length(ext: &RoutingPacket) -> usize {
    ext.get_hdr_ext_len() as usize * 8 + 8 - 4
}

/// Represents an IPv6 Fragment Extension.
#[packet]
pub struct Fragment {
    #[construct_with(u8)]
    pub next_header: IpNextHeaderProtocol,
    pub reserved: u8,
    pub fragment_offset_with_flags: u16be,
    pub id: u32be,
    #[length = "0"]
    #[payload]
    pub payload: Vec<u8>,
}

const FRAGMENT_FLAGS_MASK: u16 = 0x03;
const FRAGMENT_FLAGS_MORE_FRAGMENTS: u16 = 0x01;
const FRAGMENT_OFFSET_MASK: u16 = !FRAGMENT_FLAGS_MASK;

impl<'p> FragmentPacket<'p> {
    pub fn get_fragment_offset(&self) -> u16 {
        self.get_fragment_offset_with_flags() & FRAGMENT_OFFSET_MASK
    }

    pub fn is_last_fragment(&self) -> bool {
        (self.get_fragment_offset_with_flags() & FRAGMENT_FLAGS_MORE_FRAGMENTS) == 0
    }
}

impl<'p> MutableFragmentPacket<'p> {
    pub fn get_fragment_offset(&self) -> u16 {
        self.get_fragment_offset_with_flags() & FRAGMENT_OFFSET_MASK
    }

    pub fn is_last_fragment(&self) -> bool {
        (self.get_fragment_offset_with_flags() & FRAGMENT_FLAGS_MORE_FRAGMENTS) == 0
    }

    pub fn set_fragment_offset(&mut self, offset: u16) {
        let fragment_offset_with_flags = self.get_fragment_offset_with_flags();

        self.set_fragment_offset_with_flags(
            (offset & FRAGMENT_OFFSET_MASK) | (fragment_offset_with_flags & FRAGMENT_FLAGS_MASK),
        );
    }

    pub fn set_last_fragment(&mut self, is_last: bool) {
        let fragment_offset_with_flags = self.get_fragment_offset_with_flags();

        self.set_fragment_offset_with_flags(if is_last {
            fragment_offset_with_flags & !FRAGMENT_FLAGS_MORE_FRAGMENTS
        } else {
            fragment_offset_with_flags | FRAGMENT_FLAGS_MORE_FRAGMENTS
        });
    }
}

/// Represents an Destination Options.
pub type Destination = Extension;
/// A structure enabling manipulation of on the wire packets.
pub type DestinationPacket<'p> = ExtensionPacket<'p>;
/// A structure enabling manipulation of on the wire packets.
pub type MutableDestinationPacket<'p> = MutableExtensionPacket<'p>;

#[test]
fn ipv6_header_test() {
    use crate::ip::IpNextHeaderProtocols;
    use crate::{MutablePacket, Packet, PacketSize};
    use alloc::vec;

    let mut packet = [0u8; 0x200];
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
        assert_eq!(0x0101, ip_header.payload().len());

        ip_header.set_next_header(IpNextHeaderProtocols::Hopopt);
        assert_eq!(ip_header.get_next_header(), IpNextHeaderProtocols::Hopopt);

        ip_header.set_hop_limit(1);
        assert_eq!(ip_header.get_hop_limit(), 1);

        let source = Ipv6Addr::new(0x110, 0x1001, 0x110, 0x1001, 0x110, 0x1001, 0x110, 0x1001);
        ip_header.set_source(source);
        assert_eq!(ip_header.get_source(), source);

        let dest = Ipv6Addr::new(0x110, 0x1001, 0x110, 0x1001, 0x110, 0x1001, 0x110, 0x1001);
        ip_header.set_destination(dest);
        assert_eq!(ip_header.get_destination(), dest);

        let mut pos = {
            let mut hopopt = MutableHopByHopPacket::new(ip_header.payload_mut()).unwrap();

            hopopt.set_next_header(IpNextHeaderProtocols::Ipv6Opts);
            assert_eq!(hopopt.get_next_header(), IpNextHeaderProtocols::Ipv6Opts);

            hopopt.set_hdr_ext_len(1);
            assert_eq!(hopopt.get_hdr_ext_len(), 1);

            hopopt.set_options(&[b'A'; 14][..]);
            assert_eq!(hopopt.payload(), b"AAAAAAAAAAAAAA");

            hopopt.packet_size()
        };

        pos += {
            let mut dstopt =
                MutableDestinationPacket::new(&mut ip_header.payload_mut()[pos..]).unwrap();

            dstopt.set_next_header(IpNextHeaderProtocols::Ipv6Route);
            assert_eq!(dstopt.get_next_header(), IpNextHeaderProtocols::Ipv6Route);

            dstopt.set_hdr_ext_len(1);
            assert_eq!(dstopt.get_hdr_ext_len(), 1);

            dstopt.set_options(&[b'B'; 14][..]);
            assert_eq!(dstopt.payload(), b"BBBBBBBBBBBBBB");

            dstopt.packet_size()
        };

        pos += {
            let mut routing =
                MutableRoutingPacket::new(&mut ip_header.payload_mut()[pos..]).unwrap();

            routing.set_next_header(IpNextHeaderProtocols::Ipv6Frag);
            assert_eq!(routing.get_next_header(), IpNextHeaderProtocols::Ipv6Frag);

            routing.set_hdr_ext_len(1);
            assert_eq!(routing.get_hdr_ext_len(), 1);

            routing.set_routing_type(4);
            assert_eq!(routing.get_routing_type(), 4);

            routing.set_segments_left(2);
            assert_eq!(routing.get_segments_left(), 2);

            routing.set_data(&[b'C'; 12][..]);
            assert_eq!(routing.payload(), b"CCCCCCCCCCCC");

            routing.packet_size()
        };

        pos += {
            let mut frag = MutableFragmentPacket::new(&mut ip_header.payload_mut()[pos..]).unwrap();

            frag.set_next_header(IpNextHeaderProtocols::Udp);
            assert_eq!(frag.get_next_header(), IpNextHeaderProtocols::Udp);

            frag.set_fragment_offset(1024);
            assert_eq!(frag.get_fragment_offset(), 1024);

            frag.set_last_fragment(false);
            assert!(!frag.is_last_fragment());

            frag.set_id(1234);
            assert_eq!(frag.get_id(), 1234);

            frag.packet_size()
        };

        assert_eq!(
            ExtensionIterable::new(&ip_header.payload()[..pos])
                .map(|ext| (
                    ext.get_next_header(),
                    ext.get_hdr_ext_len(),
                    ext.packet_size()
                ))
                .collect::<Vec<_>>(),
            vec![
                (IpNextHeaderProtocols::Ipv6Opts, 1, 16),
                (IpNextHeaderProtocols::Ipv6Route, 1, 16),
                (IpNextHeaderProtocols::Ipv6Frag, 1, 16),
                (IpNextHeaderProtocols::Udp, 0, 8),
            ]
        );
    }

    let ref_packet = [0x61,           /* ver/traffic class */
                      0x11,           /* traffic class/flow label */
                      0x01, 0x01,     /* flow label */
                      0x01, 0x01,     /* payload length */
                      0x00,           /* next header */
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
                      0x01, 0x10, 0x10, 0x01,
                      /* Hop-by-Hop Options */
                      0x3c,             // Next Header
                      0x01,             // Hdr Ext Len
                      b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
                      b'A', b'A', b'A', b'A', b'A', b'A',
                      /* Destination Options */
                      0x2b,             // Next Header
                      0x01,             // Hdr Ext Len
                      b'B', b'B', b'B', b'B', b'B', b'B', b'B', b'B',
                      b'B', b'B', b'B', b'B', b'B', b'B',
                      /* Routing */
                      0x2c,             // Next Header
                      0x01,             // Hdr Ext Len
                      0x04,             // Routing Type
                      0x02,             // Segments Left
                      b'C', b'C', b'C', b'C', b'C', b'C', b'C', b'C',
                      b'C', b'C', b'C', b'C',
                      /* Fragment */
                      0x11,                     // Next Header
                      0x00,                     // Reserved
                      0x04, 0x01,               // Fragment Offset
                      0x00, 0x00, 0x04, 0xd2    // Identification
                      ];
    assert_eq!(&ref_packet[..], &packet[..ref_packet.len()]);
}
