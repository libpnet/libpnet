// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! IPv4 packet abstraction

use packet::ip::IpNextHeaderProtocol;
use packet::{PseudoHeader, PrimitiveValues};
use util::rfc1071_checksum;
use pnet_macros_support::types::*;

use std::net::Ipv4Addr;


/// Represents an IPv4 Packet
#[packet]
pub struct Ipv4 {
    version: u4,
    header_length: u4,
    dscp: u6,
    ecn: u2,
    total_length: u16be,
    identification: u16be,
    flags: u3,
    fragment_offset: u13be,
    ttl: u8,
    #[construct_with(u8)]
    next_level_protocol: IpNextHeaderProtocol,
    checksum: u16be,
    #[construct_with(u8, u8, u8, u8)]
    source: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    destination: Ipv4Addr,
    #[length_fn = "ipv4_options_length"]
    options: Vec<Ipv4Option>,
    #[payload]
    payload: Vec<u8>,
}


impl<'p> PseudoHeader for Ipv4Packet<'p> {
    fn checksum(&self) -> u32 {
        let mut sum = 0u32;

        // Checksum pseudo-header
        // IPv4 source
        let source = self.get_source();
        match source.octets() {
            [a, b, c, d] => {
                let src = vec![a, b, c, d];
                sum = sum + (src[0] as u32) + (src[2] as u32) << 8;
                sum = sum + src[1] as u32 + src[3] as u32;
            }
        }

        // IPv4 destination
        let destination = self.get_destination();
        match destination.octets() {
            [a, b, c, d] => {
                let dst = vec![a, b, c, d];
                sum = sum + (dst[0] as u32) + (dst[2] as u32) << 8;
                sum = sum + dst[1] as u32 + dst[3] as u32;
            }
        }

        // IPv4 Next level protocol
        let next_level_protocol = self.get_next_level_protocol();
        let (next_proto,) = next_level_protocol.to_primitive_values();
        sum = sum + (next_proto as u32);
        return sum;
    }
}

fn ipv4_options_length(ipv4: &Ipv4Packet) -> usize {
    ipv4.get_header_length() as usize - 5
}

/// Calculates the checksum of an IPv4 packet
pub fn checksum<'a>(packet: &Ipv4Packet<'a>) -> u16be {
    use packet::Packet;

    return rfc1071_checksum(packet.packet(), 0);
}

#[test]
fn ipv4_options_length_test() {
    let mut packet = [0u8; 20];
    let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
    ip_header.set_header_length(5);
    assert_eq!(ipv4_options_length(&ip_header.to_immutable()), 0);
}

/// Represents the IPv4 Option field
#[packet]
pub struct Ipv4Option {
    copied: u1,
    class: u2,
    number: u5,
    length: u8,
    #[payload]
    data: Vec<u8>,
}

#[test]
fn ipv4_packet_test() {
    use packet::ip::IpNextHeaderProtocols;

    let mut packet = [0u8; 20];
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
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
        assert_eq!(ip_header.get_next_level_protocol(),
                   IpNextHeaderProtocols::Udp);

        ip_header.set_source(Ipv4Addr::new(192, 168, 0, 1));
        assert_eq!(ip_header.get_source(), Ipv4Addr::new(192, 168, 0, 1));

        ip_header.set_destination(Ipv4Addr::new(192, 168, 0, 199));
        assert_eq!(ip_header.get_destination(), Ipv4Addr::new(192, 168, 0, 199));

        let imm_header = checksum(&ip_header.to_immutable());
        ip_header.set_checksum(imm_header);
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

    assert_eq!(&ref_packet[..], &packet[..]);
}
