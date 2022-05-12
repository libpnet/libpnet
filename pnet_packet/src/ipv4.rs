// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! An IPv4 packet abstraction.

use crate::PrimitiveValues;
use crate::ip::IpNextHeaderProtocol;

use alloc::vec::Vec;

use pnet_macros::packet;
use pnet_macros_support::types::*;

use pnet_base::core_net::Ipv4Addr;

/// The IPv4 header flags.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Ipv4Flags {
    use pnet_macros_support::types::*;

    /// Don't Fragment flag.
    pub const DontFragment: u3 = 0b010;
    /// More Fragments flag.
    pub const MoreFragments: u3 = 0b001;
}

/// IPv4 header options numbers as defined in
/// <http://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml>
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod Ipv4OptionNumbers {
    use super::Ipv4OptionNumber;

    /// End of Options List.
    pub const EOL: Ipv4OptionNumber = Ipv4OptionNumber(0);

    /// No Operation.
    pub const NOP: Ipv4OptionNumber = Ipv4OptionNumber(1);

    /// Security.
    pub const SEC: Ipv4OptionNumber = Ipv4OptionNumber(2);

    /// Loose Source Route.
    pub const LSR: Ipv4OptionNumber = Ipv4OptionNumber(3);

    /// Time Stamp.
    pub const TS: Ipv4OptionNumber = Ipv4OptionNumber(4);

    /// Extended Security.
    pub const ESEC: Ipv4OptionNumber = Ipv4OptionNumber(5);

    /// Commercial Security.
    pub const CIPSO: Ipv4OptionNumber = Ipv4OptionNumber(6);

    /// Record Route.
    pub const RR: Ipv4OptionNumber = Ipv4OptionNumber(7);

    /// Stream ID.
    pub const SID: Ipv4OptionNumber = Ipv4OptionNumber(8);

    /// Strict Source Route.
    pub const SSR: Ipv4OptionNumber = Ipv4OptionNumber(9);

    /// Experimental Measurement.
    pub const ZSU: Ipv4OptionNumber = Ipv4OptionNumber(10);

    /// MTU Probe.
    pub const MTUP: Ipv4OptionNumber = Ipv4OptionNumber(11);

    /// MTU Reply.
    pub const MTUR: Ipv4OptionNumber = Ipv4OptionNumber(12);

    /// Experimental Flow Control.
    pub const FINN: Ipv4OptionNumber = Ipv4OptionNumber(13);

    /// Experimental Access Control.
    pub const VISA: Ipv4OptionNumber = Ipv4OptionNumber(14);

    /// ENCODE.
    pub const ENCODE: Ipv4OptionNumber = Ipv4OptionNumber(15);

    /// IMI Traffic Descriptor.
    pub const IMITD: Ipv4OptionNumber = Ipv4OptionNumber(16);

    /// Extended Internet Protocol.
    pub const EIP: Ipv4OptionNumber = Ipv4OptionNumber(17);

    /// Traceroute.
    pub const TR: Ipv4OptionNumber = Ipv4OptionNumber(18);

    /// Address Extension.
    pub const ADDEXT: Ipv4OptionNumber = Ipv4OptionNumber(19);

    /// Router Alert.
    pub const RTRALT: Ipv4OptionNumber = Ipv4OptionNumber(20);

    /// Selective Directed Broadcast.
    pub const SDB: Ipv4OptionNumber = Ipv4OptionNumber(21);

    /// Dynamic Packet State.
    pub const DPS: Ipv4OptionNumber = Ipv4OptionNumber(23);

    /// Upstream Multicast Pkt.
    pub const UMP: Ipv4OptionNumber = Ipv4OptionNumber(24);

    /// Quick-Start.
    pub const QS: Ipv4OptionNumber = Ipv4OptionNumber(25);

    /// RFC3692-style Experiment.
    pub const EXP: Ipv4OptionNumber = Ipv4OptionNumber(30);
}

/// Represents an IPv4 option.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ipv4OptionNumber(pub u8);

impl Ipv4OptionNumber {
    /// Create a new `Ipv4OptionNumber` instance.
    pub fn new(value: u8) -> Ipv4OptionNumber {
        Ipv4OptionNumber(value)
    }
}

impl PrimitiveValues for Ipv4OptionNumber {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

/// Represents an IPv4 Packet.
#[packet]
pub struct Ipv4 {
    pub version: u4,
    pub header_length: u4,
    pub dscp: u6,
    pub ecn: u2,
    pub total_length: u16be,
    pub identification: u16be,
    pub flags: u3,
    pub fragment_offset: u13be,
    pub ttl: u8,
    #[construct_with(u8)]
    pub next_level_protocol: IpNextHeaderProtocol,
    pub checksum: u16be,
    #[construct_with(u8, u8, u8, u8)]
    pub source: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub destination: Ipv4Addr,
    #[length_fn = "ipv4_options_length"]
    pub options: Vec<Ipv4Option>,
    #[length_fn = "ipv4_payload_length"]
    #[payload]
    pub payload: Vec<u8>,
}

/// Calculates a checksum of an IPv4 packet header.
/// The checksum field of the packet is regarded as zeros during the calculation.
pub fn checksum(packet: &Ipv4Packet) -> u16be {
    use crate::Packet;
    use crate::util;

    let min = Ipv4Packet::minimum_packet_size();
    let max = packet.packet().len();
    let header_length = match packet.get_header_length() as usize * 4 {
        length if length < min => min,
        length if length > max => max,
        length => length,
    };
    let data = &packet.packet()[..header_length];
    util::checksum(data, 5)
}

#[cfg(test)]
mod checksum_tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn checksum_zeros() {
        let mut data = vec![0; 20];
        let expected = 64255;
        let mut pkg = MutableIpv4Packet::new(&mut data[..]).unwrap();
        pkg.set_header_length(5);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
        pkg.set_checksum(123);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
    }

    #[test]
    fn checksum_nonzero() {
        let mut data = vec![255; 20];
        let expected = 2560;
        let mut pkg = MutableIpv4Packet::new(&mut data[..]).unwrap();
        pkg.set_header_length(5);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
        pkg.set_checksum(123);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
    }

    #[test]
    fn checksum_too_small_header_length() {
        let mut data = vec![148; 20];
        let expected = 51910;
        let mut pkg = MutableIpv4Packet::new(&mut data[..]).unwrap();
        pkg.set_header_length(0);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
    }

    #[test]
    fn checksum_too_large_header_length() {
        let mut data = vec![148; 20];
        let expected = 51142;
        let mut pkg = MutableIpv4Packet::new(&mut data[..]).unwrap();
        pkg.set_header_length(99);
        assert_eq!(checksum(&pkg.to_immutable()), expected);
    }
}

fn ipv4_options_length(ipv4: &Ipv4Packet) -> usize {
    // the header_length unit is the "word"
    // - and a word is made of 4 bytes,
    // - and the header length (without the options) is 5 words long
    (ipv4.get_header_length() as usize * 4).saturating_sub(20)
}

#[test]
fn ipv4_options_length_test() {
    let mut packet = [0u8; 20];
    let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
    ip_header.set_header_length(5);
    assert_eq!(ipv4_options_length(&ip_header.to_immutable()), 0);
}

fn ipv4_payload_length(ipv4: &Ipv4Packet) -> usize {
    (ipv4.get_total_length() as usize).saturating_sub(ipv4.get_header_length() as usize * 4)
}

#[test]
fn ipv4_payload_length_test() {
    let mut packet = [0u8; 30];
    let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
    ip_header.set_header_length(5);
    ip_header.set_total_length(20);
    assert_eq!(ipv4_payload_length(&ip_header.to_immutable()), 0);
    // just comparing with 0 is prone to false positives in this case.
    // for instance if one forgets to set total_length, one always gets 0
    ip_header.set_total_length(30);
    assert_eq!(ipv4_payload_length(&ip_header.to_immutable()), 10);
}

/// Represents the IPv4 Option field.
#[packet]
pub struct Ipv4Option {
    copied: u1,
    class: u2,
    #[construct_with(u5)]
    number: Ipv4OptionNumber,
    #[length_fn = "ipv4_option_length"]
    // The length field is an optional field, using a Vec is a way to implement
    // it
    length: Vec<u8>,
    #[length_fn = "ipv4_option_payload_length"]
    #[payload]
    data: Vec<u8>,
}

/// This function gets the 'length' of the length field of the IPv4Option packet
/// Few options (EOL, NOP) are 1 bytes long, and then have a length field equal
/// to 0.
fn ipv4_option_length(option: &Ipv4OptionPacket) -> usize {
    match option.get_number() {
        Ipv4OptionNumbers::EOL => 0,
        Ipv4OptionNumbers::NOP => 0,
        _ => 1,
    }
}

fn ipv4_option_payload_length(ipv4_option: &Ipv4OptionPacket) -> usize {
    match ipv4_option.get_length().first() {
        Some(len) => (*len as usize).saturating_sub(2),
        None => 0,
    }
}

#[test]
fn ipv4_packet_test() {
    use crate::ip::IpNextHeaderProtocols;
    use crate::Packet;
    use crate::PacketSize;

    let mut packet = [0u8; 200];
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
        assert_eq!(95, ip_header.payload().len());
        assert_eq!(ip_header.get_total_length(), ip_header.packet_size() as u16);

        ip_header.set_identification(257);
        assert_eq!(ip_header.get_identification(), 257);

        ip_header.set_flags(Ipv4Flags::DontFragment);
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

    assert_eq!(&ref_packet[..], &packet[..ref_packet.len()]);
}

#[test]
fn ipv4_packet_option_test() {
    use alloc::vec;

    let mut packet = [0u8; 3];
    {
        let mut ipv4_options = MutableIpv4OptionPacket::new(&mut packet[..]).unwrap();

        ipv4_options.set_copied(1);
        assert_eq!(ipv4_options.get_copied(), 1);

        ipv4_options.set_class(0);
        assert_eq!(ipv4_options.get_class(), 0);

        ipv4_options.set_number(Ipv4OptionNumber(3));
        assert_eq!(ipv4_options.get_number(), Ipv4OptionNumbers::LSR);

        ipv4_options.set_length(&vec![3]);
        assert_eq!(ipv4_options.get_length(), vec![3]);

        ipv4_options.set_data(&vec![16]);
    }

    let ref_packet = [0x83,           /* copy / class / number */
                      0x03,           /* length */
                      0x10,           /* data */];

    assert_eq!(&ref_packet[..], &packet[..]);
}

#[test]
fn ipv4_packet_set_payload_test() {
    use crate::Packet;

    let mut packet = [0u8; 25]; // allow 20 byte header and 5 byte payload
    let mut ip_packet = MutableIpv4Packet::new(&mut packet[..]).unwrap();
    ip_packet.set_total_length(25);
    ip_packet.set_header_length(5);
    let payload = b"stuff"; // 5 bytes
    ip_packet.set_payload(&payload[..]);
    assert_eq!(ip_packet.payload(), payload);
}

#[test]
#[should_panic(expected = "index 25 out of range for slice of length 24")]
fn ipv4_packet_set_payload_test_panic() {
    let mut packet = [0u8; 24]; // allow 20 byte header and 4 byte payload
    let mut ip_packet = MutableIpv4Packet::new(&mut packet[..]).unwrap();
    ip_packet.set_total_length(25);
    ip_packet.set_header_length(5);
    let payload = b"stuff"; // 5 bytes
    ip_packet.set_payload(&payload[..]); // panic
}
