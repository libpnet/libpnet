// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A TCP packet abstraction.

use crate::Packet;
use crate::PrimitiveValues;
use crate::ip::IpNextHeaderProtocols;

use alloc::{vec, vec::Vec};

use pnet_macros::packet;
use pnet_macros_support::types::*;

use pnet_base::core_net::Ipv4Addr;
use pnet_base::core_net::Ipv6Addr;
use crate::util::{self, Octets};

/// The TCP flags.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod TcpFlags {
    /// CWR – Congestion Window Reduced (CWR) flag is set by the sending
    /// host to indicate that it received a TCP segment with the ECE flag set
    /// and had responded in congestion control mechanism (added to header by RFC 3168).
    pub const CWR: u8 = 0b10000000;
    /// ECE – ECN-Echo has a dual role, depending on the value of the
    /// SYN flag. It indicates:
    /// If the SYN flag is set (1), that the TCP peer is ECN capable.
    /// If the SYN flag is clear (0), that a packet with Congestion Experienced
    /// flag set (ECN=11) in IP header received during normal transmission
    /// (added to header by RFC 3168).
    pub const ECE: u8 = 0b01000000;
    /// URG – indicates that the Urgent pointer field is significant.
    pub const URG: u8 = 0b00100000;
    /// ACK – indicates that the Acknowledgment field is significant.
    /// All packets after the initial SYN packet sent by the client should have this flag set.
    pub const ACK: u8 = 0b00010000;
    /// PSH – Push function. Asks to push the buffered data to the receiving application.
    pub const PSH: u8 = 0b00001000;
    /// RST – Reset the connection.
    pub const RST: u8 = 0b00000100;
    /// SYN – Synchronize sequence numbers. Only the first packet sent from each end
    /// should have this flag set.
    pub const SYN: u8 = 0b00000010;
    /// FIN – No more data from sender.
    pub const FIN: u8 = 0b00000001;
}

/// Represents a TCP packet.
#[packet]
pub struct Tcp {
    pub source: u16be,
    pub destination: u16be,
    pub sequence: u32be,
    pub acknowledgement: u32be,
    pub data_offset: u4,
    pub reserved: u4,
    pub flags: u8,
    pub window: u16be,
    pub checksum: u16be,
    pub urgent_ptr: u16be,
    #[length_fn = "tcp_options_length"]
    pub options: Vec<TcpOption>,
    #[payload]
    pub payload: Vec<u8>,
}

/// Represents a TCP option.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcpOptionNumber(pub u8);

/// The TCP header options.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod TcpOptionNumbers {
    use super::TcpOptionNumber;

    /// End of Options list.
    pub const EOL: TcpOptionNumber = TcpOptionNumber(0);

    /// No operation.
    pub const NOP: TcpOptionNumber = TcpOptionNumber(1);

    /// Maximum segment size.
    pub const MSS: TcpOptionNumber = TcpOptionNumber(2);

    /// Window scale.
    pub const WSCALE: TcpOptionNumber = TcpOptionNumber(3);

    /// Selective acknowledgements permitted.
    pub const SACK_PERMITTED: TcpOptionNumber = TcpOptionNumber(4);

    /// Selective acknowledgment.
    pub const SACK: TcpOptionNumber = TcpOptionNumber(5);

    /// Timestamps.
    pub const TIMESTAMPS: TcpOptionNumber = TcpOptionNumber(8);
}

/// A TCP option.
#[packet]
pub struct TcpOption {
    #[construct_with(u8)]
    number: TcpOptionNumber,
    #[length_fn = "tcp_option_length"]
    // The length field is an optional field, using a Vec is a way to implement
    // it
    length: Vec<u8>,
    #[length_fn = "tcp_option_payload_length"]
    #[payload]
    data: Vec<u8>,
}

impl TcpOption {
    /// NOP: This may be used to align option fields on 32-bit boundaries for better performance.
    pub fn nop() -> Self {
        TcpOption {
            number: TcpOptionNumbers::NOP,
            length: vec![],
            data: vec![],
        }
    }

    /// Timestamp: TCP timestamps, defined in RFC 1323, can help TCP determine in which order
    /// packets were sent. TCP timestamps are not normally aligned to the system clock and
    /// start at some random value.
    pub fn timestamp(my: u32, their: u32) -> Self {
        let mut data = vec![];
        data.extend_from_slice(&my.octets()[..]);
        data.extend_from_slice(&their.octets()[..]);

        TcpOption {
            number: TcpOptionNumbers::TIMESTAMPS,
            length: vec![10],
            data: data,
        }
    }

    /// MSS: The maximum segment size (MSS) is the largest amount of data, specified in bytes,
    /// that TCP is willing to receive in a single segment.
    pub fn mss(val: u16) -> Self {
        let mut data = vec![];
        data.extend_from_slice(&val.octets()[..]);

        TcpOption {
            number: TcpOptionNumbers::MSS,
            length: vec![4],
            data: data,
        }
    }

    /// Window scale: The TCP window scale option, as defined in RFC 1323, is an option used to
    /// increase the maximum window size from 65,535 bytes to 1 gigabyte.
    pub fn wscale(val: u8) -> Self {
        TcpOption {
            number: TcpOptionNumbers::WSCALE,
            length: vec![3],
            data: vec![val],
        }
    }

    /// Selective acknowledgment (SACK) option, defined in RFC 2018 allows the receiver to acknowledge
    /// discontinuous blocks of packets which were received correctly. This options enables use of
    /// SACK during negotiation.
    pub fn sack_perm() -> Self {
        TcpOption {
            number: TcpOptionNumbers::SACK_PERMITTED,
            length: vec![2],
            data: vec![],
        }
    }

    /// Selective acknowledgment (SACK) option, defined in RFC 2018 allows the receiver to acknowledge
    /// discontinuous blocks of packets which were received correctly. The acknowledgement can specify
    /// a number of SACK blocks, where each SACK block is conveyed by the starting and ending sequence
    /// numbers of a contiguous range that the receiver correctly received.
    pub fn selective_ack(acks: &[u32]) -> Self {
        let mut data = vec![];
        for ack in acks {
            data.extend_from_slice(&ack.octets()[..]);
        }
        TcpOption {
            number: TcpOptionNumbers::SACK,
            length: vec![1 /* number */ + 1 /* length */ + data.len() as u8],
            data: data,
        }
    }
}

/// This function gets the 'length' of the length field of the IPv4Option packet
/// Few options (EOL, NOP) are 1 bytes long, and then have a length field equal
/// to 0.
#[inline]
fn tcp_option_length(option: &TcpOptionPacket) -> usize {
    match option.get_number() {
        TcpOptionNumbers::EOL => 0,
        TcpOptionNumbers::NOP => 0,
        _ => 1,
    }
}

fn tcp_option_payload_length(ipv4_option: &TcpOptionPacket) -> usize {
    match ipv4_option.get_length_raw().first() {
        Some(len) if *len >= 2 => *len as usize - 2,
        _ => 0,
    }
}

impl TcpOptionNumber {
    /// Create a new `TcpOptionNumber` instance.
    pub fn new(value: u8) -> TcpOptionNumber {
        TcpOptionNumber(value)
    }
}

impl PrimitiveValues for TcpOptionNumber {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

#[inline]
fn tcp_options_length(tcp: &TcpPacket) -> usize {
    let data_offset = tcp.get_data_offset();

    if data_offset > 5 {
        data_offset as usize * 4 - 20
    } else {
        0
    }
}

/// Calculate a checksum for a packet built on IPv4.
pub fn ipv4_checksum(packet: &TcpPacket, source: &Ipv4Addr, destination: &Ipv4Addr) -> u16 {
    ipv4_checksum_adv(packet, &[], source, destination)
}

/// Calculate the checksum for a packet built on IPv4, Advanced version which
/// accepts an extra slice of data that will be included in the checksum
/// as being part of the data portion of the packet.
///
/// If `packet` contains an odd number of bytes the last byte will not be
/// counted as the first byte of a word together with the first byte of
/// `extra_data`.
pub fn ipv4_checksum_adv(packet: &TcpPacket,
                         extra_data: &[u8],
                         source: &Ipv4Addr,
                         destination: &Ipv4Addr)
    -> u16 {
    util::ipv4_checksum(packet.packet(),
                        8,
                        extra_data,
                        source,
                        destination,
                        IpNextHeaderProtocols::Tcp)
}

/// Calculate a checksum for a packet built on IPv6.
pub fn ipv6_checksum(packet: &TcpPacket, source: &Ipv6Addr, destination: &Ipv6Addr) -> u16 {
    ipv6_checksum_adv(packet, &[], source, destination)
}

/// Calculate the checksum for a packet built on IPv6, Advanced version which
/// accepts an extra slice of data that will be included in the checksum
/// as being part of the data portion of the packet.
///
/// If `packet` contains an odd number of bytes the last byte will not be
/// counted as the first byte of a word together with the first byte of
/// `extra_data`.
pub fn ipv6_checksum_adv(packet: &TcpPacket,
                         extra_data: &[u8],
                         source: &Ipv6Addr,
                         destination: &Ipv6Addr)
    -> u16 {
    util::ipv6_checksum(packet.packet(),
                        8,
                        extra_data,
                        source,
                        destination,
                        IpNextHeaderProtocols::Tcp)
}

#[test]
fn tcp_header_ipv4_test() {
    use crate::ip::IpNextHeaderProtocols;
    use crate::ipv4::MutableIpv4Packet;

    const IPV4_HEADER_LEN: usize = 20;
    const TCP_HEADER_LEN: usize = 32;
    const TEST_DATA_LEN: usize = 4;

    let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TEST_DATA_LEN];
    let ipv4_source = Ipv4Addr::new(192, 168, 2, 1);
    let ipv4_destination = Ipv4Addr::new(192, 168, 111, 51);
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_header.set_source(ipv4_source);
        ip_header.set_destination(ipv4_destination);
    }

    // Set data
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN] = 't' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 1] = 'e' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 2] = 's' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 3] = 't' as u8;

    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        tcp_header.set_source(49511);
        assert_eq!(tcp_header.get_source(), 49511);

        tcp_header.set_destination(9000);
        assert_eq!(tcp_header.get_destination(), 9000);

        tcp_header.set_sequence(0x9037d2b8);
        assert_eq!(tcp_header.get_sequence(), 0x9037d2b8);

        tcp_header.set_acknowledgement(0x944bb276);
        assert_eq!(tcp_header.get_acknowledgement(), 0x944bb276);

        tcp_header.set_flags(TcpFlags::PSH | TcpFlags::ACK);
        assert_eq!(tcp_header.get_flags(), TcpFlags::PSH | TcpFlags::ACK);

        tcp_header.set_window(4015);
        assert_eq!(tcp_header.get_window(), 4015);

        tcp_header.set_data_offset(8);
        assert_eq!(tcp_header.get_data_offset(), 8);

        let ts = TcpOption::timestamp(743951781, 44056978);
        tcp_header.set_options(&vec![TcpOption::nop(), TcpOption::nop(), ts]);

        let checksum = ipv4_checksum(&tcp_header.to_immutable(), &ipv4_source, &ipv4_destination);
        tcp_header.set_checksum(checksum);
        assert_eq!(tcp_header.get_checksum(), 0xc031);
    }
    let ref_packet = [0xc1, 0x67, /* source */
                      0x23, 0x28, /* destination */
                      0x90, 0x37, 0xd2, 0xb8, /* seq */
                      0x94, 0x4b, 0xb2, 0x76, /* ack */
                      0x80, 0x18, 0x0f, 0xaf, /* length, flags, win */
                      0xc0, 0x31, /* checksum */
                      0x00, 0x00,  /* urg ptr */
                      0x01, 0x01, /* options: nop */
                      0x08, 0x0a, 0x2c, 0x57,
                      0xcd, 0xa5, 0x02, 0xa0,
                      0x41, 0x92, /* timestamp */
                      0x74, 0x65, 0x73, 0x74 /* "test" */
                      ];
    assert_eq!(&ref_packet[..], &packet[20..]);
}

#[test]
fn tcp_test_options_invalid_offset() {
    let mut buf = [0; 20]; // no space for options
    {
        if let Some(mut tcp) = MutableTcpPacket::new(&mut buf[..]) {
            tcp.set_data_offset(10); // set invalid offset
        }
    }

    if let Some(tcp) = TcpPacket::new(&buf[..]) {
        let _options = tcp.get_options_iter(); // shouldn't crash here
    }
}

#[test]
fn tcp_test_options_vec_invalid_offset() {
    let mut buf = [0; 20]; // no space for options
    {
        if let Some(mut tcp) = MutableTcpPacket::new(&mut buf[..]) {
            tcp.set_data_offset(10); // set invalid offset
        }
    }

    if let Some(tcp) = TcpPacket::new(&buf[..]) {
        let _options = tcp.get_options(); // shouldn't crash here
    }
}

#[test]
fn tcp_test_options_slice_invalid_offset() {
    let mut buf = [0; 20]; // no space for options
    {
        if let Some(mut tcp) = MutableTcpPacket::new(&mut buf[..]) {
            tcp.set_data_offset(10); // set invalid offset
        }
    }

    if let Some(tcp) = TcpPacket::new(&buf[..]) {
        let _options = tcp.get_options_raw(); // shouldn't crash here
    }
}

#[test]
fn tcp_test_option_invalid_len() {
    use std::println;
    let mut buf = [0; 24];
    {
        if let Some(mut tcp) = MutableTcpPacket::new(&mut buf[..]) {
            tcp.set_data_offset(6);
        }
        buf[20] = 2; // option type
        buf[21] = 8; // option len, not enough space for it
    }

    if let Some(tcp) = TcpPacket::new(&buf[..]) {
        let options = tcp.get_options_iter();
        for opt in options {
            println!("{:?}", opt);
        }
    }
}

#[test]
fn tcp_test_payload_slice_invalid_offset() {
    let mut buf = [0; 20];
    {
        if let Some(mut tcp) = MutableTcpPacket::new(&mut buf[..]) {
            tcp.set_data_offset(10); // set invalid offset
        }
    }

    if let Some(tcp) = TcpPacket::new(&buf[..]) {
        assert_eq!(tcp.payload().len(), 0);
    }
}
