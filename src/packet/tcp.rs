// Copyright (c) 2015 David Stainton <dstainton415@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TCP packet abstraction

use packet::Packet;
use packet::ip::IpNextHeaderProtocol;

use pnet_macros::types::*;

use std::net::{Ipv4Addr, Ipv6Addr};

/// Represents a TCP Packet
#[packet]
pub struct Tcp {
    source: u16be,
    destination: u16be,
    sequence: u32be,
    acknowledgement: u32be,
    #[payload]
    payload: Vec<u8>
}


#[test]
fn tcp_header_ipv4_test() {
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::MutableIpv4Packet;

    const IPV4_HEADER_LEN: usize = 20;
    const TCP_HEADER_LEN: usize = 12;
    const PAYLOAD_LEN: usize = 4;

    let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + PAYLOAD_LEN];

    let ipv4_source = Ipv4Addr::new(192, 168, 0, 1);
    let ipv4_destination = Ipv4Addr::new(192, 168, 0, 199);
    let next_level_protocol = IpNextHeaderProtocols::Tcp;
    {
        let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_level_protocol(next_level_protocol);
        ip_header.set_source(ipv4_source);
        ip_header.set_destination(ipv4_destination);
    }

    // Set data
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 0] = 't' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 1] = 'e' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 2] = 's' as u8;
    packet[IPV4_HEADER_LEN + TCP_HEADER_LEN + 3] = 't' as u8;

    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[20..]).unwrap();
        tcp_header.set_source(12345);
        assert_eq!(tcp_header.get_source(), 12345);

        tcp_header.set_destination(54321);
        assert_eq!(tcp_header.get_destination(), 54321);

        tcp_header.set_sequence(3456);
        assert_eq!(tcp_header.get_sequence(), 3456);

        tcp_header.set_acknowledgement(7799);
        assert_eq!(tcp_header.get_acknowledgement(), 7799);
    }

    let ref_packet = [0x30, 0x39,  // source
                      0xd4, 0x31,  // destination
                      0x00, 0x00,  // sequence
                      0x0d, 0x80,
                      0x00, 0x00,  // acknowledgement
                      0x1e, 0x77];

    assert_eq!(&ref_packet[..], &packet[IPV4_HEADER_LEN .. IPV4_HEADER_LEN + TCP_HEADER_LEN]);
}

#[test]
fn tcp_header_ipv6_test() {
    use packet::ip::{IpNextHeaderProtocols};
    use packet::ipv6::{MutableIpv6Packet};

    const IPV6_HEADER_LEN: usize = 40;
    const TCP_HEADER_LEN: usize = 12;
    const PAYLOAD_LEN: usize = 4;

    let mut packet = [0u8; IPV6_HEADER_LEN + TCP_HEADER_LEN + PAYLOAD_LEN];

    let next_header = IpNextHeaderProtocols::Tcp;
    let ipv6_source = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    let ipv6_destination = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
    {
        let mut ip_header = MutableIpv6Packet::new(&mut packet[..]).unwrap();
        ip_header.set_next_header(next_header);
        ip_header.set_source(ipv6_source);
        ip_header.set_destination(ipv6_destination);
    }

    // Set data
    packet[IPV6_HEADER_LEN + TCP_HEADER_LEN + 0] = 't' as u8;
    packet[IPV6_HEADER_LEN + TCP_HEADER_LEN + 1] = 'e' as u8;
    packet[IPV6_HEADER_LEN + TCP_HEADER_LEN + 2] = 's' as u8;
    packet[IPV6_HEADER_LEN + TCP_HEADER_LEN + 3] = 't' as u8;

    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV6_HEADER_LEN..]).unwrap();
        tcp_header.set_source(12345);
        assert_eq!(tcp_header.get_source(), 12345);

        tcp_header.set_destination(54321);
        assert_eq!(tcp_header.get_destination(), 54321);

        tcp_header.set_sequence(3456);
        assert_eq!(tcp_header.get_sequence(), 3456);

        tcp_header.set_acknowledgement(7799);
        assert_eq!(tcp_header.get_acknowledgement(), 7799);
    }

    let ref_packet = [0x30, 0x39,  // source
                      0xd4, 0x31,  // destination
                      0x00, 0x00,  // sequence
                      0x0d, 0x80,
                      0x00, 0x00,  // acknowledgement
                      0x1e, 0x77];

    assert_eq!(&ref_packet[..], &packet[IPV6_HEADER_LEN .. IPV6_HEADER_LEN + TCP_HEADER_LEN]);
}
