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
    #[payload]
    payload: Vec<u8>
}


#[test]
fn tcp_header_ipv4_test() {
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::MutableIpv4Packet;

    let mut packet = [0u8; 20 + 8 + 4];
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
    packet[20 + 8 + 0] = 't' as u8;
    packet[20 + 8 + 1] = 'e' as u8;
    packet[20 + 8 + 2] = 's' as u8;
    packet[20 + 8 + 3] = 't' as u8;

    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[20..]).unwrap();
        tcp_header.set_source(12345);
        assert_eq!(tcp_header.get_source(), 12345);

        tcp_header.set_destination(54321);
        assert_eq!(tcp_header.get_destination(), 54321);

    }

    let ref_packet = [0x30, 0x39, /* source */
                     0xd4, 0x31];  /* destination */
    assert_eq!(&ref_packet[..], &packet[20 .. 24]);
}

#[test]
fn tcp_header_ipv6_test() {
    use packet::ip::{IpNextHeaderProtocols};
    use packet::ipv6::{MutableIpv6Packet};

    let mut packet = [0u8; 40 + 8 + 4];
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
    packet[40 + 8 + 0] = 't' as u8;
    packet[40 + 8 + 1] = 'e' as u8;
    packet[40 + 8 + 2] = 's' as u8;
    packet[40 + 8 + 3] = 't' as u8;

    {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[40..]).unwrap();
        tcp_header.set_source(12345);
        assert_eq!(tcp_header.get_source(), 12345);

        tcp_header.set_destination(54321);
        assert_eq!(tcp_header.get_destination(), 54321);
    }

    let ref_packet = [0x30, 0x39,  /* source */
                     0xd4, 0x31];  /* destination */
    assert_eq!(&ref_packet[..], &packet[40 .. 44]);
}
