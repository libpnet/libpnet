// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! IPv6 packet abstraction

use packet::ip::IpNextHeaderProtocol;

use pnet_macros::types::*;

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
    payload: Vec<u8>
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
    assert_eq!(&ref_packet[..], &packet[..]);
}

