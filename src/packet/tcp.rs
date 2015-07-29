// Copyright (c) 2015 David Stainton <dstainton415@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TCP packet abstraction

use pnet_macros::types::*;

/// Represents a TCP Packet
#[packet]
pub struct Tcp {
    source: u16be,
    destination: u16be,
    sequence: u32be,
    acknowledgement: u32be,
    data_offset: u4,
    reserved: u4,
    control_bits: u8,
    window: u16be,
    checksum: u16be,
    urgent_pointer: u16be,
    #[length_fn = "tcp_options_length"]
    options: Vec<TcpOptions>,
    #[length_fn = "tcp_padding_length"]
    padding: Vec<TcpPadding>,
    #[payload]
    payload: Vec<u8>
}

fn tcp_options_length<'a>(tcp: &TcpPacket<'a>) -> usize {
    /* The data offset field specifies the total size of the TCP header
       in 32-bit words. The minimum size of a TCP header is 20 bytes and thus
       TCP headers must have data offset set to 5 or more.
     */
    let size = tcp.get_data_offset() as usize;
    return (size - 5) * 4
}

/// Represents the TCP Option fields
#[packet]
pub struct TcpOptions {
    kind: u8,
    #[payload]
    data: Vec<u8>
}

fn tcp_padding_length<'a>(tcp: &TcpPacket<'a>) -> usize {
    /* The TCP header padding is used to ensure that the entire header
       ends on a 32 bit boundary.
     */
    return tcp.get_data_offset() as usize % 4;
}

/// Represents the TCP header padding
#[packet]
pub struct TcpPadding {
    #[payload]
    data: Vec<u8>
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP_HEADER_LEN: usize = 20;
    const TCP_OPTIONS_LEN: usize = 4;
    const PAYLOAD_LEN: usize = 4;

    #[test]
    fn tcp_header_ipv4_test() {
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::ipv4::MutableIpv4Packet;
        use std::net::{Ipv4Addr};

        const IPV4_HEADER_LEN: usize = 20;

        let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + PAYLOAD_LEN + TCP_OPTIONS_LEN];
        let ipv4_source = Ipv4Addr::new(192, 168, 0, 1);
        let ipv4_destination = Ipv4Addr::new(192, 168, 0, 199);
        let next_level_protocol = IpNextHeaderProtocols::Tcp;
        {
            let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
            ip_header.set_next_level_protocol(next_level_protocol);
            ip_header.set_source(ipv4_source);
            ip_header.set_destination(ipv4_destination);
        }

        generate_tcp_and_payload(&mut packet[IPV4_HEADER_LEN..]);
    }


    #[test]
    fn tcp_header_ipv6_test() {
        use packet::ip::{IpNextHeaderProtocols};
        use packet::ipv6::{MutableIpv6Packet};
        use std::net::{Ipv6Addr};

        const IPV6_HEADER_LEN: usize = 40;
        const OPTIONS_LEN: usize = 2;

        let mut packet = [0u8; IPV6_HEADER_LEN + TCP_HEADER_LEN + OPTIONS_LEN + PAYLOAD_LEN];
        let next_header = IpNextHeaderProtocols::Tcp;
        let ipv6_source = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        let ipv6_destination = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
        {
            let mut ip_header = MutableIpv6Packet::new(&mut packet[..]).unwrap();
            ip_header.set_next_header(next_header);
            ip_header.set_source(ipv6_source);
            ip_header.set_destination(ipv6_destination);
        }

        generate_tcp_and_payload(&mut packet[IPV6_HEADER_LEN..]);
    }

    #[test]
    fn tcp_padding_test() {
        const OPTIONS_LEN: usize = 2;
        const PADDING_LEN: usize = 2;

        let mut packet = [0u8; TCP_HEADER_LEN + TCP_OPTIONS_LEN + PADDING_LEN];
        generate_tcp_with_options_and_padding(&mut packet[..]);

        let ref_packet = [0x30, 0x39,  // source
                          0xd4, 0x31,  // destination
                          0x00, 0x00,  // sequence
                          0x0d, 0x80,
                          0x00, 0x00,  // acknowledgement
                          0x1e, 0x77,
                          0x70,        // header length + reserved
                          0x03,        // control bits
                          0x45, 0x66,  // window
                          0x66, 0x99,  // checksum
                          0x11, 0x22,  // urgent pointer
                          0x00, 0x00,  // TCP Options + padding
                          0x00, 0x00];

        assert_eq!(&ref_packet[..], &packet[.. TCP_HEADER_LEN + OPTIONS_LEN + PADDING_LEN]);
    }

    fn generate_tcp_with_options(packet: &mut [u8]) {

        let mut packet, tcp_header = generate_simple_tcp_header(packet);
        /*
           compose a TCP header with the options section set
         */
        let mut opts: Vec<TcpOptions> = Vec::new();
        let tcp_option = TcpOptions{
            kind: 0x0,
            data: vec![0x01,0x01,0x01],
        };
        opts.push(tcp_option);
        tcp_header.set_options(opts);
    }

    fn generate_tcp_and_payload(packet: &mut [u8]) {
        let mut packet, tcp_header = generate_simple_tcp_header(packet);

        // Set payload data
        packet[TCP_HEADER_LEN + 0] = 't' as u8;
        packet[TCP_HEADER_LEN + 1] = 'e' as u8;
        packet[TCP_HEADER_LEN + 2] = 's' as u8;
        packet[TCP_HEADER_LEN + 3] = 't' as u8;

        let ref_packet = [0x30, 0x39,  // source
                          0xd4, 0x31,  // destination
                          0x00, 0x00,  // sequence
                          0x0d, 0x80,
                          0x00, 0x00,  // acknowledgement
                          0x1e, 0x77,
                          0x50,        // header length + reserved
                          0x03,        // control bits
                          0x45, 0x66,  // window
                          0x66, 0x99,  // checksum
                          0x11, 0x22]; // urgent pointer
        assert_eq!(&ref_packet[..], &packet[.. TCP_HEADER_LEN]);


        generate_tcp_with_options(packet);

        let ref_packet = [0x30, 0x39,  // source
                          0xd4, 0x31,  // destination
                          0x00, 0x00,  // sequence
                          0x0d, 0x80,
                          0x00, 0x00,  // acknowledgement
                          0x1e, 0x77,
                          0x70,        // header length + reserved
                          0x03,        // control bits
                          0x45, 0x66,  // window
                          0x66, 0x99,  // checksum
                          0x11, 0x22,  // urgent pointer
                          0x00, 0x01,  // TCP Options
                          0x01, 0x01];

        assert_eq!(&ref_packet[..], &packet[.. TCP_HEADER_LEN + TCP_OPTIONS_LEN]);
    }

    fn generate_tcp_with_options_and_padding(packet: &mut [u8]) {

        let mut packet, tcp_header = generate_simple_tcp_header(packet);
        /*
           compose a TCP header with the options section set
           with non-32bit boundary... so that padding is required.
         */
        let mut opts: Vec<TcpOptions> = Vec::new();
        let tcp_option = TcpOptions{
            kind: 0x0,
            data: vec![0x01],
        };
        opts.push(tcp_option);
        tcp_header.set_options(opts);

        let mut padding: Vec<TcpPadding> = Vec::new();
        let tcp_padding = TcpPadding{
            data: vec![0x00,0x00],
        };
        padding.push(tcp_padding);
        tcp_header.set_padding(padding);
    }

    fn generate_simple_tcp_header(packet: &mut [u8]) -> &mut MutableTcpPacket {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[..]).unwrap();
        tcp_header.set_source(12345);
        assert_eq!(tcp_header.get_source(), 12345);

        tcp_header.set_destination(54321);
        assert_eq!(tcp_header.get_destination(), 54321);

        tcp_header.set_sequence(3456);
        assert_eq!(tcp_header.get_sequence(), 3456);

        tcp_header.set_acknowledgement(7799);
        assert_eq!(tcp_header.get_acknowledgement(), 7799);

        tcp_header.set_data_offset(0x7);
        assert_eq!(tcp_header.get_data_offset(), 0x7);

        tcp_header.set_reserved(0x0);
        assert_eq!(tcp_header.get_reserved(), 0x0);

        tcp_header.set_control_bits(0x03);
        assert_eq!(tcp_header.get_control_bits(), 0x03);

        tcp_header.set_window(0x4566);
        assert_eq!(tcp_header.get_window(), 0x4566);

        tcp_header.set_checksum(0x6699);
        assert_eq!(tcp_header.get_checksum(), 0x6699);

        tcp_header.set_urgent_pointer(0x1122);
        assert_eq!(tcp_header.get_urgent_pointer(), 0x1122);

        packet, tcp_header
    }
}
