// Copyright (c) 2015 David Stainton <dstainton415@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! TCP packet abstraction

use packet::Packet;
use packet::HasPseudoheader;
use packet::checksum::rfc1071_checksum;
use pnet_macros::types::*;

/// Represents a TCP Packet
#[packet]
pub struct Tcp {
    source: u16be,
    destination: u16be,
    sequence: u32be,
    acknowledgement: u32be,
    data_offset_and_reserved: u8,
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
    let mut v = tcp.get_data_offset_and_reserved();
    v  = v >> 4; // get rid of reserved bits
    v = v - 5; // remove the size of the minimal tcp header of 20 bytes
    v = v * 4; // multiple the remaining word count by 4 to get the byte count
    return v as usize;
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
    return tcp.get_data_offset_and_reserved() as usize % 4;
}

/// Represents the TCP header padding
#[packet]
pub struct TcpPadding {
    #[payload]
    data: Vec<u8>
}

/// Calculates the checksum of a TCP packet
/// The passed in TcpPacket must have it's initial checksum value set to zero.
pub fn checksum<'a, T: HasPseudoheader>(packet: &TcpPacket<'a>, encapsulating_packet: T) -> u16be {
    let mut sum = encapsulating_packet.pseudoheader_checksum();
    let length = packet.packet().len() as u32;
    sum = sum + length & 0xffff;
    sum = sum + length >> 16;
    return rfc1071_checksum(packet.packet(), sum);
}


#[cfg(test)]
mod tests {
    use super::*;

    const TCP_MIN_HEADER_LEN: usize = 20;
    const TCP_OPTIONS_LEN: usize = 12;
    const PAYLOAD_LEN: usize = 5;

    #[test]
    fn tcp_header_ipv4_test() {
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::packet::ipv4::{Ipv4Packet,MutableIpv4Packet};
        use std::net::{Ipv4Addr};

        const IPV4_HEADER_LEN: usize = 20;

        let mut packet = [0u8; IPV4_HEADER_LEN + TCP_MIN_HEADER_LEN + TCP_OPTIONS_LEN + PAYLOAD_LEN];
        let ipv4_source = Ipv4Addr::new(127, 0, 0, 1);
        let ipv4_destination = Ipv4Addr::new(127, 0, 0, 1);
        let next_level_protocol = IpNextHeaderProtocols::Tcp;
        let mut csum = 0;

        {
            let mut mut_ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
            mut_ip_header.set_next_level_protocol(next_level_protocol);
            mut_ip_header.set_source(ipv4_source);
            mut_ip_header.set_destination(ipv4_destination);
        }

        {
            let mut mutable_tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
            mutable_tcp_header.set_checksum(0);
        }

        {
            let ip_header = Ipv4Packet::new(&packet[..IPV4_HEADER_LEN]).unwrap();
            let tcp_header = TcpPacket::new(&packet[IPV4_HEADER_LEN..]).unwrap();
            csum = checksum(&tcp_header, ip_header);
        }

        {
            let mut mutable_tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
            mutable_tcp_header.set_checksum(csum);
        }

        {
            generate_simple_tcp_header(&mut packet[IPV4_HEADER_LEN..]);
        }

        // Set payload data
        packet[IPV4_HEADER_LEN + TCP_MIN_HEADER_LEN + TCP_OPTIONS_LEN + 0] = 'm' as u8;
        packet[IPV4_HEADER_LEN + TCP_MIN_HEADER_LEN + TCP_OPTIONS_LEN + 1] = 'e' as u8;
        packet[IPV4_HEADER_LEN + TCP_MIN_HEADER_LEN + TCP_OPTIONS_LEN + 2] = 'o' as u8;
        packet[IPV4_HEADER_LEN + TCP_MIN_HEADER_LEN + TCP_OPTIONS_LEN + 3] = 'w' as u8;
        packet[IPV4_HEADER_LEN + TCP_MIN_HEADER_LEN + TCP_OPTIONS_LEN + 4] = '\n' as u8;

        let ref_tcp_packet = [0xe0, 0x0f, // source port
                              0x25, 0xc2, // dest port
                              0xdf, 0x06, // sequence
                              0xe6, 0xe6,
                              0xc9, 0x2d, // acknowledgement
                              0x98, 0x71,
                              0x80,       // header length + reserved
                              0x18,       // control bits
                              0x02, 0xab, // window
                              0xfe, 0x2d, // checksum
                              0x00, 0x00, // urgent pointer
                              0x01, 0x01, // tcp option no-op
                              0x08, 0x0a, // tcp option timestamp, options length == 10 bytes
                              0x1d, 0xfc, // 4-byte send timestamp
                              0xcb, 0x76,
                              0x1d, 0xfc, // 4-byte latest replied timestamp
                              0xbe, 0x62,
                              0x6d, 0x65, // payload
                              0x6f, 0x77, 0x0a];
        assert_eq!(&ref_tcp_packet[..], &packet[IPV4_HEADER_LEN..]);

        //tcp/ipv4 == "45, 00 00 39 58 89 40 00 40 06 e4 33 7f 00 00 01 7f 00 00 01 e0 0f 25 c2 df 06 e6 e6 c9 2d 98 71 80 18 02 ab fe 2d 00 00 01 01 08 0a 1d fc cb 76 1d fc be 62 6d 65 6f 77 0a";

    }

    fn generate_simple_tcp_header<'p>(packet: &'p mut [u8]) {
        let mut tcp_header = MutableTcpPacket::new(&mut packet[..]).unwrap();
        tcp_header.set_source(57359);
        assert_eq!(tcp_header.get_source(), 57359);

        tcp_header.set_destination(9666);
        assert_eq!(tcp_header.get_destination(), 9666);

        tcp_header.set_sequence(3741771494);
        assert_eq!(tcp_header.get_sequence(), 3741771494);

        tcp_header.set_acknowledgement(3375208561);
        assert_eq!(tcp_header.get_acknowledgement(), 3375208561);

        tcp_header.set_data_offset_and_reserved(0x80);
        assert_eq!(tcp_header.get_data_offset_and_reserved(), 0x80);

        tcp_header.set_control_bits(0x18);
        assert_eq!(tcp_header.get_control_bits(), 0x18);

        tcp_header.set_window(0x02ab);
        assert_eq!(tcp_header.get_window(), 0x02ab);

        tcp_header.set_checksum(0xfe2d);
        assert_eq!(tcp_header.get_checksum(), 0xfe2d);

        tcp_header.set_urgent_pointer(0x0000);
        assert_eq!(tcp_header.get_urgent_pointer(), 0x0000);

        let tcp_option = TcpOptions{
            kind: 0x1,
            data: vec![0x01,0x08,0x0a,0x1d,0xfc,0xcb,0x76,0x1d,0xfc,0xbe,0x62],
        };
        let mut options: Vec<TcpOptions> = vec![tcp_option];
        tcp_header.set_options(options);
    }
}
