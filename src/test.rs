// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate libc;

use std::clone::Clone;
use std::result::{Ok, Err};
use std::option::{Some};
use std::task::try_future;
use std::io::net::ip::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::iter::Iterator;

use datalink::{datalink_channel};
use packet::Packet;
use packet::ethernet::{EtherTypes, EthernetHeader, MutableEthernetHeader, EthernetPacket};
use packet::ip::{IpNextHeaderProtocols, IpNextHeaderProtocol};
use packet::ipv4::{Ipv4Header, MutableIpv4Header, Ipv4Packet};
use packet::ipv6::{MutableIpv6Header, Ipv6Packet};
use packet::udp::{UdpHeader, MutableUdpHeader, UdpPacket};
use transport::{udp_header_iter, ipv4_header_iter, transport_channel, TransportProtocol, Ipv4, Ipv6};
use transport;
use datalink;
use util::NetworkInterface;

const MIN_PACKET_SIZE: uint = 64;
const ETHERNET_HEADER_LEN: uint = 14;
const IPV4_HEADER_LEN: uint = 20;
const IPV6_HEADER_LEN: uint = 40;
const UDP_HEADER_LEN: uint = 8;
const TEST_DATA_LEN: uint = 4;

const IPV4_SOURCE: IpAddr = Ipv4Addr(127, 0, 0, 1);
const IPV4_DESTINATION: IpAddr = Ipv4Addr(127, 0, 0, 1);
const IPV6_SOURCE: IpAddr = Ipv6Addr(0, 0, 0, 0, 0, 0, 0, 1);
const IPV6_DESTINATION: IpAddr = Ipv6Addr(0, 0, 0, 0, 0, 0, 0, 1);

// Use a protocol which is unlikely to have other packets on
const TEST_PROTO: IpNextHeaderProtocol = IpNextHeaderProtocols::Test1;

fn build_ipv4_header(packet: &mut [u8], offset: uint) {
    let mut ip_header = MutableIpv4Header::new(packet.slice_from_mut(offset));

    let total_len = (IPV4_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN) as u16;

    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(total_len);
    ip_header.set_ttl(4);
    ip_header.set_next_level_protocol(TEST_PROTO);
    ip_header.set_source(IPV4_SOURCE);
    ip_header.set_destination(IPV4_DESTINATION);
    ip_header.checksum();
}

fn build_ipv6_header(packet: &mut [u8], offset: uint) {
    let mut ip_header = MutableIpv6Header::new(packet.slice_from_mut(offset));

    ip_header.set_version(6);
    ip_header.set_payload_length((UDP_HEADER_LEN + TEST_DATA_LEN) as u16);
    ip_header.set_next_header(TEST_PROTO);
    ip_header.set_hop_limit(4);
    ip_header.set_source(IPV6_SOURCE);
    ip_header.set_destination(IPV6_DESTINATION);
}

fn build_udp_header(packet: &mut [u8], offset: uint) {
    let mut udp_header = MutableUdpHeader::new(packet.slice_from_mut(offset));

    udp_header.set_source(1234); // Arbitary port number
    udp_header.set_destination(1234);
    udp_header.set_length((UDP_HEADER_LEN + TEST_DATA_LEN) as u16);
}

fn build_udp4_packet(packet: &mut [u8], start: uint, msg: &str) {
    build_ipv4_header(packet, start);
    build_udp_header(packet, start + IPV4_HEADER_LEN as uint);

    let data_start = start + IPV4_HEADER_LEN + UDP_HEADER_LEN;
    packet[data_start + 0] = msg.char_at(0) as u8;
    packet[data_start + 1] = msg.char_at(1) as u8;
    packet[data_start + 2] = msg.char_at(2) as u8;
    packet[data_start + 3] = msg.char_at(3) as u8;

    let slice = packet.slice_from_mut(start + IPV4_HEADER_LEN as uint);
    MutableUdpHeader::new(slice).checksum(IPV4_SOURCE, IPV4_DESTINATION, TEST_PROTO);
}

fn build_udp6_packet(packet: &mut [u8], start: uint, msg: &str) {
    build_ipv6_header(packet, start);
    build_udp_header(packet, start + IPV6_HEADER_LEN as uint);

    let data_start = start + IPV6_HEADER_LEN + UDP_HEADER_LEN;
    packet[data_start + 0] = msg.char_at(0) as u8;
    packet[data_start + 1] = msg.char_at(1) as u8;
    packet[data_start + 2] = msg.char_at(2) as u8;
    packet[data_start + 3] = msg.char_at(3) as u8;

    let slice = packet.slice_from_mut(start + IPV6_HEADER_LEN as uint);
    MutableUdpHeader::new(slice).checksum(IPV6_SOURCE, IPV6_DESTINATION, TEST_PROTO);
}

fn get_test_interface() -> NetworkInterface {
    use std::os::getenv;
    use util;

    (*util::get_network_interfaces()
        .as_slice().iter()
        .filter(|x| {
            match getenv("PNET_TEST_IFACE") {
                Some(name) => x.name == name,
                None => x.is_loopback()
            }
        })
        .next()
        .unwrap())
        .clone()
}

// OSes have a nasty habit of tweaking IP fields, so we only check
// the less volatile fields (identification, checksum)
fn check_ipv4_header(packet: &[u8], header: Ipv4Header) {
    let ipv4_header = Ipv4Header::new(packet);

    assert_eq!(header.get_version(), ipv4_header.get_version());
    assert_eq!(header.get_header_length(), ipv4_header.get_header_length());
    assert_eq!(header.get_dscp(), ipv4_header.get_dscp());
    assert_eq!(header.get_ecn(), ipv4_header.get_ecn());
    assert_eq!(header.get_total_length(), ipv4_header.get_total_length());
    assert_eq!(header.get_flags(), ipv4_header.get_flags());
    assert_eq!(header.get_fragment_offset(), ipv4_header.get_fragment_offset());
    assert_eq!(header.get_ttl(), ipv4_header.get_ttl());
    assert_eq!(header.get_next_level_protocol(), ipv4_header.get_next_level_protocol());
    assert_eq!(header.get_source(), ipv4_header.get_source());
    assert_eq!(header.get_destination(), ipv4_header.get_destination());
}

fn layer4(ip: IpAddr, header_len: uint) {
    let mut packet = [0u8, ..IPV6_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN];
    let packet_len = header_len + UDP_HEADER_LEN + TEST_DATA_LEN;

    match ip {
        Ipv4Addr(..) => {
            build_udp4_packet(packet.as_mut_slice(), 0, "l4i4")
        },
        Ipv6Addr(..) => {
            build_udp6_packet(packet.as_mut_slice(), 0, "l4i6")
        }
    };

    let udp = UdpHeader::new(packet.slice(header_len, packet_len));

    let (tx, rx) = channel();

    let (mut ttx, mut trx) = match transport_channel(128, transport::Layer4(get_proto(ip))) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("layer4: unable to create channel: {}", e),
    };

    let res = try_future( proc() {
        tx.send(());
        pfor!((header, addr) in udp_header_iter(&mut trx) {
            assert_eq!(addr, ip);
            assert_eq!(header, UdpHeader::new(packet.slice(header_len, packet_len)));
            break;
        } on Err(e) {
            panic!("Receive failed for layer4_test(): {}", e);
        })
    });

    rx.recv();
    match ttx.send_to(udp, ip) {
        Ok(res) => assert_eq!(res as uint, UDP_HEADER_LEN + TEST_DATA_LEN),
        Err(e) => panic!("layer4_test failed: {}", e)
    }

    fn get_proto(ip: IpAddr) -> TransportProtocol {
        match ip {
            Ipv4Addr(..) => Ipv4(TEST_PROTO),
            Ipv6Addr(..) => Ipv6(TEST_PROTO)
        }
    }

    match res.unwrap() {
        Err(e) => panic!(e),
        _ => ()
    }
}

#[test]
fn layer4_ipv4() {
    layer4(Ipv4Addr(127, 0, 0, 1), IPV4_HEADER_LEN as uint);
}

#[test]
fn layer4_ipv6() {
    layer4(Ipv6Addr(0, 0, 0, 0, 0, 0, 0, 1), IPV6_HEADER_LEN);
}

#[test]
fn layer3_ipv4() {
    let send_addr = Ipv4Addr(127, 0, 0, 1);
    let mut packet = [0u8, ..IPV4_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN];

    build_udp4_packet(packet.as_mut_slice(), 0, "l3i4");

    let (tx, rx) = channel();

    let tc =  transport_channel(IPV4_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN,
                                    transport::Layer3(TEST_PROTO));
    let (mut ttx, mut trx) = match tc {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("layer3: unable to create channel: {}", e),
    };

    let res = try_future( proc() {
        tx.send(());
        pfor!((header, addr) in ipv4_header_iter(&mut trx) {
            assert_eq!(addr, send_addr);
            check_ipv4_header(packet, header);
            let udp_header = UdpHeader::new(header.packet().slice_from(
                                           header.get_header_length() as uint * 4u));
            assert_eq!(udp_header, UdpHeader::new(packet.slice_from(IPV4_HEADER_LEN)));

            assert_eq!(udp_header.packet().slice_from(UDP_HEADER_LEN),
                       packet.slice_from(IPV4_HEADER_LEN + UDP_HEADER_LEN))
            break;
        } on Err(e) {
            panic!("receive failed for layer3_ipv4_test(): {}", e);
        })
    });


    rx.recv();
    match ttx.send_to(Ipv4Header::new(packet), send_addr) {
        Ok(res) => assert_eq!(res as uint, packet.len()),
        Err(e) => panic!("layer3_ipv4_test failed: {}", e)
    }

    match res.unwrap() {
        Err(e) => panic!(e),
        _ => ()
    }

}

#[test]
fn layer2() {
    let interface = get_test_interface();

    let mut packet = [0u8, ..ETHERNET_HEADER_LEN +
                             IPV4_HEADER_LEN +
                             UDP_HEADER_LEN +
                             TEST_DATA_LEN];

    {
        let mut ethernet_header = MutableEthernetHeader::new(packet.as_mut_slice());
        ethernet_header.set_source(interface.mac_address());
        ethernet_header.set_destination(interface.mac_address());
        ethernet_header.set_ethertype(EtherTypes::Ipv4);
    }

    build_udp4_packet(packet.as_mut_slice(), ETHERNET_HEADER_LEN as uint, "l2tt");

    let (tx, rx) = channel();

    let dlc = datalink_channel(&interface, MIN_PACKET_SIZE*2, MIN_PACKET_SIZE*2, datalink::Layer2);
    let (mut dltx, mut dlrx) = match dlc {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("layer2: unable to create channel: {}", e)
    };

    let res = try_future( proc() {
        tx.send(());
        let mut i = 0u;
        pfor!(eh in dlrx.iter() {
            if i == 10_000 {
                panic!("layer2: did not find matching packet after 10_000 iterations");
            }
            if EthernetHeader::new(packet) == eh {
                return;
            }
            i += 1;
        } on Err(e) {
            panic!("layer2 failed: {}", e);
        })
    });

    rx.recv();
    match dltx.send_to(EthernetHeader::new(packet), None) {
        Some(Ok(())) => (),
        Some(Err(e)) => panic!("layer2_test failed: {}", e),
        None => panic!("Provided buffer too small")
    }

    match res.unwrap() {
        Err(e) => panic!(e),
        _ => ()
    }
}

#[test]
fn check_test_environment() {
    use std::os;
    let tasks = os::getenv("RUST_TEST_TASKS");
    if !tasks.is_some() || tasks.unwrap().as_slice() != "1" {
        panic!("Tests must be run with environment variable RUST_TEST_TASKS=1");
    }

    test_iface();

    #[cfg(not(target_os = "linux"))]
    fn test_iface() {
        let iface = os::getenv("PNET_TEST_IFACE");
        if !iface.is_some() {
            panic!("The environment variable PNET_TEST_IFACE must be set.");
        }
    }

    #[cfg(target_os = "linux")]
    fn test_iface() {}
}
