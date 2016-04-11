// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate libc;

use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use std::sync::mpsc::channel;
use std::thread;
use std::iter::Iterator;

use packet::Packet;
use packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use packet::ipv4;
use packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use packet::udp::{UdpPacket, MutableUdpPacket};
use transport::{TransportChannelType, TransportProtocol, ipv4_packet_iter, transport_channel,
                udp_packet_iter};
use transport::TransportProtocol::{Ipv4, Ipv6};
use util::{IpAddr, checksum};


const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const TEST_DATA_LEN: usize = 4;

fn ipv4_source() -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, 1)
}

fn ipv4_destination() -> Ipv4Addr {
    Ipv4Addr::new(127, 0, 0, 1)
}

fn ipv6_source() -> Ipv6Addr {
    Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)
}

fn ipv6_destination() -> Ipv6Addr {
    Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)
}

// Use a protocol which is unlikely to have other packets on
const TEST_PROTO: IpNextHeaderProtocol = IpNextHeaderProtocols::Test1;

fn build_ipv4_header(packet: &mut [u8], offset: usize) {
    let mut ip_header = MutableIpv4Packet::new(&mut packet[offset..]).unwrap();

    let total_len = (IPV4_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN) as u16;

    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_total_length(total_len);
    ip_header.set_ttl(4);
    ip_header.set_next_level_protocol(TEST_PROTO);
    ip_header.set_source(ipv4_source());
    ip_header.set_destination(ipv4_destination());
    let checksum = ipv4::checksum(&ip_header.to_immutable());
    ip_header.set_checksum(checksum);
}

fn build_ipv6_header(packet: &mut [u8], offset: usize) {
    let mut ip_header = MutableIpv6Packet::new(&mut packet[offset..]).unwrap();

    ip_header.set_version(6);
    ip_header.set_payload_length((UDP_HEADER_LEN + TEST_DATA_LEN) as u16);
    ip_header.set_next_header(TEST_PROTO);
    ip_header.set_hop_limit(4);
    ip_header.set_source(ipv6_source());
    ip_header.set_destination(ipv6_destination());
}

fn build_udp_header(packet: &mut [u8], offset: usize) {
    let mut udp_header = MutableUdpPacket::new(&mut packet[offset..]).unwrap();

    udp_header.set_source(1234); // Arbitary port number
    udp_header.set_destination(1234);
    udp_header.set_length((UDP_HEADER_LEN + TEST_DATA_LEN) as u16);
}


fn build_udp4_packet(packet: &mut [u8],
                     start: usize,
                     msg: &str) {
    build_ipv4_header(packet, start);
    build_udp_header(packet, start + IPV4_HEADER_LEN as usize);

    let msg = msg.as_bytes();

    let data_start = start + IPV4_HEADER_LEN + UDP_HEADER_LEN;
    packet[data_start] = msg[0];
    packet[data_start + 1] = msg[1];
    packet[data_start + 2] = msg[2];
    packet[data_start + 3] = msg[3];

    let (raw_ip_header, raw_udp_packet) = packet.split_at_mut(20);
    let ip_header = Ipv4Packet::new(&raw_ip_header[..]).unwrap();
    let pseudo_header = ip_header.get_pseudo_header(packet.get_length() as u32);
    let csum = util::rfc1071_checksum(&raw_udp_packet, Some(&pseudo_header[..]));
    MutableUdpPacket::new(raw_udp_packet).unwrap().set_checksum(csum);
}

fn build_udp6_packet(packet: &mut [u8], start: usize, msg: &str) {
    build_ipv6_header(packet, start);
    build_udp_header(packet, start + IPV6_HEADER_LEN as usize);

    let msg = msg.as_bytes();

    let data_start = start + IPV6_HEADER_LEN + UDP_HEADER_LEN;
    packet[data_start] = msg[0];
    packet[data_start + 1] = msg[1];
    packet[data_start + 2] = msg[2];
    packet[data_start + 3] = msg[3];

    let (raw_ip_header, raw_udp_packet) = packet.split_at_mut(40);
    let ip_header = Ipv6Packet::new(&raw_ip_header[..]).unwrap(); // XXX
    let pseudo_header = ip_header.get_pseudo_header(Some(packet.get_length() as u32));
    let csum = util::rfc1071_checksum(&raw_udp_packet, Some(&pseudo_header[..]));
    MutableUdpPacket::new(raw_udp_packet).unwrap().set_checksum(csum);
}

// OSes have a nasty habit of tweaking IP fields, so we only check
// the less volatile fields (identification, checksum)
fn check_ipv4_header(packet: &[u8], header: &Ipv4Packet) {
    let ipv4_header = Ipv4Packet::new(packet).unwrap();

    assert_eq!(header.get_version(), ipv4_header.get_version());
    assert_eq!(header.get_header_length(), ipv4_header.get_header_length());
    assert_eq!(header.get_dscp(), ipv4_header.get_dscp());
    assert_eq!(header.get_ecn(), ipv4_header.get_ecn());
    assert_eq!(header.get_total_length(), ipv4_header.get_total_length());
    assert_eq!(header.get_flags(), ipv4_header.get_flags());
    assert_eq!(header.get_fragment_offset(),
               ipv4_header.get_fragment_offset());
    assert_eq!(header.get_ttl(), ipv4_header.get_ttl());
    assert_eq!(header.get_next_level_protocol(),
               ipv4_header.get_next_level_protocol());
    assert_eq!(header.get_source(), ipv4_header.get_source());
    assert_eq!(header.get_destination(), ipv4_header.get_destination());
}

fn layer4(ip: IpAddr, header_len: usize) {
    let mut packet = [0u8; IPV6_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN];
    let packet_len = header_len + UDP_HEADER_LEN + TEST_DATA_LEN;

    match ip {
        IpAddr::V4(..) => {
            build_udp4_packet(&mut packet[..], 0, "l4i4")
        }
        IpAddr::V6(..) => {
            build_udp6_packet(&mut packet[..], 0, "l4i6")
        }
    };

    let udp = UdpPacket::new(&packet[header_len..packet_len]).unwrap();

    let (tx, rx) = channel();

    let tc = transport_channel(128, TransportChannelType::Layer4(get_proto(ip)));
    let (mut ttx, mut trx) = match tc {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("layer4: unable to create channel: {}", e),
    };

    let res = thread::spawn(move || {
        tx.send(()).unwrap();
        let mut iter = udp_packet_iter(&mut trx);
        loop {
            let next = iter.next();
            match next {
                Ok((header, addr)) => {
                    assert_eq!(addr, ip);
                    assert_eq!(header,
                               UdpPacket::new(&packet[header_len..packet_len]).unwrap());
                    break;
                }
                Err(e) => {
                    panic!("Receive failed for layer4_test(): {}", e);
                }
            }

        }
    });

    rx.recv().unwrap();
    match ttx.send_to(udp, ip) {
        Ok(res) => assert_eq!(res as usize, UDP_HEADER_LEN + TEST_DATA_LEN),
        Err(e) => panic!("layer4_test failed: {}", e),
    }

    fn get_proto(ip: IpAddr) -> TransportProtocol {
        match ip {
            IpAddr::V4(..) => Ipv4(TEST_PROTO),
            IpAddr::V6(..) => Ipv6(TEST_PROTO),
        }
    }

    assert!(res.join().is_ok())
}

#[test]
#[cfg(not(feature = "appveyor"))]
fn layer4_ipv4() {
    layer4(IpAddr::V4(ipv4_source()), IPV4_HEADER_LEN as usize);
}

// travis does not currently support IPv6
#[test]
#[cfg(all(not(feature = "appveyor"),
          not(all(target_os = "linux", feature = "travis"))))]
fn layer4_ipv6() {
    layer4(IpAddr::V6(ipv6_source()), IPV6_HEADER_LEN);
}

#[test]
#[cfg(not(feature = "appveyor"))]
fn layer3_ipv4() {
    let send_addr = IpAddr::V4(ipv4_source());
    let mut packet = [0u8; IPV4_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN];

    build_udp4_packet(&mut packet[..], 0, "l3i4");

    let (tx, rx) = channel();

    let tc = transport_channel(IPV4_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN,
                               TransportChannelType::Layer3(TEST_PROTO));
    let (mut ttx, mut trx) = match tc {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("layer3: unable to create channel: {}", e),
    };

    let res = thread::spawn(move || {
        tx.send(()).unwrap();
        let mut iter = ipv4_packet_iter(&mut trx);
        loop {
            let next = iter.next();
            match next {
                Ok((header, addr)) => {
                    assert_eq!(addr, send_addr);
                    check_ipv4_header(&packet[..], &header);
                    let udp_header =
                        UdpPacket::new(&header.packet()[(header.get_header_length() as usize *
                                                         4usize)..])
                            .unwrap();
                    assert_eq!(udp_header,
                               UdpPacket::new(&packet[IPV4_HEADER_LEN..]).unwrap());

                    assert_eq!(&udp_header.packet()[UDP_HEADER_LEN..],
                               &packet[IPV4_HEADER_LEN + UDP_HEADER_LEN..]);
                    break;
                }
                Err(e) => {
                    panic!("receive failed for layer3_ipv4_test(): {}", e);
                }
            }
        }
    });


    rx.recv().unwrap();
    match ttx.send_to(Ipv4Packet::new(&packet[..]).unwrap(), send_addr) {
        Ok(res) => assert_eq!(res as usize, packet.len()),
        Err(e) => panic!("layer3_ipv4_test failed: {}", e),
    }

    assert!(res.join().is_ok())
}

// FIXME Find a way to test this with netmap
#[cfg(all(not(feature = "appveyor"), not(feature = "netmap")))]
#[test]
fn layer2() {
    use datalink::{DataLinkChannelType, datalink_channel};
    use packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};

    const MIN_PACKET_SIZE: usize = 64;
    const ETHERNET_HEADER_LEN: usize = 14;

    #[cfg(windows)]
    fn get_test_interface() -> util::NetworkInterface {
        use std::clone::Clone;
        use std::env;
        let interfaces = util::get_network_interfaces();

        interfaces.iter()
                  .filter(|x| {
                      match env::var("PNET_TEST_IFACE") {
                          Ok(name) => x.name == name,
                          Err(_) => true,
                      }
                  })
                  .next()
                  .unwrap()
                  .clone()
    }

    #[cfg(not(windows))]
    fn get_test_interface() -> util::NetworkInterface {
        use std::clone::Clone;
        use std::env;
        let interfaces = util::get_network_interfaces();

        interfaces.iter()
                  .filter(|x| {
                      match env::var("PNET_TEST_IFACE") {
                          Ok(name) => x.name == name,
                          Err(_) => x.is_loopback(),
                      }
                  })
                  .next()
                  .unwrap()
                  .clone()
    }

    let interface = get_test_interface();

    let mut packet = [0u8; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN];

    {
        let mut ethernet_header = MutableEthernetPacket::new(&mut packet[..]).unwrap();
        ethernet_header.set_source(interface.mac_address());
        ethernet_header.set_destination(interface.mac_address());
        ethernet_header.set_ethertype(EtherTypes::Ipv4);
    }

    build_udp4_packet(&mut packet[..],
                      ETHERNET_HEADER_LEN as usize,
                      "l2tt");

    let (tx, rx) = channel();

    let dlc = datalink_channel(&interface,
                               MIN_PACKET_SIZE * 2,
                               MIN_PACKET_SIZE * 2,
                               DataLinkChannelType::Layer2);
    let (mut dltx, mut dlrx) = match dlc {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("layer2: unable to create channel: {}", e),
    };

    let res = thread::spawn(move || {
        tx.send(()).unwrap();
        let mut i = 0usize;
        let mut iter = dlrx.iter();
        loop {
            let next = iter.next();
            match next {
                Ok(eh) => {
                    if i == 10_000 {
                        panic!("layer2: did not find matching packet after 10_000 iterations");
                    }
                    if EthernetPacket::new(&packet[..]).unwrap() == eh {
                        return;
                    }
                    i += 1;
                }
                Err(e) => {
                    panic!("layer2 failed: {}", e);
                }
            }
        }
    });

    rx.recv().unwrap();
    match dltx.send_to(&EthernetPacket::new(&packet[..]).unwrap(), None) {
        Some(Ok(())) => (),
        Some(Err(e)) => panic!("layer2_test failed: {}", e),
        None => panic!("Provided buffer too small"),
    }

    assert!(res.join().is_ok())
}

#[test]
fn check_test_environment() {
    use std::env;
    let tasks = env::var("RUST_TEST_THREADS");
    if !tasks.is_ok() || &tasks.unwrap()[..] != "1" {
        panic!("Tests must be run with environment variable RUST_TEST_THREADS=1");
    }

    test_iface();

    #[cfg(all(not(windows), not(target_os = "linux")))]
    fn test_iface() {
        let iface = env::var("PNET_TEST_IFACE");
        if !iface.is_ok() {
            panic!("The environment variable PNET_TEST_IFACE must be set.");
        }
    }

    #[cfg(any(windows, target_os = "linux"))]
    fn test_iface() {
    }
}
