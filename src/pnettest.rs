// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(warnings)]

use crate::datalink;

use crate::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use crate::packet::ipv4;
use crate::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use crate::packet::ipv6::MutableIpv6Packet;
use crate::packet::udp;
use crate::packet::udp::{MutableUdpPacket, UdpPacket};
use crate::packet::Packet;
use std::iter::Iterator;
use pnet_base::core_net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::channel;
use std::thread;
use crate::transport::TransportProtocol::{Ipv4, Ipv6};
use crate::transport::{
    ipv4_packet_iter, transport_channel, udp_packet_iter, TransportChannelType, TransportProtocol,
};

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
    let mut ip_header = MutableIpv4Packet::new(&mut packet[offset..]).expect("could not create MutableIpv4Packet");

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
    let mut ip_header = MutableIpv6Packet::new(&mut packet[offset..]).expect("could not create MutableIpv6Packet");

    ip_header.set_version(6);
    ip_header.set_payload_length((UDP_HEADER_LEN + TEST_DATA_LEN) as u16);
    ip_header.set_next_header(TEST_PROTO);
    ip_header.set_hop_limit(4);
    ip_header.set_source(ipv6_source());
    ip_header.set_destination(ipv6_destination());
}

fn build_udp_header(packet: &mut [u8], offset: usize) {
    let mut udp_header = MutableUdpPacket::new(&mut packet[offset..]).expect("could not create MutableUdpPacket");

    udp_header.set_source(1234); // Arbitrary port number
    udp_header.set_destination(1234);
    udp_header.set_length((UDP_HEADER_LEN + TEST_DATA_LEN) as u16);
}

fn is_ipv4(ip: &IpAddr) -> bool {
    if let IpAddr::V4(_) = *ip {
        true
    } else {
        false
    }
}

fn build_udp4_packet(
    packet: &mut [u8],
    start: usize,
    msg: &str,
    ni: Option<&datalink::NetworkInterface>,
) {
    build_ipv4_header(packet, start);
    build_udp_header(packet, start + IPV4_HEADER_LEN as usize);

    let msg = msg.as_bytes();

    let data_start = start + IPV4_HEADER_LEN + UDP_HEADER_LEN;
    packet[data_start] = msg[0];
    packet[data_start + 1] = msg[1];
    packet[data_start + 2] = msg[2];
    packet[data_start + 3] = msg[3];

    let (source, dest) = if let Some(ni) = ni {
        let ipmask = ni
            .ips
            .iter()
            .filter(|addr| is_ipv4(&addr.ip()))
            .next()
            .expect("could not find network interface with ipv4 addresses");
        match (ipmask.ip()).clone() {
            IpAddr::V4(v4) => (v4, v4),
            IpAddr::V6(_) => panic!("found ipv6 addresses when expecting ipv4 addresses"),
        }
    } else {
        (ipv4_source(), ipv4_destination())
    };

    let slice = &mut packet[(start + IPV4_HEADER_LEN as usize)..];
    let checksum = udp::ipv4_checksum(&UdpPacket::new(slice).expect("could not create UdpPacket"), &source, &dest);
    MutableUdpPacket::new(slice).expect("could not create MutableUdpPacket").set_checksum(checksum);
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

    let slice = &mut packet[(start + IPV6_HEADER_LEN as usize)..];
    let checksum = udp::ipv6_checksum(
        &UdpPacket::new(slice).expect("could not create UdpPacket"),
        &ipv6_source(),
        &ipv6_destination(),
    );
    MutableUdpPacket::new(slice).expect("could not create MutableUdpPacket").set_checksum(checksum);
}

// OSes have a nasty habit of tweaking IP fields, so we only check
// the less volatile fields (identification, checksum)
fn check_ipv4_header(packet: &[u8], header: &Ipv4Packet) {
    let ipv4_header = Ipv4Packet::new(packet).expect("could not create Ipv4Packet");

    assert_eq!(header.get_version(), ipv4_header.get_version());
    assert_eq!(header.get_header_length(), ipv4_header.get_header_length());
    assert_eq!(header.get_dscp(), ipv4_header.get_dscp());
    assert_eq!(header.get_ecn(), ipv4_header.get_ecn());
    assert_eq!(header.get_total_length(), ipv4_header.get_total_length());
    assert_eq!(header.get_flags(), ipv4_header.get_flags());
    assert_eq!(
        header.get_fragment_offset(),
        ipv4_header.get_fragment_offset()
    );
    assert_eq!(header.get_ttl(), ipv4_header.get_ttl());
    assert_eq!(
        header.get_next_level_protocol(),
        ipv4_header.get_next_level_protocol()
    );
    assert_eq!(header.get_source(), ipv4_header.get_source());
    assert_eq!(header.get_destination(), ipv4_header.get_destination());
}

fn layer4(ip: IpAddr, header_len: usize) {
    let mut packet = [0u8; IPV6_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN];
    let packet_len = header_len + UDP_HEADER_LEN + TEST_DATA_LEN;

    match ip {
        IpAddr::V4(..) => build_udp4_packet(&mut packet[..], 0, "l4i4", None),
        IpAddr::V6(..) => build_udp6_packet(&mut packet[..], 0, "l4i6"),
    };

    let udp = UdpPacket::new(&packet[header_len..packet_len]).expect("could not create UdpPacket");

    let (tx, rx) = channel();

    let tc = transport_channel(128, TransportChannelType::Layer4(get_proto(ip)));
    let (mut ttx, mut trx) = match tc {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("layer4: unable to create channel: {}", e),
    };

    let res = thread::spawn(move || {
        tx.send(()).expect("could not send message through channel");
        let mut iter = udp_packet_iter(&mut trx);
        loop {
            let next = iter.next();
            match next {
                Ok((header, addr)) => {
                    assert_eq!(addr, ip);
                    assert_eq!(
                        header,
                        UdpPacket::new(&packet[header_len..packet_len]).expect("could not create UdpPacket")
                    );
                    break;
                }
                Err(e) => {
                    panic!("Receive failed for layer4_test(): {}", e);
                }
            }
        }
    });

    rx.recv().expect("failed to receive message through channel");
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
#[cfg(all(
    not(feature = "appveyor"),
    not(all(target_os = "linux", feature = "travis"))
))]
fn layer4_ipv6() {
    layer4(IpAddr::V6(ipv6_source()), IPV6_HEADER_LEN);
}

#[test]
#[cfg(not(feature = "appveyor"))]
fn layer3_ipv4() {
    let send_addr = IpAddr::V4(ipv4_source());
    let mut packet = [0u8; IPV4_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN];

    build_udp4_packet(&mut packet[..], 0, "l3i4", None);

    let (tx, rx) = channel();

    let tc = transport_channel(
        IPV4_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN,
        TransportChannelType::Layer3(TEST_PROTO),
    );
    let (mut ttx, mut trx) = match tc {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("layer3: unable to create channel: {}", e),
    };

    let res = thread::spawn(move || {
        tx.send(()).expect("could not send message through channel");
        let mut iter = ipv4_packet_iter(&mut trx);
        loop {
            let next = iter.next();
            match next {
                Ok((header, addr)) => {
                    assert_eq!(addr, send_addr);
                    check_ipv4_header(&packet[..], &header);
                    let udp_header = UdpPacket::new(
                        &header.packet()[(header.get_header_length() as usize * 4usize)..],
                    )
                    .expect("could not create UdpPacket");
                    assert_eq!(
                        udp_header,
                        UdpPacket::new(&packet[IPV4_HEADER_LEN..]).expect("could not create UdpPacket")
                    );

                    assert_eq!(
                        &udp_header.packet()[UDP_HEADER_LEN..],
                        &packet[IPV4_HEADER_LEN + UDP_HEADER_LEN..]
                    );
                    break;
                }
                Err(e) => {
                    panic!("receive failed for layer3_ipv4_test(): {}", e);
                }
            }
        }
    });

    rx.recv().expect("unable to receive message through channel");
    match ttx.send_to(Ipv4Packet::new(&packet[..]).expect("could not create Ipv4Packet"), send_addr) {
        Ok(res) => assert_eq!(res as usize, packet.len()),
        Err(e) => panic!("layer3_ipv4_test failed: {}", e),
    }

    assert!(res.join().is_ok())
}

#[cfg(windows)]
fn get_test_interface() -> datalink::NetworkInterface {
    use std::clone::Clone;
    use std::env;
    let interfaces = datalink::interfaces();

    interfaces
        .iter()
        .filter(|x| match env::var("PNET_TEST_IFACE") {
            Ok(name) => x.name == name,
            Err(_) => true,
        })
        .next()
        .expect("failed to get test interface")
        .clone()
}

#[cfg(not(windows))]
fn get_test_interface() -> datalink::NetworkInterface {
    use std::clone::Clone;
    use std::env;
    let interfaces = datalink::interfaces();

    interfaces
        .iter()
        .filter(|x| match env::var("PNET_TEST_IFACE") {
            Ok(name) => x.name == name,
            Err(_) => x.is_loopback(),
        })
        .next()
        .expect("failed to get test interface")
        .clone()
}

// FIXME Find a way to test this with netmap
#[cfg(all(not(feature = "appveyor"), not(feature = "netmap")))]
#[test]
fn layer2() {
    use crate::datalink;
    use crate::datalink::Channel::Ethernet;
    use crate::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};

    const ETHERNET_HEADER_LEN: usize = 14;

    let interface = get_test_interface();

    let mut packet = [0u8; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN];

    {
        let mut ethernet_header = MutableEthernetPacket::new(&mut packet[..]).expect("could not create MutableEthernetPacket");
        ethernet_header.set_source(interface.mac.expect("could not find mac address for test interface"));
        ethernet_header.set_destination(interface.mac.expect("could not find mac address for test interface"));
        ethernet_header.set_ethertype(EtherTypes::Ipv4);
    }

    build_udp4_packet(
        &mut packet[..],
        ETHERNET_HEADER_LEN as usize,
        "l2tt",
        Some(&interface),
    );

    let (tx, rx) = channel();

    let dlc_sidea = datalink::channel(&interface, Default::default());
    let (mut dltx, _) = match dlc_sidea {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("layer2: unexpected L2 packet type"),
        Err(e) => panic!("layer2: unable to create channel: {}", e),
    };

    let dlc_sideb = datalink::channel(&interface, Default::default());
    let (_, mut dlrx) = match dlc_sideb {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("layer2: unexpected L2 packet type"),
        Err(e) => panic!("layer2: unable to create channel: {}", e),
    };

    let res = thread::spawn(move || {
        tx.send(()).expect("could not send message through channel");
        let mut i = 0usize;
        loop {
            let next = dlrx.next();
            match next {
                Ok(eh) => {
                    if i == 10_000 {
                        panic!("layer2: did not find matching packet after 10_000 iterations");
                    }
                    if EthernetPacket::new(&packet[..]).expect("failed to create EthernetPacket").payload()
                        == EthernetPacket::new(eh).expect("failed to create EthernetPacket").payload()
                    {
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

    rx.recv().expect("failed to receive message through channel");
    match dltx.send_to(&packet[..], None) {
        Some(Ok(())) => (),
        Some(Err(e)) => panic!("layer2_test failed: {}", e),
        None => panic!("Provided buffer too small"),
    }

    assert!(res.join().is_ok())
}

#[test]
#[cfg(target_os = "linux")]
fn layer2_timeouts() {
    use crate::datalink;
    use crate::datalink::Channel::Ethernet;
    use crate::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
    use std::io::ErrorKind;
    use std::time::Duration;

    const ETHERNET_HEADER_LEN: usize = 14;

    let interface = get_test_interface();

    let mut packet = [0u8; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + TEST_DATA_LEN];

    {
        let mut ethernet_header = MutableEthernetPacket::new(&mut packet[..]).expect("failed to create MutableEthernetPacket");
        ethernet_header.set_source(interface.mac.expect("missing mac address for test interface"));
        ethernet_header.set_destination(interface.mac.expect("missing mac address for test interface"));
        ethernet_header.set_ethertype(EtherTypes::Ipv4);
    }

    build_udp4_packet(
        &mut packet[..],
        ETHERNET_HEADER_LEN as usize,
        "l2tt",
        Some(&interface),
    );

    let (tx, rx) = channel();

    let cfg = datalink::Config {
        read_timeout: Some(Duration::new(0, 1)),
        write_timeout: Some(Duration::from_millis(100)),
        ..Default::default()
    };
    let dlc_sidea = datalink::channel(&interface, cfg.clone());
    let (_, mut dlrx) = match dlc_sidea {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("layer2_timeouts: unexpected L2 packet type"),
        Err(e) => panic!("layer2_timeouts: unable to create channel: {}", e),
    };

    let dlc_sideb = datalink::channel(&interface, cfg);
    let (mut dltx, _) = match dlc_sideb {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("layer2_timeouts: unexpected L2 packet type"),
        Err(e) => panic!("layer2_timeouts: unable to create channel: {}", e),
    };

    let packet_len = packet.len();
    let res = thread::spawn(move || {
        tx.send(()).expect("failed to send message through channel");
        loop {
            match dlrx.next() {
                Ok(eh) => {
                    panic!(
                        "layer2_timeouts: should have exceeded timeout ({}/{})",
                        eh.len(),
                        packet_len
                    );
                }
                Err(e) => {
                    assert!(e.kind() == ErrorKind::TimedOut);
                    return;
                }
            }
        }
    });
    rx.recv().expect("failed to receive message through channel");

    // Wait a while
    thread::sleep(Duration::from_millis(1000));
    match dltx.send_to(&packet[..], None) {
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
    if !tasks.is_ok() || &tasks.expect("failed to read RUST_TEST_THREADS env variable")[..] != "1" {
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
    fn test_iface() {}
}
