//! Retrieve a MAC address from an IP address
//!
//! This uses ARP for IPv4 and NDP for IPv6. ARP packets are straightforward, essentially
//!
//! ```text
//! Ethernet Packet
//!   ARP Packet
//! ```
//!
//! but NDP packets have a few more layers
//!
//! ```text
//! Ethernet Packet
//!     IPv6 Packet
//!         Neighborhood Solicitation / Advertisement Packet
//!             NDP Option Packet
//! ````

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use std::{env, process};

use pnet::datalink::{Channel, DataLinkReceiver, DataLinkSender, NetworkInterface};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmpv6::ndp::{
    MutableNdpOptionPacket, MutableNeighborSolicitPacket, NdpOptionPacket, NdpOptionTypes,
    NeighborAdvertPacket, NeighborSolicitPacket,
};
use pnet::packet::icmpv6::{self, Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::util::MacAddr;

const TIMEOUT: Duration = Duration::from_secs(10);

// Constants used to help locate our nested packets
const PKT_ETH_SIZE: usize = EthernetPacket::minimum_packet_size();
const PKT_ARP_SIZE: usize = ArpPacket::minimum_packet_size();
const PKT_IP6_SIZE: usize = Ipv6Packet::minimum_packet_size();
const PKT_NDP_SOL_SIZE: usize = NeighborSolicitPacket::minimum_packet_size();
const PKT_NDP_ADV_SIZE: usize = NeighborAdvertPacket::minimum_packet_size();
const PKT_OPT_SIZE: usize = NdpOptionPacket::minimum_packet_size();
const PKT_MAC_SIZE: usize = 6;

const PKT_ARP_OFFSET: usize = PKT_ETH_SIZE;
const PKT_IP6_OFFSET: usize = PKT_ETH_SIZE;
const PKT_NDP_OFFSET: usize = PKT_IP6_OFFSET + PKT_IP6_SIZE;

const PKT_MIN_ARP_RESP_SIZE: usize = PKT_ETH_SIZE + PKT_ARP_SIZE;
const PKT_MIN_NDP_RESP_SIZE: usize = PKT_ETH_SIZE + PKT_IP6_SIZE + PKT_NDP_ADV_SIZE;

/// Given an IPv4 or IPv6 address and an interface name
pub fn get_mac(ifname: &str, ip: IpAddr) -> Result<MacAddr, Error> {
    let interfaces = pnet::datalink::interfaces();

    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == ifname)
        .ok_or_else(|| Error::Interface(ifname.into()))?;

    println!("Source MAC address: {}", interface.mac.unwrap());

    match ip {
        IpAddr::V4(ipv4) => get_mac_via_arp(&interface, ipv4),
        IpAddr::V6(ipv6) => get_mac_via_ndp(&interface, ipv6),
    }
}

/// Use ARP to locate the MAC of an IPv4 address
fn get_mac_via_arp(interface: &NetworkInterface, target_ipv4: Ipv4Addr) -> Result<MacAddr, Error> {
    let source_ipv4 = interface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            IpAddr::V4(addr) => Some(addr),
            IpAddr::V6(_) => None,
        })
        .unwrap();

    let source_mac = interface.mac.unwrap();
    let mut pkt_buf = [0u8; PKT_ETH_SIZE + PKT_ARP_SIZE];

    // Use scope blocks so we can reborrow our buffer
    {
        // Build our base ethernet frame
        let mut pkt_eth = MutableEthernetPacket::new(&mut pkt_buf).unwrap();

        pkt_eth.set_destination(MacAddr::broadcast());
        pkt_eth.set_source(interface.mac.unwrap());
        pkt_eth.set_ethertype(EtherTypes::Arp);
    }

    {
        // Build the ARP frame on top of the ethernet frame
        let mut pkt_arp = MutableArpPacket::new(&mut pkt_buf[PKT_ARP_OFFSET..]).unwrap();

        pkt_arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        pkt_arp.set_protocol_type(EtherTypes::Ipv4);
        pkt_arp.set_hw_addr_len(6);
        pkt_arp.set_proto_addr_len(4);
        pkt_arp.set_operation(ArpOperations::Request);
        pkt_arp.set_sender_hw_addr(interface.mac.unwrap());
        pkt_arp.set_sender_proto_addr(source_ipv4);
        pkt_arp.set_target_hw_addr(MacAddr::zero());
        pkt_arp.set_target_proto_addr(target_ipv4);
    }

    let (mut sender, mut receiver) = build_eth_channel(interface);
    let start = Instant::now();

    // Send to the broadcast address
    sender.send_to(&pkt_buf, None).unwrap().unwrap();
    eprintln!("Sent ARP request");

    // Zero buffer for sanity check
    pkt_buf.fill(0);

    loop {
        let buf = receiver.next().unwrap();

        if buf.len() < PKT_MIN_ARP_RESP_SIZE {
            timeout_check(start)?;
            continue;
        }

        let pkt_arp = ArpPacket::new(&buf[PKT_ARP_OFFSET..]).unwrap();

        if pkt_arp.get_sender_proto_addr() == target_ipv4
            && pkt_arp.get_target_hw_addr() == source_mac
        {
            return Ok(pkt_arp.get_sender_hw_addr());
        }

        timeout_check(start)?;
    }
}

/// Use NDP to locate the MAC of an IPv6 address
fn get_mac_via_ndp(interface: &NetworkInterface, target_ipv6: Ipv6Addr) -> Result<MacAddr, Error> {
    let source_ipv6 = interface
        .ips
        .iter()
        .find_map(|ip| match ip.ip() {
            IpAddr::V4(_) => None,
            IpAddr::V6(addr) => Some(addr),
        })
        .unwrap();

    let source_mac = interface.mac.unwrap();
    let mut pkt_buf =
        [0u8; PKT_ETH_SIZE + PKT_IP6_SIZE + PKT_NDP_SOL_SIZE + PKT_OPT_SIZE + PKT_MAC_SIZE];

    // Use scope blocks so we can reborrow our buffer
    {
        // Build our base ethernet frame
        let mut pkt_eth = MutableEthernetPacket::new(&mut pkt_buf).unwrap();

        pkt_eth.set_destination(MacAddr::broadcast());
        pkt_eth.set_source(interface.mac.unwrap());
        pkt_eth.set_ethertype(EtherTypes::Ipv6);
    }

    {
        // Build the ipv6 packet
        let mut pkt_ipv6 = MutableIpv6Packet::new(&mut pkt_buf[PKT_IP6_OFFSET..]).unwrap();

        pkt_ipv6.set_version(0x06);
        pkt_ipv6.set_payload_length(
            (PKT_NDP_SOL_SIZE + PKT_OPT_SIZE + PKT_MAC_SIZE)
                .try_into()
                .unwrap(),
        );
        pkt_ipv6.set_next_header(IpNextHeaderProtocols::Icmpv6);
        pkt_ipv6.set_hop_limit(u8::MAX);
        pkt_ipv6.set_source(source_ipv6);
        pkt_ipv6.set_destination(target_ipv6);
    }

    {
        // Build the NDP packet
        let mut pkt_ndp =
            MutableNeighborSolicitPacket::new(&mut pkt_buf[PKT_NDP_OFFSET..]).unwrap();
        pkt_ndp.set_target_addr(target_ipv6);
        pkt_ndp.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
        pkt_ndp.set_checksum(0x3131);

        let mut pkt_opt = MutableNdpOptionPacket::new(pkt_ndp.get_options_raw_mut()).unwrap();
        pkt_opt.set_option_type(NdpOptionTypes::SourceLLAddr);
        pkt_opt.set_length(octets_len(PKT_MAC_SIZE));
        pkt_opt.set_data(&source_mac.octets());
    }

    {
        // Set the checksum (part of the NDP packet)
        let mut pkt_icmpv6 = MutableIcmpv6Packet::new(&mut pkt_buf[PKT_NDP_OFFSET..]).unwrap();
        pkt_icmpv6.set_checksum(icmpv6::checksum(
            &pkt_icmpv6.to_immutable(),
            &source_ipv6,
            &target_ipv6,
        ));
    }

    let (mut sender, mut receiver) = build_eth_channel(interface);
    let start = Instant::now();

    // Send to the broadcast address
    sender.send_to(&pkt_buf, None).unwrap().unwrap();
    eprintln!("Sent NDP request");

    // Zero buffer for sanity check
    pkt_buf.fill(0);

    loop {
        let buf = receiver.next().unwrap();

        if buf.len() < PKT_MIN_NDP_RESP_SIZE {
            timeout_check(start)?;
            continue;
        }

        let pkt_eth = EthernetPacket::new(buf).unwrap();
        let pkt_ipv6 = Ipv6Packet::new(&buf[PKT_IP6_OFFSET..]).unwrap();
        let _pkt_ndp = NeighborAdvertPacket::new(&buf[PKT_NDP_OFFSET..]).unwrap();

        if pkt_ipv6.get_source() == target_ipv6 && pkt_eth.get_destination() == source_mac {
            return Ok(pkt_eth.get_source());
        }

        timeout_check(start)?;
    }
}

/// Construct a sender/receiver channel from an interface
fn build_eth_channel(
    interface: &NetworkInterface,
) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    let cfg = pnet::datalink::Config::default();
    match pnet::datalink::channel(interface, cfg) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Channel error: {e}"),
    }
}

/// Length in octets (8bytes)
fn octets_len(len: usize) -> u8 {
    // 3 = log2(8)
    (len.next_power_of_two() >> 3).try_into().unwrap()
}

/// Bail if we exceed TIMEOUT
fn timeout_check(start: Instant) -> Result<(), Error> {
    if Instant::now().duration_since(start) > TIMEOUT {
        Err(Error::Timeout(TIMEOUT))
    } else {
        Ok(())
    }
}

/// Simple error types for this demo
#[derive(Debug)]
pub enum Error {
    /// Something didn't happen on time
    Timeout(Duration),
    /// Interface of this name did not exist
    Interface(String),
}

const USAGE: &str = "USAGE: arp_packet <NETWORK INTERFACE> <TARGET IP>";

fn main() {
    let mut args = env::args().skip(1);
    let Some(iface_name) = args.next() else {
        eprintln!("{USAGE}");
        process::exit(1);
    };

    let Some(target_ip) = args.next() else {
        eprintln!("{USAGE}");
        process::exit(1);
    };

    let target_mac = get_mac(&iface_name, target_ip.parse().unwrap()).unwrap();
    println!("Target MAC address: {}", target_mac);
}
