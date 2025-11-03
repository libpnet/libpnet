// Copyright (c) 2024 
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// This example demonstrates sending packets at both the datalink layer (Layer 2) 
/// and transport layer (Layer 4). It shows how to construct and send different types of packets.
extern crate pnet;
extern crate pnet_datalink;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, Config, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::IcmpCode;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{UdpPacket, MutableUdpPacket};
use pnet::packet::MutablePacket;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel};
use pnet::util::MacAddr;
use std::env;
use std::net::{IpAddr, Ipv4Addr};
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        println!("Usage: {} <interface_name> [target_ip]", args[0]);
        println!("\nAvailable interfaces:");
        for interface in datalink::interfaces() {
            println!("  {}", interface.name);
        }
        return;
    }

    let interface_name = &args[1];
    let target_ip = if args.len() >= 3 {
        args[2].parse::<Ipv4Addr>().unwrap_or_else(|_| {
            println!("Invalid IP address: {}", args[2]);
            process::exit(1);
        })
    } else {
        Ipv4Addr::new(8, 8, 8, 8) // Default to Google DNS
    };

    // Find the network interface
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == *interface_name)
        .unwrap_or_else(|| {
            println!("Interface '{}' not found", interface_name);
            process::exit(1);
        });

    println!("Using interface: {}", interface.name);
    println!("Target IP: {}", target_ip);

    // Demonstrate different types of packet sending
    println!("\n=== Packet Sending Demo ===");
    
    // 1. Send Layer 2 (Ethernet) packets
    send_layer2_packets(&interface, target_ip);
    
    // 2. Send Layer 4 (Transport) packets  
    send_layer4_packets(target_ip);
}

/// Demonstrates sending packets at the datalink layer (Layer 2)
fn send_layer2_packets(interface: &NetworkInterface, target_ip: Ipv4Addr) {
    println!("\n--- Layer 2 (Datalink) Packet Sending ---");
    
    let config = Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: false,
        socket_fd: None,
    };

    // Create a datalink channel
    let (mut tx, _rx) = match datalink::channel(interface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            println!("Unhandled channel type");
            return;
        }
        Err(e) => {
            println!("Failed to create datalink channel: {}", e);
            return;
        }
    };

    // Send a few different types of packets
    send_arp_packet(&mut *tx, interface, target_ip);
    send_icmp_packet(&mut *tx, interface, target_ip);
    send_udp_packet(&mut *tx, interface, target_ip);
}

/// Send an ARP request packet
fn send_arp_packet(tx: &mut dyn pnet::datalink::DataLinkSender, interface: &NetworkInterface, target_ip: Ipv4Addr) {
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};
    
    println!("Sending ARP request for {}", target_ip);
    
    // Get source MAC and IP
    let source_mac = interface.mac.unwrap_or_else(|| {
        println!("Interface has no MAC address");
        MacAddr::new(0, 0, 0, 0, 0, 0)
    });
    
    let source_ip = interface.ips
        .iter()
        .find_map(|ip_net| {
            if let IpAddr::V4(ipv4) = ip_net.ip() {
                Some(ipv4)
            } else {
                None
            }
        })
        .unwrap_or_else(|| Ipv4Addr::new(192, 168, 1, 100));

    // Build the complete packet: Ethernet + ARP
    let ethernet_size = EthernetPacket::minimum_packet_size();
    let arp_size = MutableArpPacket::minimum_packet_size();
    let total_size = ethernet_size + arp_size;
    
    tx.build_and_send(1, total_size, &mut |packet| {
        let mut ethernet_packet = MutableEthernetPacket::new(packet).unwrap();
        
        // Set Ethernet header
        ethernet_packet.set_destination(MacAddr::broadcast());
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Arp);
        
        // Set ARP header
        let mut arp_packet = MutableArpPacket::new(ethernet_packet.payload_mut()).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::new(0, 0, 0, 0, 0, 0));
        arp_packet.set_target_proto_addr(target_ip);
    });
    
    println!("  ✓ ARP request sent");
}

/// Send an ICMP ping packet
fn send_icmp_packet(tx: &mut dyn pnet::datalink::DataLinkSender, interface: &NetworkInterface, target_ip: Ipv4Addr) {
    use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
    
    println!("Sending ICMP ping to {}", target_ip);
    
    let source_mac = interface.mac.unwrap_or(MacAddr::new(0, 0, 0, 0, 0, 0));
    let source_ip = interface.ips
        .iter()
        .find_map(|ip_net| {
            if let IpAddr::V4(ipv4) = ip_net.ip() {
                Some(ipv4)
            } else {
                None
            }
        })
        .unwrap_or_else(|| Ipv4Addr::new(192, 168, 1, 100));

    // Build Ethernet + IPv4 + ICMP packet
    let ethernet_size = EthernetPacket::minimum_packet_size();
    let ipv4_size = Ipv4Packet::minimum_packet_size();
    let icmp_size = MutableIcmpPacket::minimum_packet_size();
    let total_size = ethernet_size + ipv4_size + icmp_size;
    
    tx.build_and_send(1, total_size, &mut |packet| {
        let mut ethernet_packet = MutableEthernetPacket::new(packet).unwrap();
        
        // Ethernet header
        ethernet_packet.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)); // Broadcast for demo
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Ipv4);
        
        // IPv4 header
        let mut ipv4_packet = MutableIpv4Packet::new(ethernet_packet.payload_mut()).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_dscp(0);
        ipv4_packet.set_ecn(0);
        ipv4_packet.set_total_length((ipv4_size + icmp_size) as u16);
        ipv4_packet.set_identification(0x1234);
        ipv4_packet.set_flags(Ipv4Flags::DontFragment);
        ipv4_packet.set_fragment_offset(0);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ipv4_packet.set_source(source_ip);
        ipv4_packet.set_destination(target_ip);
        
        // Calculate IPv4 checksum
        let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);
        
        // ICMP header
        let mut icmp_packet = MutableIcmpPacket::new(ipv4_packet.payload_mut()).unwrap();
        icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
        icmp_packet.set_icmp_code(IcmpCode::new(0));
        icmp_packet.set_checksum(0); // Will be calculated
        
        // Calculate ICMP checksum
        let checksum = pnet::packet::icmp::checksum(&icmp_packet.to_immutable());
        icmp_packet.set_checksum(checksum);
    });
    
    println!("  ✓ ICMP ping sent");
}

/// Send a UDP packet
fn send_udp_packet(tx: &mut dyn pnet::datalink::DataLinkSender, interface: &NetworkInterface, target_ip: Ipv4Addr) {
    println!("Sending UDP packet to {}:53 (DNS)", target_ip);
    
    let source_mac = interface.mac.unwrap_or(MacAddr::new(0, 0, 0, 0, 0, 0));
    let source_ip = interface.ips
        .iter()
        .find_map(|ip_net| {
            if let IpAddr::V4(ipv4) = ip_net.ip() {
                Some(ipv4)
            } else {
                None
            }
        })
        .unwrap_or_else(|| Ipv4Addr::new(192, 168, 1, 100));

    let payload = b"Hello, World!";
    
    // Build Ethernet + IPv4 + UDP packet
    let ethernet_size = EthernetPacket::minimum_packet_size();
    let ipv4_size = Ipv4Packet::minimum_packet_size();
    let udp_size = UdpPacket::minimum_packet_size();
    let total_size = ethernet_size + ipv4_size + udp_size + payload.len();
    
    tx.build_and_send(1, total_size, &mut |packet| {
        let mut ethernet_packet = MutableEthernetPacket::new(packet).unwrap();
        
        // Ethernet header
        ethernet_packet.set_destination(MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff));
        ethernet_packet.set_source(source_mac);
        ethernet_packet.set_ethertype(EtherTypes::Ipv4);
        
        // IPv4 header
        let mut ipv4_packet = MutableIpv4Packet::new(ethernet_packet.payload_mut()).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_dscp(0);
        ipv4_packet.set_ecn(0);
        ipv4_packet.set_total_length((ipv4_size + udp_size + payload.len()) as u16);
        ipv4_packet.set_identification(0x5678);
        ipv4_packet.set_flags(Ipv4Flags::DontFragment);
        ipv4_packet.set_fragment_offset(0);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4_packet.set_source(source_ip);
        ipv4_packet.set_destination(target_ip);
        
        // Calculate IPv4 checksum
        let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(checksum);
        
        // UDP header
        let mut udp_packet = MutableUdpPacket::new(ipv4_packet.payload_mut()).unwrap();
        udp_packet.set_source(12345);
        udp_packet.set_destination(53); // DNS port
        udp_packet.set_length((udp_size + payload.len()) as u16);
        udp_packet.set_checksum(0);
        
        // Copy payload
        udp_packet.set_payload(payload);
        
        // Calculate UDP checksum
        let checksum = pnet::packet::udp::ipv4_checksum(&udp_packet.to_immutable(), &source_ip, &target_ip);
        udp_packet.set_checksum(checksum);
    });
    
    println!("  ✓ UDP packet sent");
}

/// Demonstrates sending packets at the transport layer (Layer 4)
fn send_layer4_packets(target_ip: Ipv4Addr) {
    println!("\n--- Layer 4 (Transport) Packet Sending ---");
    
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Udp));
    
    // Create a transport channel
    let (mut tx, _rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            println!("Failed to create transport channel: {}", e);
            return;
        }
    };
    
    // Create a UDP packet
    let mut vec: Vec<u8> = vec![0; UdpPacket::minimum_packet_size() + 13]; // 13 bytes for "Hello, World!"
    let mut udp_packet = MutableUdpPacket::new(&mut vec[..]).unwrap();
    
    udp_packet.set_source(54321);
    udp_packet.set_destination(80); // HTTP port
    udp_packet.set_length((UdpPacket::minimum_packet_size() + 13) as u16);
    udp_packet.set_payload(b"Hello, World!");
    
    // Send the packet
    match tx.send_to(udp_packet, IpAddr::V4(target_ip)) {
        Ok(_) => println!("  ✓ Layer 4 UDP packet sent to {}:80", target_ip),
        Err(e) => println!("  ✗ Failed to send Layer 4 packet: {}", e),
    }
}