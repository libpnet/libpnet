// Copyright (c) 2024
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// This example demonstrates receiving packets at both the datalink layer (Layer 2)
/// and transport layer (Layer 4). It shows how to capture and parse different types of packets.
extern crate pnet;
extern crate pnet_datalink;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, Config, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{icmp_packet_iter, tcp_packet_iter, transport_channel, udp_packet_iter};
use std::env;
use std::process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <interface_name> [mode]", args[0]);
        println!("Modes: layer2, layer4, both (default: both)");
        println!("Example: {} eth0 layer2", args[0]);
        println!("\nAvailable interfaces:");
        for interface in datalink::interfaces() {
            println!("  {}", interface.name);
        }
        return;
    }

    let interface_name = &args[1];
    let mode = if args.len() >= 3 {
        args[2].as_str()
    } else {
        "both"
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
    println!("Mode: {}", mode);
    println!("Starting packet capture... (Press Ctrl+C to stop)\n");

    // Shared counters for statistics
    let stats = Arc::new(PacketStats::new());

    match mode {
        "layer2" => {
            receive_layer2_packets(&interface, stats);
        }
        "layer4" => {
            receive_layer4_packets(&interface, stats);
        }
        "both" => {
            let stats_l2 = Arc::clone(&stats);
            let stats_l4 = Arc::clone(&stats);
            let interface_l2 = interface.clone();
            let interface_l4 = interface.clone();

            // Start Layer 2 receiver in a separate thread
            let l2_handle = thread::spawn(move || {
                receive_layer2_packets(&interface_l2, stats_l2);
            });

            // Start Layer 4 receiver in a separate thread
            let l4_handle = thread::spawn(move || {
                receive_layer4_packets(&interface_l4, stats_l4);
            });

            // Print statistics every 5 seconds
            let stats_print = Arc::clone(&stats);
            let stats_handle = thread::spawn(move || {
                let mut last_stats = PacketStats::new();
                loop {
                    thread::sleep(Duration::from_secs(5));
                    stats_print.print_rate(&mut last_stats);
                }
            });

            // Wait for threads (they run indefinitely)
            let _ = l2_handle.join();
            let _ = l4_handle.join();
            let _ = stats_handle.join();
        }
        _ => {
            println!("Invalid mode: {}. Use 'layer2', 'layer4', or 'both'", mode);
            process::exit(1);
        }
    }
}

/// Statistics tracking for received packets
struct PacketStats {
    ethernet: AtomicUsize,
    arp: AtomicUsize,
    ipv4: AtomicUsize,
    ipv6: AtomicUsize,
    icmp: AtomicUsize,
    tcp: AtomicUsize,
    udp: AtomicUsize,
    other: AtomicUsize,
    total: AtomicUsize,
    start_time: Instant,
}

impl PacketStats {
    fn new() -> Self {
        PacketStats {
            ethernet: AtomicUsize::new(0),
            arp: AtomicUsize::new(0),
            ipv4: AtomicUsize::new(0),
            ipv6: AtomicUsize::new(0),
            icmp: AtomicUsize::new(0),
            tcp: AtomicUsize::new(0),
            udp: AtomicUsize::new(0),
            other: AtomicUsize::new(0),
            total: AtomicUsize::new(0),
            start_time: Instant::now(),
        }
    }

    fn increment_ethernet(&self) {
        self.ethernet.fetch_add(1, Ordering::Relaxed);
    }
    fn increment_arp(&self) {
        self.arp.fetch_add(1, Ordering::Relaxed);
    }
    fn increment_ipv4(&self) {
        self.ipv4.fetch_add(1, Ordering::Relaxed);
    }
    fn increment_ipv6(&self) {
        self.ipv6.fetch_add(1, Ordering::Relaxed);
    }
    fn increment_icmp(&self) {
        self.icmp.fetch_add(1, Ordering::Relaxed);
    }
    fn increment_tcp(&self) {
        self.tcp.fetch_add(1, Ordering::Relaxed);
    }
    fn increment_udp(&self) {
        self.udp.fetch_add(1, Ordering::Relaxed);
    }
    fn increment_other(&self) {
        self.other.fetch_add(1, Ordering::Relaxed);
    }
    fn increment_total(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    fn get_ethernet(&self) -> usize {
        self.ethernet.load(Ordering::Relaxed)
    }
    fn get_arp(&self) -> usize {
        self.arp.load(Ordering::Relaxed)
    }
    fn get_ipv4(&self) -> usize {
        self.ipv4.load(Ordering::Relaxed)
    }
    fn get_ipv6(&self) -> usize {
        self.ipv6.load(Ordering::Relaxed)
    }
    fn get_icmp(&self) -> usize {
        self.icmp.load(Ordering::Relaxed)
    }
    fn get_tcp(&self) -> usize {
        self.tcp.load(Ordering::Relaxed)
    }
    fn get_udp(&self) -> usize {
        self.udp.load(Ordering::Relaxed)
    }
    fn get_other(&self) -> usize {
        self.other.load(Ordering::Relaxed)
    }
    fn get_total(&self) -> usize {
        self.total.load(Ordering::Relaxed)
    }

    fn print_stats(&self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        let total = self.get_total();
        let rate = if elapsed > 0.0 {
            total as f64 / elapsed
        } else {
            0.0
        };

        println!("\n=== Packet Statistics ===");
        println!(
            "Runtime: {:.1}s | Total: {} packets ({:.1} pps)",
            elapsed, total, rate
        );
        println!(
            "Ethernet: {} | ARP: {} | IPv4: {} | IPv6: {}",
            self.get_ethernet(),
            self.get_arp(),
            self.get_ipv4(),
            self.get_ipv6()
        );
        println!(
            "ICMP: {} | TCP: {} | UDP: {} | Other: {}",
            self.get_icmp(),
            self.get_tcp(),
            self.get_udp(),
            self.get_other()
        );
    }

    fn print_rate(&self, last_stats: &mut PacketStats) {
        let current_total = self.get_total();
        let last_total = last_stats.get_total();
        let rate = (current_total - last_total) as f64 / 5.0; // 5 second interval

        println!("Rate: {:.1} pps | Total: {} packets", rate, current_total);

        // Update last stats
        last_stats.total.store(current_total, Ordering::Relaxed);
    }
}

/// Demonstrates receiving packets at the datalink layer (Layer 2)
fn receive_layer2_packets(interface: &NetworkInterface, stats: Arc<PacketStats>) {
    println!("--- Layer 2 (Datalink) Packet Reception ---");

    let config = Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: true,
        socket_fd: None,
    };

    // Create a datalink channel
    let (_tx, mut rx) = match datalink::channel(interface, config) {
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

    let mut packet_count = 0;
    loop {
        match rx.next() {
            Ok(packet) => {
                packet_count += 1;
                stats.increment_total();

                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    stats.increment_ethernet();
                    parse_ethernet_packet(&ethernet_packet, &stats);

                    // Print first few packets for demonstration
                    if packet_count <= 10 {
                        print_ethernet_packet_info(&ethernet_packet, packet_count);
                    }
                }
            }
            Err(e) => {
                println!("Failed to receive packet: {}", e);
                break;
            }
        }

        // Print statistics every 1000 packets
        if packet_count % 1000 == 0 {
            stats.print_stats();
        }
    }
}

/// Parse an Ethernet packet and extract inner protocol information
fn parse_ethernet_packet(ethernet: &EthernetPacket, stats: &Arc<PacketStats>) {
    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
                stats.increment_ipv4();
                parse_ipv4_packet(&ipv4_packet, stats);
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6_packet) = Ipv6Packet::new(ethernet.payload()) {
                stats.increment_ipv6();
                parse_ipv6_packet(&ipv6_packet, stats);
            }
        }
        EtherTypes::Arp => {
            if let Some(_arp_packet) = ArpPacket::new(ethernet.payload()) {
                stats.increment_arp();
            }
        }
        _ => {
            stats.increment_other();
        }
    }
}

/// Parse IPv4 packet and extract transport layer information
fn parse_ipv4_packet(ipv4: &Ipv4Packet, stats: &Arc<PacketStats>) {
    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Icmp => {
            if let Some(_icmp_packet) = IcmpPacket::new(ipv4.payload()) {
                stats.increment_icmp();
            }
        }
        IpNextHeaderProtocols::Tcp => {
            if let Some(_tcp_packet) = TcpPacket::new(ipv4.payload()) {
                stats.increment_tcp();
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(_udp_packet) = UdpPacket::new(ipv4.payload()) {
                stats.increment_udp();
            }
        }
        _ => {
            stats.increment_other();
        }
    }
}

/// Parse IPv6 packet and extract transport layer information
fn parse_ipv6_packet(ipv6: &Ipv6Packet, stats: &Arc<PacketStats>) {
    match ipv6.get_next_header() {
        IpNextHeaderProtocols::Icmpv6 => {
            stats.increment_icmp();
        }
        IpNextHeaderProtocols::Tcp => {
            if let Some(_tcp_packet) = TcpPacket::new(ipv6.payload()) {
                stats.increment_tcp();
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(_udp_packet) = UdpPacket::new(ipv6.payload()) {
                stats.increment_udp();
            }
        }
        _ => {
            stats.increment_other();
        }
    }
}

/// Print detailed information about an Ethernet packet
fn print_ethernet_packet_info(ethernet: &EthernetPacket, count: usize) {
    println!("\n--- Packet #{} ---", count);
    println!(
        "Ethernet: {} -> {} (Type: {:?})",
        ethernet.get_source(),
        ethernet.get_destination(),
        ethernet.get_ethertype()
    );

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
                println!(
                    "  IPv4: {} -> {} (Proto: {:?})",
                    ipv4_packet.get_source(),
                    ipv4_packet.get_destination(),
                    ipv4_packet.get_next_level_protocol()
                );

                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                            println!(
                                "    TCP: {}:{} -> {}:{}",
                                ipv4_packet.get_source(),
                                tcp_packet.get_source(),
                                ipv4_packet.get_destination(),
                                tcp_packet.get_destination()
                            );
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                            println!(
                                "    UDP: {}:{} -> {}:{}",
                                ipv4_packet.get_source(),
                                udp_packet.get_source(),
                                ipv4_packet.get_destination(),
                                udp_packet.get_destination()
                            );
                        }
                    }
                    IpNextHeaderProtocols::Icmp => {
                        if let Some(icmp_packet) = IcmpPacket::new(ipv4_packet.payload()) {
                            println!(
                                "    ICMP: Type {:?}, Code {:?}",
                                icmp_packet.get_icmp_type(),
                                icmp_packet.get_icmp_code()
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
        EtherTypes::Arp => {
            if let Some(arp_packet) = ArpPacket::new(ethernet.payload()) {
                println!(
                    "  ARP: {:?} {} -> {}",
                    arp_packet.get_operation(),
                    arp_packet.get_sender_proto_addr(),
                    arp_packet.get_target_proto_addr()
                );
            }
        }
        _ => {}
    }
}

/// Demonstrates receiving packets at the transport layer (Layer 4)
fn receive_layer4_packets(_interface: &NetworkInterface, stats: Arc<PacketStats>) {
    println!("--- Layer 4 (Transport) Packet Reception ---");

    // Start multiple transport receivers for different protocols
    let stats_icmp = Arc::clone(&stats);
    let stats_tcp = Arc::clone(&stats);
    let stats_udp = Arc::clone(&stats);

    // ICMP receiver
    let icmp_handle = thread::spawn(move || {
        receive_icmp_packets(stats_icmp);
    });

    // TCP receiver
    let tcp_handle = thread::spawn(move || {
        receive_tcp_packets(stats_tcp);
    });

    // UDP receiver
    let udp_handle = thread::spawn(move || {
        receive_udp_packets(stats_udp);
    });

    // Wait for all receivers
    let _ = icmp_handle.join();
    let _ = tcp_handle.join();
    let _ = udp_handle.join();
}

/// Receive ICMP packets using transport layer API
fn receive_icmp_packets(stats: Arc<PacketStats>) {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));

    let (_tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            println!("Failed to create ICMP transport channel: {}", e);
            return;
        }
    };

    let mut iter = icmp_packet_iter(&mut rx);
    let mut count = 0;

    println!("ICMP transport receiver started");

    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                count += 1;
                stats.increment_icmp();
                stats.increment_total();

                if count <= 5 {
                    println!(
                        "ICMP #{}: Type {:?}, Code {:?} from {}",
                        count,
                        packet.get_icmp_type(),
                        packet.get_icmp_code(),
                        addr
                    );
                }
            }
            Err(e) => {
                println!("ICMP receive error: {}", e);
                break;
            }
        }
    }
}

/// Receive TCP packets using transport layer API
fn receive_tcp_packets(stats: Arc<PacketStats>) {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));

    let (_tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            println!("Failed to create TCP transport channel: {}", e);
            return;
        }
    };

    let mut iter = tcp_packet_iter(&mut rx);
    let mut count = 0;

    println!("TCP transport receiver started");

    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                count += 1;
                stats.increment_tcp();
                stats.increment_total();

                if count <= 5 {
                    println!(
                        "TCP #{}: {}:{} -> {}:{} [Seq: {}, Ack: {}] from {}",
                        count,
                        addr,
                        packet.get_source(),
                        addr,
                        packet.get_destination(),
                        packet.get_sequence(),
                        packet.get_acknowledgement(),
                        addr
                    );
                }
            }
            Err(e) => {
                println!("TCP receive error: {}", e);
                break;
            }
        }
    }
}

/// Receive UDP packets using transport layer API
fn receive_udp_packets(stats: Arc<PacketStats>) {
    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Udp));

    let (_tx, mut rx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => {
            println!("Failed to create UDP transport channel: {}", e);
            return;
        }
    };

    let mut iter = udp_packet_iter(&mut rx);
    let mut count = 0;

    println!("UDP transport receiver started");

    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                count += 1;
                stats.increment_udp();
                stats.increment_total();

                if count <= 5 {
                    println!(
                        "UDP #{}: {}:{} -> {}:{} [Len: {}] from {}",
                        count,
                        addr,
                        packet.get_source(),
                        addr,
                        packet.get_destination(),
                        packet.get_length(),
                        addr
                    );
                }
            }
            Err(e) => {
                println!("UDP receive error: {}", e);
                break;
            }
        }
    }
}
