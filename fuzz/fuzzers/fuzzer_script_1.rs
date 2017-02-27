#![no_main]
extern crate libfuzzer_sys;
extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::arp::{MutableArpPacket, ArpOperations, ArpHardwareTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, Ipv4Flags};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket, MutableTcpOptionPacket, TcpOptionNumbers, TcpFlags};

#[export_name="rust_fuzzer_test_input"]
pub extern fn go(data: &[u8]) {
	if let Some(eth) = EthernetPacket::new(data) {
		let s = eth.get_source();
		let d = eth.get_destination();
		let t = eth.get_ethertype();
		let pl = eth.payload();
		if let Some(ipv4) = Ipv4Packet::new(pl) {
			let options = ipv4.get_options_raw();
			for o in options.iter() {
				*o;
			}
		}
	}
}
