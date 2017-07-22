#![no_main]
extern crate libfuzzer_sys;
extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};

#[export_name="rust_fuzzer_test_input"]
pub extern fn go(data: &[u8]) {
	if let Some(eth) = EthernetPacket::new(data) {
		let s = eth.get_source();
		let d = eth.get_destination();
		let t = eth.get_ethertype();
		let pl = eth.payload();
		for b in pl.iter() {
			*b;
		}
	}

}
