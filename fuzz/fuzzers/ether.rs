#![no_main]
extern crate libfuzzer_sys;
extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::ethernet::EthernetPacket;

#[export_name="rust_fuzzer_test_input"]
pub extern fn go(data: &[u8]) {
	if let Some(eth) = EthernetPacket::new(data) {
		let _s = eth.get_source();
		let _d = eth.get_destination();
		let _t = eth.get_ethertype();
		let pl = eth.payload();
		for b in pl.iter() {
			*b;
		}
	}

}
