#![no_main]
extern crate libfuzzer_sys;
extern crate pnet;

use pnet::packet::Packet;
use pnet::packet::tcp::TcpPacket;

#[export_name="rust_fuzzer_test_input"]
pub extern fn go(data: &[u8]) {
	if let Some(tcp) = TcpPacket::new(data) {
		let options = tcp.get_options_iter();
		for o in options {
			o.payload();
		}
		for b in tcp.payload().iter() {
			*b;
		}
	}
}
