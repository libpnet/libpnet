//! A Linux cooked-mode capture (LINKTYPE_LINUX_SLL) packet abstraction.

use alloc::vec::Vec;

use super::ethernet::EtherType;
use pnet_macros::packet;
use pnet_macros_support::types::*;

// ref: https://wiki.wireshark.org/SLL
// ref: https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html

/// Represents an SLL packet (LINKTYPE_LINUX_SLL).
#[packet]
pub struct SLL {
	#[construct_with(u16)]
	pub packet_type: u16be,
	#[construct_with(u16)]
	pub link_layer_address_type: u16be,
	#[construct_with(u16)]
	pub link_layer_address_len: u16be,
	#[construct_with(u8, u8, u8, u8, u8, u8, u8, u8)]
	#[length = "8"]
	pub link_layer_address: Vec<u8>,
	#[construct_with(u16)]
	pub protocol: EtherType,
	#[payload]
	pub payload: Vec<u8>,
}
