// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # libpnet
//!
//! `libpnet` provides a cross-platform API for low level networking using Rust.
//!
//! There are four key components:
//!
//!  * The packet module, allowing safe construction and manipulation of packets
//! * The pnet_packet crate, providing infrastructure for the packet module
//!  * The transport module, which allows implementation of transport protocols
//!  * The datalink module, which allows sending and receiving data link packets directly
//!
//! ## Terminology
//!
//! The documentation uses the following terms interchangably:
//!
//!  * Layer 2, datalink layer
//!  * Layer 3, network layer
//!  * Layer 4, transport layer
//!
//! Unless otherwise stated, all interactions with libpnet are in host-byte order - any platform
//! specific variations are handled internally.
//!
//! ## Examples
//!
//! More examples, including a packet logger, and a version of the echo server written at the
//! transport layer, can be found in the examples/ directory.
//!
//! ### Ethernet echo server
//!
//! This (fairly useless) code implements an Ethernet echo server. Whenever a packet is received on
//! an interface, it echo's the packet back; reversing the source and destination addresses.
//!
//! ```no_run
//! extern crate pnet;
//!
//! use pnet::datalink::datalink_channel;
//! use pnet::datalink::DataLinkChannelType::Layer2;
//! use pnet::packet::{Packet, MutablePacket};
//! use pnet::util::{NetworkInterface, get_network_interfaces};
//!
//! use std::env;
//!
//! // Invoke as echo <interface name>
//! fn main() {
//!     let interface_name = env::args().nth(1).unwrap();
//!     let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;
//!
//!     // Find the network interface with the provided name
//!     let interfaces = get_network_interfaces();
//!     let interface = interfaces.into_iter()
//!                               .filter(interface_names_match)
//!                               .next()
//!                               .unwrap();
//!
//!     // Create a new channel, dealing with layer 2 packets
//!     let (mut tx, mut rx) = match datalink_channel(&interface, 4096, 4096, Layer2) {
//!         Ok((tx, rx)) => (tx, rx),
//!         Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
//!     };
//!
//!     let mut iter = rx.iter();
//!     loop {
//!         match iter.next() {
//!             Ok(packet) => {
//!                 // Constructs a single packet, the same length as the the one received,
//!                 // using the provided closure. This allows the packet to be constructed
//!                 // directly in the write buffer, without copying. If copying is not a
//!                 // problem, you could also use send_to.
//!                 //
//!                 // The packet is sent once the closure has finished executing.
//!                 tx.build_and_send(1, packet.packet().len(), &mut |mut new_packet| {
//!                     // Create a clone of the original packet
//!                     new_packet.clone_from(&packet);
//!
//!                     // Switch the source and destination
//!                     new_packet.set_source(packet.get_destination());
//!                     new_packet.set_destination(packet.get_source());
//!                 });
//!             },
//!             Err(e) => {
//!                 // If an error occurs, we can handle it here
//!                 panic!("An error occurred while reading: {}", e);
//!             }
//!         }
//!     }
//! }
//! ```

#![crate_name = "pnet"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]

#![deny(missing_docs)]
#![allow(plugin_as_library)]

// FIXME Remove this once the std lib has stabilised
#![feature(convert, custom_attribute, ip_addr, libc, plugin, slice_bytes,
           slice_patterns, vec_push_all)]
#![plugin(pnet_macros)]
#![cfg_attr(test, feature(str_char))]
#![cfg_attr(any(target_os = "freebsd", target_os = "macos"), feature(clone_from_slice))]

extern crate libc;
extern crate pnet_macros;

pub mod datalink;
pub mod packet;
pub mod transport;
pub mod util;

mod bindings;
mod internal;

// NOTE should probably have a cfg(pnet_test_network) here, but cargo doesn't allow custom --cfg
//      flags
#[cfg(test)]
mod test;

// Required to make sure that imports from pnet_macros work
mod pnet {
    pub use packet;
}

