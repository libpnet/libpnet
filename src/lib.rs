// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(feature = "nightly", feature(custom_attribute, plugin))]
#![cfg_attr(feature = "nightly", plugin(pnet_macros_plugin))]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "benchmark", feature(test))]
#![cfg_attr(feature = "clippy", plugin(clippy))]
// We can't implement Iterator since we use streaming iterators
#![cfg_attr(feature = "clippy", allow(should_implement_trait))]
#![cfg_attr(any(feature = "appveyor", feature = "travis"), deny(warnings))]

//! # libpnet
//!
//! `libpnet` provides a cross-platform API for low level networking using Rust.
//!
//! There are four key components:
//!
//!  * The `packet` module, allowing safe construction and manipulation of packets;
//!  * The `pnet_packet` crate, providing infrastructure for the packet module;
//!  * The `transport` module, which allows implementation of transport protocols;
//!  * The `datalink` module, which allows sending and receiving data link
//!    packets directly.
//!
//! ## Terminology
//!
//! The documentation uses the following terms interchangably:
//!
//!  * Layer 2, datalink layer;
//!  * Layer 3, network layer;
//!  * Layer 4, transport layer.
//!
//! Unless otherwise stated, all interactions with libpnet are in host-byte
//! order - any platform specific variations are handled internally.
//!
//! ## Examples
//!
//! More examples, including a packet logger, and a version of the echo server
//! written at the transport layer, can be found in the `examples/` directory.
//!
//! ### Ethernet echo server
//!
//! This (fairly useless) code implements an Ethernet echo server. Whenever a
//! packet is received on an interface, it echo's the packet back; reversing the
//! source and destination addresses.
//!
//! ```rust,ignore
//! extern crate pnet;
//!
//! use pnet::datalink::{self, NetworkInterface};
//! use pnet::datalink::Channel::Ethernet;
//! use pnet::packet::{Packet, MutablePacket};
//! use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
//!
//! use std::env;
//!
//! // Invoke as echo <interface name>
//! fn main() {
//!     let interface_name = env::args().nth(1).unwrap();
//!     let interface_names_match =
//!         |iface: &NetworkInterface| iface.name == interface_name;
//!
//!     // Find the network interface with the provided name
//!     let interfaces = datalink::interfaces();
//!     let interface = interfaces.into_iter()
//!                               .filter(interface_names_match)
//!                               .next()
//!                               .unwrap();
//!
//!     // Create a new channel, dealing with layer 2 packets
//!     let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
//!         Ok(Ethernet(tx, rx)) => (tx, rx),
//!         Ok(_) => panic!("Unhandled channel type"),
//!         Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
//!     };
//!
//!     loop {
//!         match rx.next() {
//!             Ok(packet) => {
//!                 let packet = EthernetPacket::new(packet).unwrap();
//!
//!                 // Constructs a single packet, the same length as the the one received,
//!                 // using the provided closure. This allows the packet to be constructed
//!                 // directly in the write buffer, without copying. If copying is not a
//!                 // problem, you could also use send_to.
//!                 //
//!                 // The packet is sent once the closure has finished executing.
//!                 tx.build_and_send(1, packet.packet().len(),
//!                     &mut |mut new_packet| {
//!                         let mut new_packet = MutableEthernetPacket::new(new_packet).unwrap();
//!
//!                         // Create a clone of the original packet
//!                         new_packet.clone_from(&packet);
//!
//!                         // Switch the source and destination
//!                         new_packet.set_source(packet.get_destination());
//!                         new_packet.set_destination(packet.get_source());
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

#[cfg(feature = "benchmark")]
extern crate test;

#[cfg(feature = "std")]
pub extern crate ipnetwork;

extern crate pnet_base;

#[cfg(feature = "std")]
extern crate pnet_datalink;
extern crate pnet_packet;
#[cfg(feature = "std")]
extern crate pnet_sys;
#[cfg(feature = "std")]
extern crate pnet_transport;

/// Support for sending and receiving data link layer packets.
#[cfg(feature = "std")]
pub mod datalink {
    pub use pnet_datalink::*;
}

/// Support for packet parsing and manipulation.
pub mod packet {
    pub use pnet_packet::*;
}

/// Support for sending and receiving transport layer packets.
#[cfg(feature = "std")]
pub mod transport {
    pub use pnet_transport::*;
}

pub mod util;

// NOTE should probably have a cfg(pnet_test_network) here, but cargo doesn't
//      allow custom --cfg flags
#[cfg(all(test, std))]
mod pnettest;
