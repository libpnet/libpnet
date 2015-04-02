// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Provides interfaces for interacting with packets and headers

#![macro_use]

/// Represents a generic network packet
pub trait Packet {
    /// Retreive the underlying buffer for the packet
    fn packet<'p>(&'p self) -> &'p [u8];

    /// Retreive the payload for the packet
    fn payload<'p>(&'p self) -> &'p [u8];
}

/// Represents a generic, mutable, network packet
pub trait MutablePacket {
    /// Retreive the underlying, mutable, buffer for the packet
    fn packet_mut<'p>(&'p mut self) -> &'p mut [u8];

    /// Retreive the mutable payload for the packet
    fn payload_mut<'p>(&'p mut self) -> &'p mut [u8];

    /// Initialize this packet by cloning another
    fn clone_from<'p, T : Packet>(&'p mut self, other: T) {
        use std::slice::bytes::copy_memory;
        copy_memory(other.packet(), self.packet_mut())
    }
}

pub mod ethernet;
pub mod ip;
pub mod ipv4;
pub mod ipv6;
pub mod udp;

