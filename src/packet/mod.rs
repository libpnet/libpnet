// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
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
    fn packet(&self) -> &[u8];

    /// Retreive the payload for the packet
    fn payload(&self) -> &[u8];
}

/// Represents a generic, mutable, network packet
pub trait MutablePacket : Packet {
    /// Retreive the underlying, mutable, buffer for the packet
    fn packet_mut(&mut self) -> &mut [u8];

    /// Retreive the mutable payload for the packet
    fn payload_mut(&mut self) -> &mut [u8];

    /// Initialize this packet by cloning another
    fn clone_from<T: Packet>(&mut self, other: &T) {
        use std::ptr;

        assert!(self.packet().len() >= other.packet().len());
        unsafe {
            ptr::copy_nonoverlapping(other.packet().as_ptr(),
                                     self.packet_mut().as_mut_ptr(),
                                     other.packet().len());
        }
    }
}

/// Used to convert on-the-wire packets to their #[packet] equivalent
pub trait FromPacket : Packet {
    /// The type of the packet to convert from
    type T;

    /// Converts a wire-format packet to #[packet] struct format
    fn from_packet(&self) -> Self::T;
}

/// Used to find the calculated size of the packet. This is used for occasions where the underlying
/// buffer is not the same length as the packet itself.
pub trait PacketSize : Packet {
    /// Get the calculated size of the packet
    fn packet_size(&self) -> usize;
}

/// Used to convert a type to primitive values representing it
pub trait PrimitiveValues {
    /// A tuple of types, to represent the current value
    type T;

    /// Convert a value to primitive types representing it
    fn to_primitive_values(&self) -> Self::T;
}

impl PrimitiveValues for ::std::net::Ipv4Addr {
    type T = (u8, u8, u8, u8);
    fn to_primitive_values(&self) -> (u8, u8, u8, u8) {
        let octets = self.octets();

        (octets[0], octets[1], octets[2], octets[3])
    }
}

impl PrimitiveValues for ::std::net::Ipv6Addr {
    type T = (u16, u16, u16, u16, u16, u16, u16, u16);
    fn to_primitive_values(&self) -> (u16, u16, u16, u16, u16, u16, u16, u16) {
        let segments = self.segments();

        (segments[0],
         segments[1],
         segments[2],
         segments[3],
         segments[4],
         segments[5],
         segments[6],
         segments[7])
    }
}

pub mod ethernet;
pub mod ip;
pub mod ipv4;
pub mod ipv6;
pub mod udp;
pub mod tcp;
