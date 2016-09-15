// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Provides interfaces for interacting with packets and headers

#![macro_use]

use std::ops::{Index, IndexMut, Range, RangeTo, RangeFrom, RangeFull};

/// Represents a generic network packet
pub trait Packet {
    /// Retreive the underlying buffer for the packet
    fn packet(&self) -> &[u8];

    /// Retreive the payload for the packet
    fn payload(&self) -> &[u8];
}

/// Represents a generic, mutable, network packet
pub trait MutablePacket: Packet {
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
pub trait FromPacket: Packet {
    /// The type of the packet to convert from
    type T;

    /// Converts a wire-format packet to #[packet] struct format
    fn from_packet(&self) -> Self::T;
}

/// Used to find the calculated size of the packet. This is used for occasions where the underlying
/// buffer is not the same length as the packet itself.
pub trait PacketSize: Packet {
    /// Get the calculated size of the packet
    fn packet_size(&self) -> usize;
}

macro_rules! impl_index {
    ($t:ident, $index_t:ty, $output_t:ty) => {
        impl<'p> Index<$index_t> for $t<'p> {
            type Output = $output_t;

            fn index(&self, index: $index_t) -> &$output_t {
                &self.as_slice().index(index)
            }
        }
    };
}

macro_rules! impl_index_mut {
    ($t:ident, $index_t:ty, $output_t:ty) => {
        impl<'p> IndexMut<$index_t> for $t<'p> {
            fn index_mut(&mut self, index: $index_t) -> &mut $output_t {
                self.as_mut_slice().index_mut(index)
            }
        }
    };
}

#[derive(PartialEq)]
enum PacketData<'p> {
    Owned(Vec<u8>),
    Borrowed(&'p [u8])
}

impl<'p> PacketData<'p> {
    fn as_slice(&self) -> &[u8] {
        match self {
            &PacketData::Owned(ref data) => data.as_slice(),
            &PacketData::Borrowed(ref data) => data,
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }
}

impl_index!(PacketData, usize, u8);
impl_index!(PacketData, Range<usize>, [u8]);
impl_index!(PacketData, RangeTo<usize>, [u8]);
impl_index!(PacketData, RangeFrom<usize>, [u8]);
impl_index!(PacketData, RangeFull, [u8]);

#[derive(PartialEq)]
enum MutPacketData<'p> {
    Owned(Vec<u8>),
    Borrowed(&'p mut [u8])
}

impl<'p> MutPacketData<'p> {
    fn as_slice(&self) -> &[u8] {
        match self {
            &MutPacketData::Owned(ref data) => data.as_slice(),
            &MutPacketData::Borrowed(ref data) => data,
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            &mut MutPacketData::Owned(ref mut data) => data.as_mut_slice(),
            &mut MutPacketData::Borrowed(ref mut data) => data,
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }
}

impl_index!(MutPacketData, usize, u8);
impl_index!(MutPacketData, Range<usize>, [u8]);
impl_index!(MutPacketData, RangeTo<usize>, [u8]);
impl_index!(MutPacketData, RangeFrom<usize>, [u8]);
impl_index!(MutPacketData, RangeFull, [u8]);

impl_index_mut!(MutPacketData, usize, u8);
impl_index_mut!(MutPacketData, Range<usize>, [u8]);
impl_index_mut!(MutPacketData, RangeTo<usize>, [u8]);
impl_index_mut!(MutPacketData, RangeFrom<usize>, [u8]);
impl_index_mut!(MutPacketData, RangeFull, [u8]);


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
pub mod gre;
pub mod ip;
pub mod ipv4;
pub mod ipv6;
pub mod udp;
pub mod tcp;
pub mod arp;
pub mod icmp;
pub mod vlan;
