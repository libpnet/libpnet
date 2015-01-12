// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Ethernet packet abstraction

use std::fmt;
use packet::{Packet, MutablePacket};
use util::MacAddr;

/// A structure which represents an Ethernet header
pub struct EthernetHeader<'p> {
    packet: &'p [u8],
}
impl<'p> Copy for EthernetHeader<'p> {}

// FIXME This should probably be a macro
// FIXME What should be the proper behaviour of this?
//        - Compare whole packet?
//        - Compare just header?
//        - Compare non-volatile bits of header? (ignore ttl etc)
impl<'p> PartialEq for EthernetHeader<'p> {
    fn eq(&self, other: &EthernetHeader) -> bool {
        if self.packet.len() != other.packet.len() {
            return false;
        }
        for (b1, b2) in self.packet.iter()
                        .zip(other.packet.iter()) {
            if b1 != b2 {
                return false;
            }
        }
        return true;
    }
}
impl<'p> Eq for EthernetHeader<'p> {}

impl<'p> fmt::String for EthernetHeader<'p> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,
               "EthernetHeader {{ destination: {}, source: {}, ethertype: {} }}",
               self.get_destination(),
               self.get_source(),
               self.get_ethertype())
    }
}

// NOTE Copy/pasted from above.
impl<'p> fmt::String for MutableEthernetHeader<'p> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,
               "MutableEthernetHeader {{ destination: {}, source: {}, ethertype: {} }}",
               self.get_destination(),
               self.get_source(),
               self.get_ethertype())
    }
}

/// A structure representing an Ethernet header which can be mutated
pub struct MutableEthernetHeader<'p> {
    packet: &'p mut [u8],
}

impl<'a> Packet for EthernetHeader<'a> {
    #[inline(always)]
    fn packet<'p>(&'p self) -> &'p [u8] { self.packet }

    #[inline(always)]
    fn payload<'p>(&'p self) -> &'p [u8] { self.packet.slice_from(14) }
}

impl<'a> Packet for MutableEthernetHeader<'a> {
    #[inline(always)]
    fn packet<'p>(&'p self) -> &'p [u8] { self.packet.as_slice() }

    #[inline(always)]
    fn payload<'p>(&'p self) -> &'p [u8] { self.packet.slice_from(14) }
}

impl<'a> MutablePacket for MutableEthernetHeader<'a> {
    #[inline(always)]
    fn packet_mut<'p>(&'p mut self) -> &'p mut [u8] { self.packet.as_mut_slice() }

    #[inline(always)]
    fn payload_mut<'p>(&'p mut self) -> &'p mut [u8] { self.packet.slice_from_mut(14) }
}

/// A trait implemented by anything which provides the ability to retrieve
/// fields of an Ethernet packet
pub trait EthernetPacket : Packet {
    /// Get the destination address for an Ethernet packet
    fn get_destination(&self) -> MacAddr {
        MacAddr(
            self.packet()[0],
            self.packet()[1],
            self.packet()[2],
            self.packet()[3],
            self.packet()[4],
            self.packet()[5]
        )
    }

    /// Get the source address for an Ethernet packet
    fn get_source(&self) -> MacAddr {
        MacAddr(
            self.packet()[6],
            self.packet()[7],
            self.packet()[8],
            self.packet()[9],
            self.packet()[10],
            self.packet()[11]
        )
    }

    /// Get the Ethertype field of an Ethernet packet
    fn get_ethertype(&self) -> EtherType {
        EtherType(((self.packet()[12] as u16) << 8) | (self.packet()[13] as u16))
    }
}

impl<'p> EthernetPacket for EthernetHeader<'p> {}
impl<'p> EthernetPacket for MutableEthernetHeader<'p> {}

impl<'p> EthernetHeader<'p> {
    /// Construct a new Ethernet header backed by the given buffer with the
    /// provided offset
    pub fn new(packet: &'p [u8]) -> EthernetHeader<'p> {
        EthernetHeader { packet: packet }
    }
}

impl<'p> MutableEthernetHeader<'p> {
    /// Construct a new mutable Ethernet header backed by the given buffer with
    /// the provided offset
    pub fn new(packet: &'p mut [u8]) -> MutableEthernetHeader<'p> {
        MutableEthernetHeader { packet: packet }
    }

    /// Set the source address for an Ethernet packet
    pub fn set_source(&mut self, mac: MacAddr) {
        match mac {
            MacAddr(a, b, c, d, e, f) => {
                self.packet[6] = a;
                self.packet[7] = b;
                self.packet[8] = c;
                self.packet[9] = d;
                self.packet[10] = e;
                self.packet[11] = f;
            }
        }
    }

    /// Set the destination address for an Ethernet packet
    pub fn set_destination(&mut self, mac: MacAddr) {
        match mac {
            MacAddr(a, b, c, d, e, f) => {
                self.packet[0] = a;
                self.packet[1] = b;
                self.packet[2] = c;
                self.packet[3] = d;
                self.packet[4] = e;
                self.packet[5] = f;
            }
        }
    }

    /// Set the Ethertype for an Ethernet packet
    pub fn set_ethertype(&mut self, EtherType(ethertype): EtherType) {
        self.packet[12] = (ethertype >> 8) as u8;
        self.packet[13] = (ethertype & 0xFF) as u8;
    }
}

#[test]
fn ethernet_header_test() {
    let mut packet = [0u8; 14];
    {
        let mut ethernet_header = MutableEthernetHeader::new(packet.as_mut_slice());

        let source = MacAddr(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        ethernet_header.set_source(source);
        assert_eq!(ethernet_header.get_source(), source);

        let dest = MacAddr(0xde, 0xf0, 0x12, 0x34, 0x45, 0x67);
        ethernet_header.set_destination(dest);
        assert_eq!(ethernet_header.get_destination(), dest);

        ethernet_header.set_ethertype(EtherTypes::Ipv6);
        assert_eq!(ethernet_header.get_ethertype(), EtherTypes::Ipv6);
    }

    let ref_packet = [0xde, 0xf0, 0x12, 0x34, 0x45, 0x67, /* destination */
                      0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, /* source */
                      0x86, 0xdd /* ethertype */];
    assert_eq!(ref_packet.as_slice(), packet.as_slice());
}

/// EtherTypes defined at:
/// http://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
/// These values should be used in the Ethernet EtherType field
///
/// FIXME Should include all
/// A handful of these have been selected since most are archaic and unused.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod EtherTypes {
    use packet::ethernet::EtherType;

    pub const Ipv4: EtherType      = EtherType(0x0800);
    pub const Arp: EtherType       = EtherType(0x0806);
    pub const WakeOnLan: EtherType = EtherType(0x0842);
    pub const Rarp: EtherType      = EtherType(0x8035);
    pub const Ipv6: EtherType      = EtherType(0x86DD);
}

/// Represents the Ethernet ethertype field.
#[derive(Show, PartialEq, Eq, PartialOrd, Ord)]
pub struct EtherType(pub u16);
impl Copy for EtherType {}

impl fmt::String for EtherType {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let EtherType(ethertype) = *self;
        write!(fmt, "{}", ethertype)
    }
}

