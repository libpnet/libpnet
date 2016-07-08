// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Miscellaneous utilities for low level networking

extern crate libc;

use packet::PrimitiveValues;

use std::fmt;
use std::str::FromStr;
use std::u8;
use std::net::IpAddr;


/// A MAC address
#[derive(PartialEq, Eq, Clone, Copy, Hash)]
pub struct MacAddr(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddr {
    /// Construct a new MacAddr
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddr {
        MacAddr(a, b, c, d, e, f)
    }
}

impl PrimitiveValues for MacAddr {
    type T = (u8, u8, u8, u8, u8, u8);
    fn to_primitive_values(&self) -> (u8, u8, u8, u8, u8, u8) {
        (self.0, self.1, self.2, self.3, self.4, self.5)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,
               "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
               self.0,
               self.1,
               self.2,
               self.3,
               self.4,
               self.5)
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

// FIXME Is this the right way to do this? Which occurs is an implementation
//       issue rather than actually defined - is it useful to provide these
//       errors, or would it be better to just give ()?
/// Represents an error which occurred whilst parsing a MAC address
#[derive(Copy, Debug, PartialEq, Eq, Clone)]
pub enum ParseMacAddrErr {
    /// The MAC address has too many components, eg. 00:11:22:33:44:55:66
    TooManyComponents,
    /// The MAC address has too few components, eg. 00:11
    TooFewComponents,
    /// One of the components contains an invalid value, eg. 00:GG:22:33:44:55
    InvalidComponent,
}

impl FromStr for MacAddr {
    type Err = ParseMacAddrErr;
    fn from_str(s: &str) -> Result<MacAddr, ParseMacAddrErr> {
        let mut parts = [0u8; 6];
        let splits = s.split(':');
        let mut i = 0;
        for split in splits {
            if i == 6 {
                return Err(ParseMacAddrErr::TooManyComponents);
            }
            match u8::from_str_radix(split, 16) {
                Ok(b) if split.len() != 0 => parts[i] = b,
                _ => return Err(ParseMacAddrErr::InvalidComponent),
            }
            i += 1;
        }

        if i == 6 {
            Ok(MacAddr(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]))
        } else {
            Err(ParseMacAddrErr::TooFewComponents)
        }
    }
}

#[test]
fn mac_addr_from_str() {
    assert_eq!("00:00:00:00:00:00".parse(), Ok(MacAddr(0, 0, 0, 0, 0, 0)));
    assert_eq!("ff:ff:ff:ff:ff:ff".parse(),
               Ok(MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)));
    assert_eq!("12:34:56:78:90:ab".parse(),
               Ok(MacAddr(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB)));
    assert_eq!("::::::".parse::<MacAddr>(),
               Err(ParseMacAddrErr::InvalidComponent));
    assert_eq!("0::::::".parse::<MacAddr>(),
               Err(ParseMacAddrErr::InvalidComponent));
    assert_eq!("::::0::".parse::<MacAddr>(),
               Err(ParseMacAddrErr::InvalidComponent));
    assert_eq!("12:34:56:78".parse::<MacAddr>(),
               Err(ParseMacAddrErr::TooFewComponents));
    assert_eq!("12:34:56:78:".parse::<MacAddr>(),
               Err(ParseMacAddrErr::InvalidComponent));
    assert_eq!("12:34:56:78:90".parse::<MacAddr>(),
               Err(ParseMacAddrErr::TooFewComponents));
    assert_eq!("12:34:56:78:90:".parse::<MacAddr>(),
               Err(ParseMacAddrErr::InvalidComponent));
    assert_eq!("12:34:56:78:90:00:00".parse::<MacAddr>(),
               Err(ParseMacAddrErr::TooManyComponents));
    assert_eq!("xx:xx:xx:xx:xx:xx".parse::<MacAddr>(),
               Err(ParseMacAddrErr::InvalidComponent));
}

/// Represents a network interface and its associated addresses
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct NetworkInterface {
    /// The name of the interface
    pub name: String,
    /// The interface index (operating system specific)
    pub index: u32,
    /// A MAC address for the interface
    pub mac: Option<MacAddr>,
    /// An IP addresses for the interface
    pub ips: Option<Vec<IpAddr>>,
    /// Operating system specific flags for the interface
    pub flags: u32,
}

impl NetworkInterface {
    /// Retrieve the MAC address associated with the interface
    pub fn mac_address(&self) -> MacAddr {
        self.mac.unwrap()
    }

    /// Is the interface a loopback interface?
    pub fn is_loopback(&self) -> bool {
        self.flags & (libc::IFF_LOOPBACK as u32) != 0
    }
}

#[cfg(windows)]
#[path = "datalink/winpcap.rs"]
mod ifaces;

#[cfg(not(windows))]
#[path = "datalink/ifaces.rs"]
mod ifaces;

/// Get a list of available network interfaces for the current machine.
/// Deprecated. Instead use the implementation available for your backend.
/// The default one is at `pnet::datalink::interfaces`.
#[deprecated]
#[inline]
pub fn get_network_interfaces() -> Vec<NetworkInterface> {
    ifaces::interfaces()
}

/// Convert value to byte array
pub trait Octets {
    /// Output type - bytes array
    type Output;

    /// Return value as bytes (big-endian order)
    fn octets(&self) -> Self::Output;
}

impl Octets for u64 {
    type Output = [u8; 8];

    fn octets(&self) -> Self::Output {
        [(*self >> 56) as u8, (*self >> 48) as u8, (*self >> 40) as u8, (*self >> 32) as u8,
         (*self >> 24) as u8, (*self >> 16) as u8, (*self >> 8) as u8, *self as u8]
    }
}

impl Octets for u32 {
    type Output = [u8; 4];

    fn octets(&self) -> Self::Output {
        [(*self >> 24) as u8, (*self >> 16) as u8 , (*self >> 8) as u8, *self as u8]
    }
}

impl Octets for u16 {
    type Output = [u8; 2];

    fn octets(&self) -> Self::Output {
        [(*self >> 8) as u8, *self as u8]
    }
}

impl Octets for u8 {
    type Output = [u8; 1];

    fn octets(&self) -> Self::Output {
        [*self]
    }
}
