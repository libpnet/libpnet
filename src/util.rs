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
use datalink::NetworkInterface;

use std::fmt;
use std::str::FromStr;
use std::u8;
use std::net::IpAddr;
use std::mem;

use internal;
use sockets;

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

#[cfg(target_os = "linux")]
fn sockaddr_to_network_addr(sa: *const sockets::SockAddr) -> (Option<MacAddr>, Option<IpAddr>) {
    use std::net::SocketAddr;

    unsafe {
        if sa.is_null() {
            (None, None)
        } else if (*sa).sa_family as libc::c_int == libc::AF_PACKET {
            let sll: *const libc::sockaddr_ll = mem::transmute(sa);
            let mac = MacAddr((*sll).sll_addr[0],
                              (*sll).sll_addr[1],
                              (*sll).sll_addr[2],
                              (*sll).sll_addr[3],
                              (*sll).sll_addr[4],
                              (*sll).sll_addr[5]);

            (Some(mac), None)
        } else {
            let addr = internal::sockaddr_to_addr(mem::transmute(sa),
                                                  mem::size_of::<sockets::SockAddrStorage>());

            match addr {
                Ok(SocketAddr::V4(sa)) => (None, Some(IpAddr::V4(*sa.ip()))),
                Ok(SocketAddr::V6(sa)) => (None, Some(IpAddr::V6(*sa.ip()))),
                Err(_) => (None, None),
            }
        }
    }
}

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
fn sockaddr_to_network_addr(sa: *const sockets::SockAddr) -> (Option<MacAddr>, Option<IpAddr>) {
    use bindings::bpf;
    use std::net::SocketAddr;

    unsafe {
        if sa.is_null() {
            (None, None)
        } else if (*sa).sa_family as libc::c_int == bpf::AF_LINK {
            let sdl: *const bpf::sockaddr_dl = mem::transmute(sa);
            let nlen = (*sdl).sdl_nlen as usize;
            let mac = MacAddr((*sdl).sdl_data[nlen] as u8,
                              (*sdl).sdl_data[nlen + 1] as u8,
                              (*sdl).sdl_data[nlen + 2] as u8,
                              (*sdl).sdl_data[nlen + 3] as u8,
                              (*sdl).sdl_data[nlen + 4] as u8,
                              (*sdl).sdl_data[nlen + 5] as u8);

            (Some(mac), None)
        } else {
            let addr = internal::sockaddr_to_addr(mem::transmute(sa),
                                                  mem::size_of::<sockets::SockAddrStorage>());

            match addr {
                Ok(SocketAddr::V4(sa)) => (None, Some(IpAddr::V4(*sa.ip()))),
                Ok(SocketAddr::V6(sa)) => (None, Some(IpAddr::V6(*sa.ip()))),
                Err(_) => (None, None),
            }
        }
    }
}

/// Get a list of available network interfaces for the current machine.
/// Deprecated. Instead use the implementation available for your backend.
/// The default one is at `pnet::datalink::interfaces`.
#[deprecated(note="Moved to datalink::interfaces()")]
#[inline]
pub fn get_network_interfaces() -> Vec<NetworkInterface> {
    ::datalink::interfaces()
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
