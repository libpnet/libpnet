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

use std::ffi::CStr;
use std::fmt;
use std::str::{FromStr, from_utf8_unchecked};
use std::mem;
use std::u8;
use std::net::IpAddr;


#[cfg(not(windows))]
use internal;

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

#[cfg(target_os = "linux")]
fn sockaddr_to_network_addr(sa: *const libc::sockaddr) -> (Option<MacAddr>, Option<IpAddr>) {
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
                                                  mem::size_of::<libc::sockaddr_storage>());

            match addr {
                Ok(SocketAddr::V4(sa)) => (None, Some(IpAddr::V4(*sa.ip()))),
                Ok(SocketAddr::V6(sa)) => (None, Some(IpAddr::V6(*sa.ip()))),
                Err(_) => (None, None),
            }
        }
    }
}

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
fn sockaddr_to_network_addr(sa: *const libc::sockaddr) -> (Option<MacAddr>, Option<IpAddr>) {
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
                                                  mem::size_of::<libc::sockaddr_storage>());

            match addr {
                Ok(SocketAddr::V4(sa)) => (None, Some(IpAddr::V4(*sa.ip()))),
                Ok(SocketAddr::V6(sa)) => (None, Some(IpAddr::V6(*sa.ip()))),
                Err(_) => (None, None),
            }
        }
    }
}

/// Get a list of available network interfaces for the current machine.
#[inline]
pub fn get_network_interfaces() -> Vec<NetworkInterface> {
    get_network_interfaces_impl()
}

#[cfg(not(windows))]
fn get_network_interfaces_impl() -> Vec<NetworkInterface> {
    use std::ffi::CString;

    fn merge(old: &mut NetworkInterface, new: &NetworkInterface) {
        old.mac = match new.mac {
            None => old.mac,
            _ => new.mac,
        };
        match (&mut old.ips, &new.ips) {
            (&mut Some(ref mut old_ips), &Some(ref new_ips)) => {
                old_ips.extend_from_slice(&new_ips[..])
            }
            (&mut ref mut old_ips @ None, &Some(ref new_ips)) => *old_ips = Some(new_ips.clone()),
            _ => {}
        };
        old.flags = old.flags | new.flags;
    }

    let mut ifaces: Vec<NetworkInterface> = Vec::new();
    unsafe {
        let mut addrs: *mut libc::ifaddrs = mem::uninitialized();
        if libc::getifaddrs(&mut addrs) != 0 {
            return ifaces;
        }
        let mut addr = addrs;
        while !addr.is_null() {
            let c_str = (*addr).ifa_name as *const i8;
            let bytes = CStr::from_ptr(c_str).to_bytes();
            let name = from_utf8_unchecked(bytes).to_owned();
            let (mac, ip) = sockaddr_to_network_addr((*addr).ifa_addr as *const libc::sockaddr);
            let ni = NetworkInterface {
                name: name.clone(),
                index: 0,
                mac: mac,
                ips: ip.map(|ip| [ip].to_vec()),
                flags: (*addr).ifa_flags,
            };
            let mut found: bool = false;
            for iface in &mut ifaces {
                if name == iface.name {
                    merge(iface, &ni);
                    found = true;
                }
            }
            if !found {
                ifaces.push(ni);
            }

            addr = (*addr).ifa_next;
        }
        libc::freeifaddrs(addrs);

        for iface in &mut ifaces {
            let name = CString::new(iface.name.as_bytes());
            iface.index = libc::if_nametoindex(name.unwrap().as_ptr());
        }

        ifaces
    }
}

#[cfg(windows)]
fn get_network_interfaces_impl() -> Vec<NetworkInterface> {
    use bindings::winpcap;

    let mut adapters_size = 0u32;

    unsafe {
        let mut tmp: winpcap::IP_ADAPTER_INFO = mem::zeroed();
        // FIXME [windows] This only gets IPv4 addresses - should use
        // GetAdaptersAddresses
        winpcap::GetAdaptersInfo(&mut tmp, &mut adapters_size);
    }

    let vec_size = adapters_size / mem::size_of::<winpcap::IP_ADAPTER_INFO>() as u32;

    let mut adapters = Vec::with_capacity(vec_size as usize);

    // FIXME [windows] Check return code
    unsafe {
        winpcap::GetAdaptersInfo(adapters.as_mut_ptr(), &mut adapters_size);
    }

    // Create a complete list of NetworkInterfaces for the machine
    let mut cursor = adapters.as_mut_ptr();
    let mut all_ifaces = Vec::with_capacity(vec_size as usize);
    while !cursor.is_null() {
        let mac = unsafe {
            MacAddr((*cursor).Address[0],
                    (*cursor).Address[1],
                    (*cursor).Address[2],
                    (*cursor).Address[3],
                    (*cursor).Address[4],
                    (*cursor).Address[5])
        };
        let mut ip_cursor = unsafe { &mut (*cursor).IpAddressList as winpcap::PIP_ADDR_STRING };
        let mut ips: Vec<IpAddr> = Vec::new();
        while !ip_cursor.is_null() {
            let ip_str_ptr = unsafe { &(*ip_cursor) }.IpAddress.String.as_ptr() as *const i8;
            let bytes = unsafe { CStr::from_ptr(ip_str_ptr).to_bytes() };
            let ip_str = unsafe { from_utf8_unchecked(bytes).to_owned() };
            ips.push(ip_str.parse().unwrap());
            ip_cursor = unsafe { (*ip_cursor).Next };
        }

        unsafe {
            let name_str_ptr = (*cursor).AdapterName.as_ptr() as *const i8;

            let bytes = CStr::from_ptr(name_str_ptr).to_bytes();
            let name_str = from_utf8_unchecked(bytes).to_owned();

            all_ifaces.push(NetworkInterface {
                name: name_str,
                index: (*cursor).Index,
                mac: Some(mac),
                ips: Some(ips),
                // flags: (*cursor).Type, // FIXME [windows]
                flags: 0,
            });

            cursor = (*cursor).Next;
        }
    }

    let mut buf = [0u8; 4096];
    let mut buflen = buf.len() as u32;

    // Gets list of supported adapters in form:
    // adapter1\0adapter2\0\0desc1\0desc2\0\0
    if unsafe { winpcap::PacketGetAdapterNames(buf.as_mut_ptr() as *mut i8, &mut buflen) } == 0 {
        // FIXME [windows] Should allocate a buffer big enough and try again
        //        - size should be buf.len() + buflen (buflen is overwritten)
        panic!("FIXME [windows] unable to get interface list");
    }

    let buf_str = unsafe { from_utf8_unchecked(&buf) };
    let iface_names = buf_str.split("\0\0").next();
    let mut vec = Vec::new();

    // Return only supported adapters
    match iface_names {
        Some(iface_names) => {
            for iface in iface_names.split('\0') {
                let name = iface.to_owned();
                let next = all_ifaces.iter().filter(|x| name[..].ends_with(&x.name[..])).next();
                if next.is_some() {
                    let mut iface = next.unwrap().clone();
                    iface.name = name;
                    vec.push(iface);
                }
            }
        }
        None => (),
    };

    vec
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
