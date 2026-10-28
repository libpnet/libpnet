// Copyright (c) 2014-2016 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Interface listing implementation for all non-Windows platforms.

use crate::{MacAddr, NetworkInterface};

use ipnetwork::{ip_mask_to_prefix, IpNetwork};
use pnet_sys;

use libc;

use std::ffi::CStr;
use std::mem;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::os::raw::c_char;

/// Get a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<NetworkInterface> {
    let mut addrs: MaybeUninit<*mut libc::ifaddrs> = MaybeUninit::uninit();

    // Safety: addrs.as_mut_ptr() is valid, it points to addrs.
    if unsafe { libc::getifaddrs(addrs.as_mut_ptr()) } != 0 {
        return Vec::new();
    }

    // Safety: If there was an error, we would have already returned.
    // Therefore, getifaddrs has initialized `addrs`.
    let addrs = unsafe { addrs.assume_init() };

    // Safety: getifaddrs initialized the linked list, which remains allocated
    // until freeifaddrs below.
    let ifaces = unsafe { interfaces_from_addrs(addrs) };

    // Safety: addrs has been previously allocated through getifaddrs
    unsafe {
        libc::freeifaddrs(addrs);
    }

    ifaces
}

// Safety: addrs must point to a valid getifaddrs-style linked list for this call.
unsafe fn interfaces_from_addrs(addrs: *mut libc::ifaddrs) -> Vec<NetworkInterface> {
    fn merge(old: &mut NetworkInterface, new: &NetworkInterface) {
        old.mac = match new.mac {
            None => old.mac,
            _ => new.mac,
        };
        old.ips.extend_from_slice(&new.ips[..]);
        old.flags = old.flags | new.flags;
    }

    let mut ifaces: Vec<(&CStr, NetworkInterface)> = Vec::new();
    let mut addr = addrs;
    while !addr.is_null() {
        // Safety: We assume that addr is valid for the lifetime of this loop
        // body, and is not mutated.
        let addr_ref: &libc::ifaddrs = unsafe { &*addr };

        let c_str = addr_ref.ifa_name as *const c_char;

        // Safety: ifa_name is a null terminated interface name
        let name = unsafe { CStr::from_ptr(c_str) };
        let (mac, ip) = sockaddr_to_network_addr(addr_ref.ifa_addr as *const libc::sockaddr);
        let (_, netmask) = sockaddr_to_network_addr(addr_ref.ifa_netmask as *const libc::sockaddr);
        let prefix = netmask
            .and_then(|netmask| ip_mask_to_prefix(netmask).ok())
            .unwrap_or(0);
        let network = ip.and_then(|ip| IpNetwork::new(ip, prefix).ok());
        let ni = NetworkInterface {
            name: name.to_string_lossy().into_owned(),
            description: "".to_string(),
            // Safety: ifa_name is a valid null-terminated interface name.
            index: unsafe { libc::if_nametoindex(c_str) },
            mac: mac,
            ips: network.into_iter().collect(),
            flags: addr_ref.ifa_flags,
        };
        let mut found: bool = false;
        for (old_name, iface) in &mut ifaces {
            if name == *old_name {
                merge(iface, &ni);
                found = true;
            }
        }
        if !found {
            ifaces.push((name, ni));
        }

        addr = addr_ref.ifa_next;
    }

    ifaces.into_iter().map(|(_, iface)| iface).collect()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn sockaddr_to_network_addr(sa: *const libc::sockaddr) -> (Option<MacAddr>, Option<IpAddr>) {
    use std::net::SocketAddr;

    unsafe {
        if sa.is_null() {
            (None, None)
        } else if (*sa).sa_family as libc::c_int == libc::AF_PACKET {
            let sll: *const libc::sockaddr_ll = mem::transmute(sa);
            let mac = MacAddr(
                (*sll).sll_addr[0],
                (*sll).sll_addr[1],
                (*sll).sll_addr[2],
                (*sll).sll_addr[3],
                (*sll).sll_addr[4],
                (*sll).sll_addr[5],
            );

            (Some(mac), None)
        } else {
            let addr = pnet_sys::sockaddr_to_addr(
                mem::transmute(sa),
                mem::size_of::<libc::sockaddr_storage>(),
            );

            match addr {
                Ok(SocketAddr::V4(sa)) => (None, Some(IpAddr::V4(*sa.ip()))),
                Ok(SocketAddr::V6(sa)) => (None, Some(IpAddr::V6(*sa.ip()))),
                Err(_) => (None, None),
            }
        }
    }
}

#[cfg(any(
    target_os = "openbsd",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "illumos",
    target_os = "solaris",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos"
))]
fn sockaddr_to_network_addr(sa: *const libc::sockaddr) -> (Option<MacAddr>, Option<IpAddr>) {
    use crate::bindings::bpf;
    use std::net::SocketAddr;

    unsafe {
        if sa.is_null() {
            (None, None)
        } else if (*sa).sa_family as libc::c_int == bpf::AF_LINK {
            let sdl: *const bpf::sockaddr_dl = mem::transmute(sa);
            let nlen = (*sdl).sdl_nlen as usize;
            let mac = MacAddr(
                (*sdl).sdl_data[nlen] as u8,
                (*sdl).sdl_data[nlen + 1] as u8,
                (*sdl).sdl_data[nlen + 2] as u8,
                (*sdl).sdl_data[nlen + 3] as u8,
                (*sdl).sdl_data[nlen + 4] as u8,
                (*sdl).sdl_data[nlen + 5] as u8,
            );

            (Some(mac), None)
        } else {
            let addr = pnet_sys::sockaddr_to_addr(
                mem::transmute(sa),
                mem::size_of::<libc::sockaddr_storage>(),
            );

            match addr {
                Ok(SocketAddr::V4(sa)) => (None, Some(IpAddr::V4(*sa.ip()))),
                Ok(SocketAddr::V6(sa)) => (None, Some(IpAddr::V6(*sa.ip()))),
                Err(_) => (None, None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(name: &CStr, flags: libc::c_uint) -> libc::ifaddrs {
        // Safety: zero initializes only integer fields and nullable pointers.
        let mut addr: libc::ifaddrs = unsafe { mem::zeroed() };
        addr.ifa_name = name.as_ptr() as *mut c_char;
        addr.ifa_flags = flags;
        addr
    }

    #[test]
    fn non_utf8_names_are_lossy_without_merging_distinct_interfaces() {
        let first_name = CStr::from_bytes_with_nul(b"eth\xff0\0").unwrap();
        let second_name = CStr::from_bytes_with_nul(b"eth\xfe0\0").unwrap();
        let mut repeated = address(first_name, 4);
        let mut second = address(second_name, 2);
        second.ifa_next = &mut repeated;
        let mut first = address(first_name, 1);
        first.ifa_next = &mut second;

        // Safety: all names and linked-list entries outlive the call, and all
        // optional socket addresses are null.
        let interfaces = unsafe { interfaces_from_addrs(&mut first) };
        assert_eq!(interfaces.len(), 2);
        assert_eq!(interfaces[0].name.as_bytes(), "eth\u{fffd}0".as_bytes());
        assert_eq!(interfaces[1].name.as_bytes(), "eth\u{fffd}0".as_bytes());
        assert_eq!(interfaces[0].flags, 5);
        assert_eq!(interfaces[1].flags, 2);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn utf8_name_retains_its_interface_index() {
        let name = CStr::from_bytes_with_nul(b"lo\0").unwrap();
        let mut addr = address(name, 0);
        // Safety: addr and its name outlive the call; socket addresses are null.
        let interfaces = unsafe { interfaces_from_addrs(&mut addr) };
        // Safety: name is a valid C string.
        let expected = unsafe { libc::if_nametoindex(name.as_ptr()) };
        assert_ne!(expected, 0);
        assert_eq!(interfaces[0].index, expected);
        assert_eq!(interfaces[0].name, "lo");
    }
}
