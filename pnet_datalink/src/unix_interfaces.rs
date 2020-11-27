// Copyright (c) 2014-2016 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Interface listing implementation for all non-Windows platforms.

use {MacAddr, NetworkInterface};

use ipnetwork::{ip_mask_to_prefix, IpNetwork};
use pnet_sys;

use libc;

use std::ffi::{CStr, CString};
use std::mem;
use std::net::IpAddr;
use std::os::raw::c_char;
use std::str::from_utf8_unchecked;

/// Get a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<NetworkInterface> {
    fn merge(old: &mut NetworkInterface, new: &NetworkInterface) {
        old.mac = match new.mac {
            None => old.mac,
            _ => new.mac,
        };
        old.ips.extend_from_slice(&new.ips[..]);
        old.flags = old.flags | new.flags;
    }

    let mut ifaces: Vec<NetworkInterface> = Vec::new();
    unsafe {
        #[allow(deprecated)]
        let mut addrs: *mut libc::ifaddrs = mem::uninitialized();
        if libc::getifaddrs(&mut addrs) != 0 {
            return ifaces;
        }
        let mut addr = addrs;
        while !addr.is_null() {
            let c_str = (*addr).ifa_name as *const c_char;
            let bytes = CStr::from_ptr(c_str).to_bytes();
            let name = from_utf8_unchecked(bytes).to_owned();
            let (mac, ip) = sockaddr_to_network_addr((*addr).ifa_addr as *const libc::sockaddr);
            let (_, netmask) =
                sockaddr_to_network_addr((*addr).ifa_netmask as *const libc::sockaddr);
            let prefix = netmask
                .and_then(|netmask| ip_mask_to_prefix(netmask).ok())
                .unwrap_or(0);
            let network = ip.and_then(|ip| IpNetwork::new(ip, prefix).ok());
            let ni = NetworkInterface {
                name: name.clone(),
                description: "".to_string(),
                index: 0,
                mac: mac,
                ips: network.into_iter().collect(),
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

#[cfg(any(target_os = "openbsd", target_os = "freebsd", target_os = "netbsd", target_os = "macos", target_os = "ios"))]
fn sockaddr_to_network_addr(sa: *const libc::sockaddr) -> (Option<MacAddr>, Option<IpAddr>) {
    use bindings::bpf;
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
