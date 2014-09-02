// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Miscellaneous utilities for low level networking

use bindings::libc;

//use libc::consts::os::bsd44 as bsd44;
use std::fmt;
use std::mem;
use std::io::net::ip::IpAddr;

#[cfg(not(windows))] use internal;

/// A MAC address
#[deriving(PartialEq, Eq, Clone)]
pub enum MacAddr {
    /// A MAC address
    MacAddr(u8, u8, u8, u8, u8, u8)
}

impl fmt::Show for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MacAddr(a, b, c, d, e, f) =>
                write!(fmt, "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                       a, b, c, d, e, f)
        }
    }
}

/// Represents a network interface and its associated addresses
#[deriving(Clone, PartialEq, Eq, Show)]
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
    /// Retreive the MAC address associated with the interface
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
    unsafe {
        if sa.is_null() {
            (None, None)
        } else if (*sa).sa_family as libc::c_int == libc::AF_PACKET {
            let sll: *const libc::sockaddr_ll = mem::transmute(sa);
            let mac = MacAddr((*sll).sll_addr[0], (*sll).sll_addr[1],
                              (*sll).sll_addr[2], (*sll).sll_addr[3],
                              (*sll).sll_addr[4], (*sll).sll_addr[5]);
            return (Some(mac), None);
        } else {
            let addr = internal::sockaddr_to_addr(mem::transmute(sa),
                                        mem::size_of::<libc::sockaddr_storage>());
            return match addr {
                Ok(sa) => (None, Some(sa.ip)),
                Err(_) => (None, None)
            };
        }
    }
}

#[cfg(target_os = "freebsd")]
#[cfg(target_os = "macos")]
fn sockaddr_to_network_addr(sa: *const libc::sockaddr) -> (Option<MacAddr>, Option<IpAddr>) {
    use bindings::bpf;
    unsafe {
        if sa.is_null() {
            (None, None)
        } else if (*sa).sa_family as libc::c_int == bpf::AF_LINK {
            let sdl: *const bpf::sockaddr_dl = mem::transmute(sa);
            let nlen = (*sdl).sdl_nlen as uint;
            let mac = MacAddr((*sdl).sdl_data[nlen + 0] as u8,
                              (*sdl).sdl_data[nlen + 1] as u8,
                              (*sdl).sdl_data[nlen + 2] as u8,
                              (*sdl).sdl_data[nlen + 3] as u8,
                              (*sdl).sdl_data[nlen + 4] as u8,
                              (*sdl).sdl_data[nlen + 5] as u8
                      );
            (Some(mac), None)
        } else {
            let addr = internal::sockaddr_to_addr(mem::transmute(sa),
                                        mem::size_of::<libc::sockaddr_storage>());
            match addr {
                Ok(sa) => (None, Some(sa.ip)),
                Err(_) => (None, None)
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
    use std::string::raw as strraw;

    let mut ifaces: Vec<NetworkInterface> = Vec::new();
    unsafe {
        let mut addrs: *mut libc::ifaddrs = mem::uninitialized();
        if libc::getifaddrs(&mut addrs) != 0 {
            return ifaces;
        }
        let mut addr = addrs;
        while addr.is_not_null() {
            let name = strraw::from_buf((*addr).ifa_name as *const u8);
            let (mac, ip) = sockaddr_to_network_addr((*addr).ifa_addr as *const libc::sockaddr);
            let ni = NetworkInterface {
                name: name.clone(),
                index: 0,
                mac: mac,
                ips: ip.map(|ip| Vec::from_slice([ip])),
                flags: (*addr).ifa_flags
            };
            let mut found: bool = false;
            for iface in ifaces.mut_iter() {
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

        for iface in ifaces.mut_iter() {
            iface.index = iface.name.with_c_str(
                |name| libc::if_nametoindex(name)
            );
        }
        return ifaces;
    }

    fn merge(old: &mut NetworkInterface, new: &NetworkInterface) {
        old.mac = match new.mac {
            None => old.mac,
            _ => new.mac
        };
        match (&mut old.ips, &new.ips) {
            (&Some(ref mut old_ips), &Some(ref new_ips)) => old_ips.push_all(new_ips.as_slice()),
            _ => {}
        };
        old.flags = old.flags | new.flags;
    }

}

#[cfg(windows)]
fn get_network_interfaces_impl() -> Vec<NetworkInterface> {
    use std::str::from_utf8;
    use std::string::raw;

    use bindings::winpcap;

    let mut adapters_size = 0u32;

    unsafe {
        let mut tmp: winpcap::IP_ADAPTER_INFO = mem::zeroed();
        // FIXME [windows] This only gets IPv4 addresses - should use GetAdaptersAddresses
        winpcap::GetAdaptersInfo(
            &mut tmp,
            &mut adapters_size
        );
    }


    let vec_size = adapters_size / mem::size_of::<winpcap::IP_ADAPTER_INFO>() as u32;

    let mut adapters = Vec::with_capacity(vec_size as uint);

    // FIXME [windows] Check return code
    unsafe {
        winpcap::GetAdaptersInfo(adapters.as_mut_ptr(), &mut adapters_size);
    }

    // Create a complete list of NetworkInterfaces for the machine
    let mut cursor = adapters.as_mut_ptr();
    let mut all_ifaces = Vec::with_capacity(vec_size as uint);
    while cursor.is_not_null() {
        let mac = unsafe {
                    MacAddr((*cursor).Address[0],
                            (*cursor).Address[1],
                            (*cursor).Address[2],
                            (*cursor).Address[3],
                            (*cursor).Address[4],
                            (*cursor).Address[5])
                  };
        let mut ip_cursor = unsafe { &mut (*cursor).IpAddressList as winpcap::PIP_ADDR_STRING};
        let mut ips: Vec<IpAddr> = Vec::new();
        while ip_cursor.is_not_null() {
            let ip_str = unsafe {
                            raw::from_buf((*ip_cursor).IpAddress.String.as_ptr() as *const u8)
                         };
            ips.push(from_str(ip_str.as_slice()).unwrap());
            ip_cursor = unsafe { (*ip_cursor).Next };
        }
        unsafe {
            all_ifaces.push(NetworkInterface {
                        name: raw::from_buf((*cursor).AdapterName.as_ptr() as *const u8),
                        index: (*cursor).Index,
                        mac: Some(mac),
                        ips: Some(ips),
                        //flags: (*cursor).Type, // FIXME [windows]
                        flags: 0,
                     });

            cursor = (*cursor).Next;
        }
    }

    let mut buf = [0u8, ..4096];
    let mut buflen = buf.len() as u32;

    // Gets list of supported adapters in form:
    // adapter1\0adapter2\0\0desc1\0desc2\0\0
    if unsafe { winpcap::PacketGetAdapterNames(buf.as_mut_ptr() as *mut i8, &mut buflen) } == 0 {
        // FIXME [windows] Should allocate a buffer big enough and try again
        //        - size should be buf.len() + buflen (buflen is overwritten)
        fail!("FIXME [windows] unable to get interface list");
    }

    let buf_str = from_utf8(buf).unwrap();
    let iface_names = buf_str.split_str("\0\0").next();
    let mut vec = Vec::new();

    // Return only supported adapters
    match iface_names {
        Some(iface_names) => {
            for iface in iface_names.split('\0') {
                let name = iface.to_string();
                let next = all_ifaces.iter()
                                     .filter(|x| name.as_slice().ends_with(x.name.as_slice()))
                                     .next();
                if next.is_some() {
                    let mut iface = next.unwrap().clone();
                    iface.name = name;
                    vec.push(iface);
                }
            }
        },
        None => ()
    };

    vec
}

