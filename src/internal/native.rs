// Copyright 2013-2014 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// These functions are taken/adapted from libnative::io::{mod, net}

extern crate libc;

use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};


///
/// sockaddr and misc bindings
///

fn htons(u: u16) -> u16 {
    u.to_be()
}
fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

fn make_in6_addr(segments: [u16; 8]) -> libc::in6_addr {
    let mut val: libc::in6_addr = unsafe { mem::uninitialized() };
    val.s6_addr = unsafe { mem::transmute([
        htons(segments[0]),
        htons(segments[1]),
        htons(segments[2]),
        htons(segments[3]),
        htons(segments[4]),
        htons(segments[5]),
        htons(segments[6]),
        htons(segments[7]),
    ]) };
    val
}

fn read_u16be(buf: &[u8]) -> u16 {
    ((buf[0] as u16) << 8) | (buf[1] as u16)
}

pub fn addr_to_sockaddr(addr: SocketAddr, storage: &mut libc::sockaddr_storage) -> libc::socklen_t {
    unsafe {
        let len = match addr {
            SocketAddr::V4(sa) => {
                let ip_addr = sa.ip();
                let octets = ip_addr.octets();
                let inaddr = libc::in_addr {
                    s_addr: u32::from_be(((octets[0] as u32) << 24) | ((octets[1] as u32) << 16) |
                                         ((octets[2] as u32) << 8) |
                                         (octets[3] as u32)),
                };
                let storage = storage as *mut _ as *mut libc::sockaddr_in;
                (*storage).sin_family = libc::AF_INET as libc::sa_family_t;
                (*storage).sin_port = htons(addr.port());
                (*storage).sin_addr = inaddr;
                mem::size_of::<libc::sockaddr_in>()
            }
            SocketAddr::V6(sa) => {
                let ip_addr = sa.ip();
                let segments = ip_addr.segments();
                let inaddr = make_in6_addr(segments);
                let storage = storage as *mut _ as *mut libc::sockaddr_in6;
                (*storage).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*storage).sin6_port = htons(addr.port());
                (*storage).sin6_addr = inaddr;
                mem::size_of::<libc::sockaddr_in6>()
            }
        };

        len as libc::socklen_t
    }
}

pub fn sockaddr_to_addr(storage: &libc::sockaddr_storage, len: usize) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            assert!(len as usize >= mem::size_of::<libc::sockaddr_in>());
            let storage: &libc::sockaddr_in = unsafe { mem::transmute(storage) };
            let ip = (storage.sin_addr.s_addr as u32).to_be();
            let a = (ip >> 24) as u8;
            let b = (ip >> 16) as u8;
            let c = (ip >> 8) as u8;
            let d = ip as u8;
            let sockaddrv4 = SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), ntohs(storage.sin_port));
            Ok(SocketAddr::V4(sockaddrv4))
        }
        libc::AF_INET6 => {
            assert!(len as usize >= mem::size_of::<libc::sockaddr_in6>());
            let storage: &libc::sockaddr_in6 = unsafe { mem::transmute(storage) };
            let a = ntohs(read_u16be(&storage.sin6_addr.s6_addr[0..2]));
            let b = ntohs(read_u16be(&storage.sin6_addr.s6_addr[2..4]));
            let c = ntohs(read_u16be(&storage.sin6_addr.s6_addr[4..6]));
            let d = ntohs(read_u16be(&storage.sin6_addr.s6_addr[6..8]));
            let e = ntohs(read_u16be(&storage.sin6_addr.s6_addr[8..10]));
            let f = ntohs(read_u16be(&storage.sin6_addr.s6_addr[10..12]));
            let g = ntohs(read_u16be(&storage.sin6_addr.s6_addr[12..14]));
            let h = ntohs(read_u16be(&storage.sin6_addr.s6_addr[14..16]));
            let ip = Ipv6Addr::new(a, b, c, d, e, f, g, h);
            Ok(SocketAddr::V6(SocketAddrV6::new(ip,
                                                ntohs(storage.sin6_port),
                                                u32::from_be(storage.sin6_flowinfo),
                                                u32::from_be(storage.sin6_scope_id))))
        }
        _ => {
            #[cfg(unix)]
            use libc::EINVAL as ERROR;
            #[cfg(windows)]
            use winapi::winerror::WSAEINVAL as ERROR;
            Err(io::Error::from_raw_os_error(ERROR))
        }
    }
}
