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

use internal::CSocket;

#[cfg(windows)]
pub unsafe fn close(sock: CSocket) {
    let _ = libc::closesocket(sock);
}
#[cfg(unix)]
pub unsafe fn close(sock: CSocket) {
    let _ = libc::close(sock);
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap()
}

#[cfg(windows)]
#[inline]
pub fn retry<F>(f: &mut F) -> libc::c_int
    where F: FnMut() -> libc::c_int
{
    loop {
        let minus1 = -1;
        let ret = f();
        if ret != minus1 || errno() as isize != libc::WSAEINTR as isize {
            return ret;
        }
    }
}

#[cfg(unix)]
#[inline]
pub fn retry<F>(f: &mut F) -> libc::ssize_t
    where F: FnMut() -> libc::ssize_t
{
    loop {
        let minus1 = -1;
        let ret = f();
        if ret != minus1 || errno() as isize != libc::EINTR as isize {
            return ret;
        }
    }
}

///
/// sockaddr and misc bindings
///

fn htons(u: u16) -> u16 {
    u.to_be()
}
fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

macro_rules! to_u8_array {
    ($($num:expr),*) => {
        if cfg!(target_endian = "big") {
            [ $(($num>>8) as u8, ($num&0xff) as u8,)* ]
        } else {
            [ $(($num&0xff) as u8, ($num>>8) as u8,)* ]
        }
    }
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
                let mut inaddr: libc::in6_addr = mem::uninitialized();
                inaddr.s6_addr = to_u8_array!(segments[0], segments[1],
                                              segments[2], segments[3],
                                              segments[4], segments[5],
                                              segments[6], segments[7]);
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

macro_rules! to_u16_array {
    ($slf:ident, $($first:expr, $second:expr),*) => {
        if cfg!(target_endian = "big") {
            [$( (($slf.sin6_addr.s6_addr[$first] as u16) << 8) + $slf.sin6_addr.s6_addr[$second] as u16,)*]
        } else {
            [$( (($slf.sin6_addr.s6_addr[$second] as u16) << 8) + $slf.sin6_addr.s6_addr[$first] as u16,)*]
        }
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
            let addr = to_u16_array!(storage, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15);
            let ip = Ipv6Addr::new(addr[0], addr[1], addr[2], addr[3],
                                   addr[4], addr[5], addr[6], addr[7]);
            Ok(SocketAddr::V6(SocketAddrV6::new(ip,
                                                ntohs(storage.sin6_port),
                                                u32::from_be(storage.sin6_flowinfo),
                                                u32::from_be(storage.sin6_scope_id))))
        }
        _ => {
            #[cfg(unix)]
            use libc::EINVAL as ERROR;
            #[cfg(windows)]
            use libc::WSAEINVAL as ERROR;
            Err(io::Error::from_raw_os_error(ERROR))
        }
    }
}
