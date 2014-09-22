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

use std::mem;
use std::num::from_i32;
use std::os;
use std::io::{IoResult, IoError};
use std::io::net::ip::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

use internal::CSocket;

#[cfg(windows)]
pub unsafe fn close(sock: CSocket) { let _ = libc::closesocket(sock); }
#[cfg(unix)]
pub unsafe fn close(sock: CSocket) { let _ = libc::close(sock); }

#[cfg(windows)]
#[inline]
pub fn retry<T:Signed + FromPrimitive>(f: || -> T) -> T {
    loop {
        let minus1: T = from_i32(-1).unwrap();
        let ret = f();
        if ret != minus1 || os::errno() as int != libc::WSAEINTR as int {
            return ret
        }
    }
}

#[cfg(unix)]
#[inline]
pub fn retry<T:Signed + FromPrimitive>(f: || -> T) -> T {
    loop {
        let minus1: T = from_i32(-1).unwrap();
        let ret = f();
        if ret != minus1 || os::errno() as int != libc::EINTR as int {
            return ret
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// sockaddr and misc bindings
////////////////////////////////////////////////////////////////////////////////

fn htons(u: u16) -> u16 {
    u.to_be()
}
fn ntohs(u: u16) -> u16 {
    Int::from_be(u)
}

enum InAddr {
    In4Addr(libc::in_addr),
    In6Addr(libc::in6_addr),
}

fn ip_to_inaddr(ip: IpAddr) -> InAddr {
    match ip {
        Ipv4Addr(a, b, c, d) => {
            let ip = (a as u32 << 24) |
                     (b as u32 << 16) |
                     (c as u32 <<  8) |
                     (d as u32 <<  0);
            In4Addr(libc::in_addr {
                s_addr: Int::from_be(ip)
            })
        }
        Ipv6Addr(a, b, c, d, e, f, g, h) => {
            In6Addr(libc::in6_addr {
                s6_addr: [
                    htons(a),
                    htons(b),
                    htons(c),
                    htons(d),
                    htons(e),
                    htons(f),
                    htons(g),
                    htons(h),
                ]
            })
        }
    }
}

pub fn addr_to_sockaddr(addr: SocketAddr,
                    storage: &mut libc::sockaddr_storage)
                    -> libc::socklen_t {
    unsafe {
        let len = match ip_to_inaddr(addr.ip) {
            In4Addr(inaddr) => {
                let storage = storage as *mut _ as *mut libc::sockaddr_in;
                (*storage).sin_family = libc::AF_INET as libc::sa_family_t;
                (*storage).sin_port = htons(addr.port);
                (*storage).sin_addr = inaddr;
                mem::size_of::<libc::sockaddr_in>()
            }
            In6Addr(inaddr) => {
                let storage = storage as *mut _ as *mut libc::sockaddr_in6;
                (*storage).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*storage).sin6_port = htons(addr.port);
                (*storage).sin6_addr = inaddr;
                mem::size_of::<libc::sockaddr_in6>()
            }
        };
        return len as libc::socklen_t;
    }
}

pub fn sockaddr_to_addr(storage: &libc::sockaddr_storage,
                        len: uint) -> IoResult<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            assert!(len as uint >= mem::size_of::<libc::sockaddr_in>());
            let storage: &libc::sockaddr_in = unsafe {
                mem::transmute(storage)
            };
            let ip = (storage.sin_addr.s_addr as u32).to_be();
            let a = (ip >> 24) as u8;
            let b = (ip >> 16) as u8;
            let c = (ip >>  8) as u8;
            let d = (ip >>  0) as u8;
            Ok(SocketAddr {
                ip: Ipv4Addr(a, b, c, d),
                port: ntohs(storage.sin_port),
            })
        }
        libc::AF_INET6 => {
            assert!(len as uint >= mem::size_of::<libc::sockaddr_in6>());
            let storage: &libc::sockaddr_in6 = unsafe {
                mem::transmute(storage)
            };
            let a = ntohs(storage.sin6_addr.s6_addr[0]);
            let b = ntohs(storage.sin6_addr.s6_addr[1]);
            let c = ntohs(storage.sin6_addr.s6_addr[2]);
            let d = ntohs(storage.sin6_addr.s6_addr[3]);
            let e = ntohs(storage.sin6_addr.s6_addr[4]);
            let f = ntohs(storage.sin6_addr.s6_addr[5]);
            let g = ntohs(storage.sin6_addr.s6_addr[6]);
            let h = ntohs(storage.sin6_addr.s6_addr[7]);
            Ok(SocketAddr {
                ip: Ipv6Addr(a, b, c, d, e, f, g, h),
                port: ntohs(storage.sin6_port),
            })
        }
        _ => {
            #[cfg(unix)] use libc::EINVAL as ERROR;
            #[cfg(windows)] use libc::WSAEINVAL as ERROR;
            Err(IoError::from_errno(ERROR as uint, true))
        }
    }
}

