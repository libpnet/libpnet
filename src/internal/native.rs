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
use std::num::{Int, from_i32, SignedInt, FromPrimitive};
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};

use internal::CSocket;

#[cfg(windows)]
pub unsafe fn close(sock: CSocket) { let _ = libc::closesocket(sock); }
#[cfg(unix)]
pub unsafe fn close(sock: CSocket) { let _ = libc::close(sock); }

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap()
}

#[cfg(windows)]
#[inline]
pub fn retry<T, F>(f: &mut F) -> T
    where T : SignedInt + FromPrimitive,
          F : FnMut() -> T
{
    loop {
        let minus1: T = from_i32(-1).unwrap();
        let ret = f();
        if ret != minus1 || errno() as isize != libc::WSAEINTR as isize {
            return ret
        }
    }
}

#[cfg(unix)]
#[inline]
pub fn retry<T, F>(f: &mut F) -> T
    where T : SignedInt + FromPrimitive,
          F : FnMut() -> T
{
    loop {
        let minus1: T = from_i32(-1).unwrap();
        let ret = f();
        if ret != minus1 || errno() as isize != libc::EINTR as isize {
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

//enum InAddr {
//    In4Addr(libc::in_addr),
//    In6Addr(libc::in6_addr),
//}
//
//fn ip_to_inaddr(ip: IpAddr) -> InAddr {
//    match ip {
//        Ipv4Addr(a, b, c, d) => {
//            let ip = ((a as u32) << 24) |
//                     ((b as u32) << 16) |
//                     ((c as u32) <<  8) |
//                     ((d as u32) <<  0);
//            In4Addr(libc::in_addr {
//                s_addr: Int::from_be(ip)
//            })
//        }
//        Ipv6Addr(a, b, c, d, e, f, g, h) => {
//            In6Addr(libc::in6_addr {
//                s6_addr: [
//                    htons(a),
//                    htons(b),
//                    htons(c),
//                    htons(d),
//                    htons(e),
//                    htons(f),
//                    htons(g),
//                    htons(h),
//                ]
//            })
//        }
//    }
//}

pub fn addr_to_sockaddr(addr: SocketAddr,
                    storage: &mut libc::sockaddr_storage)
                    -> libc::socklen_t {
    unsafe {
        let len = match addr.ip() {
            IpAddr::V4(ip_addr) => {
                let [a, b, c, d] = ip_addr.octets();
                let inaddr = libc::in_addr {
                    s_addr: Int::from_be(((a as u32) << 24) |
                                         ((b as u32) << 16) |
                                         ((c as u32) <<  8) |
                                         ((d as u32) <<  0))
                };
                let storage = storage as *mut _ as *mut libc::sockaddr_in;
                (*storage).sin_family = libc::AF_INET as libc::sa_family_t;
                (*storage).sin_port = htons(addr.port());
                (*storage).sin_addr = inaddr;
                mem::size_of::<libc::sockaddr_in>()
            }
            IpAddr::V6(ip_addr) => {
                let [a, b, c, d, e, f, g, h] = ip_addr.segments();
                let inaddr = libc::in6_addr {
                    s6_addr: [
                        htons(a),
                        htons(b),
                        htons(c),
                        htons(d),
                        htons(e),
                        htons(f),
                        htons(g),
                        htons(h),
                    ],
                };
                let storage = storage as *mut _ as *mut libc::sockaddr_in6;
                (*storage).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*storage).sin6_port = htons(addr.port());
                (*storage).sin6_addr = inaddr;
                mem::size_of::<libc::sockaddr_in6>()
            }
        };
        return len as libc::socklen_t;
    }
}

pub fn sockaddr_to_addr(storage: &libc::sockaddr_storage,
                        len: usize) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            assert!(len as usize >= mem::size_of::<libc::sockaddr_in>());
            let storage: &libc::sockaddr_in = unsafe {
                mem::transmute(storage)
            };
            let ip = (storage.sin_addr.s_addr as u32).to_be();
            let a = (ip >> 24) as u8;
            let b = (ip >> 16) as u8;
            let c = (ip >>  8) as u8;
            let d = (ip >>  0) as u8;
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), ntohs(storage.sin_port)))
        }
        libc::AF_INET6 => {
            assert!(len as usize >= mem::size_of::<libc::sockaddr_in6>());
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
            let ip = IpAddr::V6(Ipv6Addr::new(a, b, c, d, e, f, g, h));
            Ok(SocketAddr::new(ip, ntohs(storage.sin6_port)))
        }
        _ => {
            #[cfg(unix)] use libc::EINVAL as ERROR;
            #[cfg(windows)] use libc::WSAEINVAL as ERROR;
            Err(io::Error::from_raw_os_error(ERROR))
        }
    }
}

