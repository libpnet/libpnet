extern crate libc;


use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};


#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use self::unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use self::windows::*;




// These functions are taken/adapted from libnative::io::{mod, net}

fn htons(u: u16) -> u16 {
    u.to_be()
}
fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

fn make_in6_addr(segments: [u16; 8]) -> In6Addr {
    let mut val: In6Addr = unsafe { mem::uninitialized() };
    val.s6_addr = unsafe {
        mem::transmute([htons(segments[0]),
                        htons(segments[1]),
                        htons(segments[2]),
                        htons(segments[3]),
                        htons(segments[4]),
                        htons(segments[5]),
                        htons(segments[6]),
                        htons(segments[7])])
    };
    val
}

pub fn addr_to_sockaddr(addr: SocketAddr,
                        storage: &mut SockAddrStorage)
    -> SockLen {
    unsafe {
        let len = match addr {
            SocketAddr::V4(sa) => {
                let ip_addr = sa.ip();
                let octets = ip_addr.octets();
                let inaddr = mk_inaddr(u32::from_be(((octets[0] as u32) << 24) |
                                                             ((octets[1] as u32) << 16) |
                                                             ((octets[2] as u32) << 8) |
                                                             (octets[3] as u32)));
                let storage = storage as *mut _ as *mut SockAddrIn;
                (*storage).sin_family = AF_INET as SockAddrFamily;
                (*storage).sin_port = htons(addr.port());
                (*storage).sin_addr = inaddr;
                mem::size_of::<SockAddrIn>()
            }
            SocketAddr::V6(sa) => {
                let ip_addr = sa.ip();
                let segments = ip_addr.segments();
                let inaddr = make_in6_addr(segments);
                let storage = storage as *mut _ as *mut SockAddrIn6;
                (*storage).sin6_family = AF_INET6 as SockAddrFamily6;
                (*storage).sin6_port = htons(addr.port());
                (*storage).sin6_addr = inaddr;
                mem::size_of::<SockAddrIn6>()
            }
        };

        len as SockLen
    }
}

pub fn sockaddr_to_addr(storage: &SockAddrStorage, len: usize) -> io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        AF_INET => {
            assert!(len as usize >= mem::size_of::<SockAddrIn>());
            let storage: &SockAddrIn = unsafe { mem::transmute(storage) };
            let ip = ipv4_addr(storage.sin_addr);
            let a = (ip >> 24) as u8;
            let b = (ip >> 16) as u8;
            let c = (ip >> 8) as u8;
            let d = ip as u8;
            let sockaddrv4 = SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), ntohs(storage.sin_port));
            Ok(SocketAddr::V4(sockaddrv4))
        }
        AF_INET6 => {
            assert!(len as usize >= mem::size_of::<SockAddrIn6>());
            let storage: &SockAddrIn6 = unsafe { mem::transmute(storage) };
            let arr: [u16; 8] = unsafe { mem::transmute(storage.sin6_addr.s6_addr) };
            let a = ntohs(arr[0]);
            let b = ntohs(arr[1]);
            let c = ntohs(arr[2]);
            let d = ntohs(arr[3]);
            let e = ntohs(arr[4]);
            let f = ntohs(arr[5]);
            let g = ntohs(arr[6]);
            let h = ntohs(arr[7]);
            let ip = Ipv6Addr::new(a, b, c, d, e, f, g, h);
            Ok(SocketAddr::V6(SocketAddrV6::new(ip,
                                                ntohs(storage.sin6_port),
                                                u32::from_be(storage.sin6_flowinfo),
                                                u32::from_be(storage.sin6_scope_id))))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "expected IPv4 or IPv6 socket")),
    }
}
