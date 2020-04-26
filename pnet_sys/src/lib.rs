// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate libc;

use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

pub use self::imp::public::*;

/// Any file descriptor on unix, only sockets on Windows.
pub struct FileDesc {
    pub fd: CSocket,
}

impl Drop for FileDesc {
    fn drop(&mut self) {
        unsafe {
            close(self.fd);
        }
    }
}

pub fn send_to(
    socket: CSocket,
    buffer: &[u8],
    dst: *const SockAddr,
    slen: SockLen,
) -> io::Result<usize> {
    let send_len = imp::retry(&mut || unsafe {
        imp::sendto(
            socket,
            buffer.as_ptr() as Buf,
            buffer.len() as BufLen,
            0,
            dst,
            slen,
        )
    });

    if send_len < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(send_len as usize)
    }
}

pub fn recv_from(
    socket: CSocket,
    buffer: &mut [u8],
    caddr: *mut SockAddrStorage,
) -> io::Result<usize> {
    let mut caddrlen = mem::size_of::<SockAddrStorage>() as SockLen;
    let len = imp::retry(&mut || unsafe {
        imp::recvfrom(
            socket,
            buffer.as_ptr() as MutBuf,
            buffer.len() as BufLen,
            0,
            caddr as *mut SockAddr,
            &mut caddrlen,
        )
    });

    if len < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(len as usize)
    }
}

/// Set a timeout for receiving from the socket.
#[cfg(unix)]
pub fn set_socket_receive_timeout(socket: CSocket, t: Duration) -> io::Result<()> {
    let ts = duration_to_timeval(t);
    let r = unsafe {
        setsockopt(
            socket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            (&ts as *const libc::timeval) as Buf,
            mem::size_of::<libc::timeval>() as SockLen,
        )
    };

    if r < 0 {
        Err(io::Error::last_os_error())
    } else if r > 0 {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Unknown return value from getsockopt(): {}", r),
        ))
    } else {
        Ok(())
    }
}

/// Extracts and returns a timout for reading from the socket.
#[cfg(unix)]
pub fn get_socket_receive_timeout(socket: CSocket) -> io::Result<Duration> {
    let ts = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let len: SockLen = mem::size_of::<libc::timeval>() as SockLen;
    let r = unsafe {
        getsockopt(
            socket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            (&ts as *const libc::timeval) as MutBuf,
            (&len as *const SockLen) as MutSockLen,
        )
    };
    assert_eq!(
        len,
        mem::size_of::<libc::timeval>() as SockLen,
        "getsockopt did not set size of return value"
    );

    if r < 0 {
        Err(io::Error::last_os_error())
    } else if r > 0 {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Unknown return value from getsockopt(): {}", r),
        ))
    } else {
        Ok(timeval_to_duration(ts))
    }
}

// These functions are taken/adapted from libnative::io::{mod, net}

fn htons(u: u16) -> u16 {
    u.to_be()
}
fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

fn make_in6_addr(segments: [u16; 8]) -> In6Addr {
    let mut val: In6Addr = unsafe { mem::MaybeUninit::<In6Addr>::uninit().assume_init() };
    val.s6_addr = unsafe {
        mem::transmute([
            htons(segments[0]),
            htons(segments[1]),
            htons(segments[2]),
            htons(segments[3]),
            htons(segments[4]),
            htons(segments[5]),
            htons(segments[6]),
            htons(segments[7]),
        ])
    };
    val
}

pub fn addr_to_sockaddr(addr: SocketAddr, storage: &mut SockAddrStorage) -> SockLen {
    unsafe {
        let len = match addr {
            SocketAddr::V4(sa) => {
                let ip_addr = sa.ip();
                let octets = ip_addr.octets();
                let inaddr = imp::mk_inaddr(u32::from_be(
                    ((octets[0] as u32) << 24)
                        | ((octets[1] as u32) << 16)
                        | ((octets[2] as u32) << 8)
                        | (octets[3] as u32),
                ));
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
                (*storage).sin6_scope_id = sa.scope_id();
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
            let ip = imp::ipv4_addr(storage.sin_addr);
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
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                ntohs(storage.sin6_port),
                u32::from_be(storage.sin6_flowinfo),
                storage.sin6_scope_id,
            )))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected IPv4 or IPv6 socket",
        )),
    }
}

#[cfg(test)]
mod tests {
    use get_socket_receive_timeout;
    use recv_from;
    use set_socket_receive_timeout;
    use std::mem;
    use std::time::{Duration, Instant};
    use CSocket;
    use SockAddrStorage;

    fn test_timeout(socket: CSocket) -> Duration {
        let mut buffer = [0u8; 1024];
        let mut caddr: SockAddrStorage = unsafe { mem::zeroed() };

        let t0 = Instant::now();
        let res = recv_from(socket, &mut buffer, &mut caddr);
        assert!(!res.is_ok());
        Instant::now() - t0
    }

    #[test]
    fn test_set_socket_receive_timeout_1s() {
        let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, 1 as libc::c_int) };
        let d = Duration::new(1, 0);
        let res = set_socket_receive_timeout(socket, d.clone());
        match res {
            Err(e) => panic!("set_socket_receive_timeout reslted in error: {}", e),
            _ => {}
        };

        let t = test_timeout(socket);
        assert!(t >= Duration::new(1, 0));
        assert!(t < Duration::from_millis(1100));
    }

    #[test]
    fn test_set_socket_receive_timeout_500ms() {
        let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, 1 as libc::c_int) };
        let d = Duration::from_millis(500);
        let res = set_socket_receive_timeout(socket, d);
        match res {
            Err(e) => panic!("set_socket_receive_timeout reslted in error: {}", e),
            _ => {}
        };

        let t = test_timeout(socket);
        assert!(t >= Duration::from_millis(500));
        assert!(t < Duration::from_millis(600));
    }

    #[test]
    fn test_set_socket_receive_timeout_1500ms() {
        let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, 1 as libc::c_int) };
        let d = Duration::from_millis(1500);
        let res = set_socket_receive_timeout(socket, d);
        match res {
            Err(e) => panic!("set_socket_receive_timeout reslted in error: {}", e),
            _ => {}
        };

        let t = test_timeout(socket);
        assert!(t >= Duration::from_millis(1500));
        assert!(t < Duration::from_millis(1600));
    }

    #[test]
    fn test_get_socket_receive_timeout() {
        let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, 1 as libc::c_int) };
        let s1 = Duration::new(1, 0);
        set_socket_receive_timeout(socket, s1).ok();
        let g1 = get_socket_receive_timeout(socket);
        match g1 {
            Err(e) => panic!("get_socket_receive_timeout resulted in error: {}", e),
            Ok(t) => assert_eq!(s1, t, "Expected to receive 1s timeout"),
        }

        let s2 = Duration::from_millis(500);
        set_socket_receive_timeout(socket, s2).ok();
        let g2 = get_socket_receive_timeout(socket);
        match g2 {
            Err(e) => panic!("get_socket_receive_timeout resulted in error: {}", e),
            Ok(t) => assert_eq!(s2, t, "Expected to receive 500ms timeout"),
        }
    }
}
