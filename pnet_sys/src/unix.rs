use super::{htons, ntohs};
use std::io;

pub mod public {

    use libc;
    use super::{htons, ntohs};
    use std::io;
    use std::mem;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::time::Duration;

    pub type CSocket = libc::c_int;
    pub type Buf = *const libc::c_void;
    pub type MutBuf = *mut libc::c_void;
    pub type BufLen = libc::size_t;
    pub type CouldFail = libc::ssize_t;
    pub type SockLen = libc::socklen_t;
    pub type MutSockLen = *mut libc::socklen_t;
    pub type SockAddr = libc::sockaddr;
    pub type SockAddrIn = libc::sockaddr_in;
    pub type SockAddrIn6 = libc::sockaddr_in6;
    pub type SockAddrStorage = libc::sockaddr_storage;
    pub type SockAddrFamily = libc::sa_family_t;
    pub type SockAddrFamily6 = libc::sa_family_t;
    pub type InAddr = libc::in_addr;
    pub type In6Addr = libc::in6_addr;

    #[cfg(not(any(target_os = "macos", target_os = "ios", target_os = "netbsd")))]
    pub type TvUsecType = libc::c_long;
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "netbsd"))]
    pub type TvUsecType = libc::c_int;
    #[cfg(not(any(target_os = "illumos", target_os = "solaris")))]
    pub type InAddrType = libc::c_uint;
    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    pub type InAddrType = libc::c_ulonglong;

    pub const AF_INET: libc::c_int = libc::AF_INET;
    pub const AF_INET6: libc::c_int = libc::AF_INET6;
    pub const SOCK_RAW: libc::c_int = libc::SOCK_RAW;

    pub const SOL_SOCKET: libc::c_int = libc::SOL_SOCKET;
    pub const SO_RCVTIMEO: libc::c_int = libc::SO_RCVTIMEO;
    pub const SO_SNDTIMEO: libc::c_int = libc::SO_SNDTIMEO;

    pub const IPPROTO_IP: libc::c_int = libc::IPPROTO_IP;
    pub const IP_HDRINCL: libc::c_int = libc::IP_HDRINCL;
    pub const IP_TTL: libc::c_int = libc::IP_TTL;

    pub const IPPROTO_IPV6: libc::c_int = libc::IPPROTO_IPV6;
    pub const IPV6_UNICAST_HOPS: libc::c_int = libc::IPV6_UNICAST_HOPS;

    pub use libc::{IFF_BROADCAST, IFF_LOOPBACK, IFF_RUNNING, IFF_MULTICAST, IFF_POINTOPOINT, IFF_UP};

    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub use libc::{IFF_LOWER_UP, IFF_DORMANT};

    pub const INVALID_SOCKET: CSocket = -1;

    pub unsafe fn close(sock: CSocket) {
        let _ = libc::close(sock);
    }

    pub unsafe fn socket(af: libc::c_int, sock: libc::c_int, proto: libc::c_int) -> CSocket {
        libc::socket(af, sock, proto)
    }

    pub unsafe fn getsockopt(
        socket: CSocket,
        level: libc::c_int,
        name: libc::c_int,
        value: MutBuf,
        option_len: MutSockLen,
    ) -> libc::c_int {
        libc::getsockopt(socket, level, name, value, option_len)
    }

    pub unsafe fn setsockopt(
        socket: CSocket,
        level: libc::c_int,
        name: libc::c_int,
        value: Buf,
        option_len: SockLen,
    ) -> libc::c_int {
        libc::setsockopt(socket, level, name, value, option_len)
    }

    /// Convert a platform specific `timeval` into a Duration.
    pub fn timeval_to_duration(tv: libc::timeval) -> Duration {
        Duration::new(tv.tv_sec as u64, (tv.tv_usec as u32) * 1000)
    }

    /// Convert a Duration into a platform specific `timeval`.
    pub fn duration_to_timeval(dur: Duration) -> libc::timeval {
        libc::timeval {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_usec: dur.subsec_micros() as TvUsecType,
        }
    }

    /// Convert a platform specific `timespec` into a Duration.
    pub fn timespec_to_duration(ts: libc::timespec) -> Duration {
        Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    }

    /// Convert a Duration into a platform specific `timespec`.
    pub fn duration_to_timespec(dur: Duration) -> libc::timespec {
        libc::timespec {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_nsec: (dur.subsec_nanos() as TvUsecType).into(),
        }
    }

    fn make_in6_addr(segments: [u16; 8]) -> In6Addr {
        // Safety: We're transmuting an array of ints to an array of ints.
        // There is no padding involved, and they must be the same size.
        let s6_addr = unsafe {
            mem::transmute::<[u16; 8], [u8; 16]>([
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

        In6Addr { s6_addr }
    }

    pub fn addr_to_sockaddr(addr: SocketAddr, storage: &mut SockAddrStorage) -> SockLen {
        unsafe {
            let len = match addr {
                SocketAddr::V4(sa) => {
                    let ip_addr = sa.ip();
                    let octets = ip_addr.octets();
                    let inaddr = super::mk_inaddr(u32::from_be(
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
                let ip = super::ipv4_addr(storage.sin_addr);
                let a = (ip >> 24) as u8;
                let b = (ip >> 16) as u8;
                let c = (ip >> 8) as u8;
                let d = ip as u8;
                let sockaddrv4 =
                    SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), ntohs(storage.sin_port));
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
}

use self::public::*;

#[inline(always)]
pub fn ipv4_addr(addr: InAddr) -> InAddrType {
    (addr.s_addr as InAddrType).to_be()
}

#[inline(always)]
pub fn mk_inaddr(addr: u32) -> InAddr {
    InAddr { s_addr: addr }
}

pub unsafe fn sendto(
    socket: CSocket,
    buf: Buf,
    len: BufLen,
    flags: libc::c_int,
    addr: *const SockAddr,
    addrlen: SockLen,
) -> CouldFail {
    libc::sendto(socket, buf, len, flags, addr, addrlen)
}

pub unsafe fn recvfrom(
    socket: CSocket,
    buf: MutBuf,
    len: BufLen,
    flags: libc::c_int,
    addr: *mut SockAddr,
    addrlen: *mut SockLen,
) -> CouldFail {
    libc::recvfrom(socket, buf, len, flags, addr, addrlen)
}

#[inline]
pub fn retry<F>(f: &mut F) -> libc::ssize_t
where
    F: FnMut() -> libc::ssize_t,
{
    loop {
        let ret = f();
        if ret != -1 || errno() as isize != libc::EINTR as isize {
            return ret;
        }
    }
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap()
}

#[cfg(test)]
mod tests {
    use crate::duration_to_timespec;
    use std::time::Duration;
    use crate::timespec_to_duration;

    #[test]
    fn test_duration_to_timespec() {
        let d1 = Duration::new(1, 0);
        let d2 = Duration::from_millis(500);

        let t1 = duration_to_timespec(d1);
        let t2 = duration_to_timespec(d2);

        let r1 = timespec_to_duration(t1);
        let r2 = timespec_to_duration(t2);

        assert_eq!(d1, r1);
        assert_eq!(d2, r2);
    }
}
