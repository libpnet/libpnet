use libc;
use std::io;

pub mod public {
    use libc;
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

    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    pub type TvUsecType = libc::c_long;
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub type TvUsecType = libc::c_int;

    pub const AF_INET: libc::c_int = libc::AF_INET;
    pub const AF_INET6: libc::c_int = libc::AF_INET6;
    pub const SOCK_RAW: libc::c_int = libc::SOCK_RAW;

    pub const SOL_SOCKET: libc::c_int = libc::SOL_SOCKET;
    pub const SO_RCVTIMEO: libc::c_int = libc::SO_RCVTIMEO;
    pub const SO_SNDTIMEO: libc::c_int = libc::SO_SNDTIMEO;

    pub const IPPROTO_IP: libc::c_int = libc::IPPROTO_IP;
    pub const IP_HDRINCL: libc::c_int = libc::IP_HDRINCL;
    pub const IP_TTL: libc::c_int = libc::IP_TTL;

    pub use libc::{IFF_UP, IFF_BROADCAST, IFF_LOOPBACK, IFF_POINTOPOINT, IFF_MULTICAST};

    pub const INVALID_SOCKET: CSocket = -1;


    pub unsafe fn close(sock: CSocket) {
        let _ = libc::close(sock);
    }

    pub unsafe fn socket(af: libc::c_int, sock: libc::c_int, proto: libc::c_int) -> CSocket {
        libc::socket(af, sock, proto)
    }

    pub unsafe fn getsockopt(socket: CSocket,
                            level: libc::c_int,
                            name: libc::c_int,
                            value: MutBuf,
                            option_len: MutSockLen)
        -> libc::c_int {
        libc::getsockopt(socket, level, name, value, option_len)
    }

    pub unsafe fn setsockopt(socket: CSocket,
                            level: libc::c_int,
                            name: libc::c_int,
                            value: Buf,
                            option_len: SockLen)
        -> libc::c_int {
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
            tv_usec: dur.subsec_micros() as TvUsecType
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
            tv_nsec: (dur.subsec_nanos() as TvUsecType).into()
        }
    }

}

use self::public::*;

#[inline(always)]
pub fn ipv4_addr(addr: InAddr) -> u32 {
    (addr.s_addr as u32).to_be()
}

#[inline(always)]
pub fn mk_inaddr(addr: u32) -> InAddr {
    InAddr { s_addr: addr }
}


pub unsafe fn sendto(socket: CSocket,
                     buf: Buf,
                     len: BufLen,
                     flags: libc::c_int,
                     addr: *const SockAddr,
                     addrlen: SockLen)
    -> CouldFail {
    libc::sendto(socket, buf, len, flags, addr, addrlen)
}

pub unsafe fn recvfrom(socket: CSocket,
                       buf: MutBuf,
                       len: BufLen,
                       flags: libc::c_int,
                       addr: *mut SockAddr,
                       addrlen: *mut SockLen)
    -> CouldFail {
    libc::recvfrom(socket, buf, len, flags, addr, addrlen)
}


#[inline]
pub fn retry<F>(f: &mut F) -> libc::ssize_t
    where F: FnMut() -> libc::ssize_t
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
    use std::time::Duration;
    use duration_to_timespec;
    use timespec_to_duration;

    #[test]
    fn test_duration_to_timespec(){
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
