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
    pub type SockAddr = libc::sockaddr;
    pub type SockAddrIn = libc::sockaddr_in;
    pub type SockAddrIn6 = libc::sockaddr_in6;
    pub type SockAddrStorage = libc::sockaddr_storage;
    pub type SockAddrFamily = libc::sa_family_t;
    pub type SockAddrFamily6 = libc::sa_family_t;
    pub type InAddr = libc::in_addr;
    pub type In6Addr = libc::in6_addr;

    pub const AF_INET: libc::c_int = libc::AF_INET;
    pub const AF_INET6: libc::c_int = libc::AF_INET6;
    pub const SOCK_RAW: libc::c_int = libc::SOCK_RAW;

    pub const IPPROTO_IP: libc::c_int = libc::IPPROTO_IP;
    pub const IP_HDRINCL: libc::c_int = libc::IP_HDRINCL;

    pub const IFF_LOOPBACK: libc::c_int = libc::IFF_LOOPBACK;

    pub const INVALID_SOCKET: CSocket = -1;


    pub unsafe fn close(sock: CSocket) {
        let _ = libc::close(sock);
    }

    pub unsafe fn socket(af: libc::c_int, sock: libc::c_int, proto: libc::c_int) -> CSocket {
        libc::socket(af, sock, proto)
    }

    pub unsafe fn setsockopt(socket: CSocket,
                            level: libc::c_int,
                            name: libc::c_int,
                            value: Buf,
                            option_len: SockLen)
        -> libc::c_int {
        libc::setsockopt(socket, level, name, value, option_len)
    }

    pub fn duration_to_timespec(dur: Duration) -> libc::timespec {
        libc::timespec {
            tv_sec: dur.as_secs() as libc::time_t,
            tv_nsec: dur.subsec_nanos() as libc::c_long,
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
