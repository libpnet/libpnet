extern crate winapi;
extern crate ws2_32;

use libc;
use std::io;

pub mod public {
    use super::winapi;
    use super::ws2_32;
    use libc;

    pub type CSocket = winapi::SOCKET;
    pub type Buf = *const libc::c_char;
    pub type MutBuf = *mut libc::c_char;
    pub type BufLen = libc::c_int;
    pub type CouldFail = libc::c_int;
    pub type SockLen = winapi::socklen_t;
    pub type MutSockLen = *mut winapi::socklen_t;
    pub type SockAddr = winapi::SOCKADDR;
    pub type SockAddrIn = winapi::SOCKADDR_IN;
    pub type SockAddrIn6 = winapi::sockaddr_in6;
    pub type SockAddrStorage = winapi::SOCKADDR_STORAGE;
    pub type SockAddrFamily = winapi::ADDRESS_FAMILY;
    pub type SockAddrFamily6 = libc::c_short;
    pub type InAddr = winapi::in_addr;
    pub type In6Addr = winapi::in6_addr;

    pub const AF_INET: libc::c_int = winapi::AF_INET;
    pub const AF_INET6: libc::c_int = winapi::AF_INET6;
    pub const SOCK_RAW: libc::c_int = winapi::SOCK_RAW;

    pub const IPPROTO_IP: libc::c_int = winapi::IPPROTO_IP;
    pub const IP_HDRINCL: libc::c_int = winapi::IP_HDRINCL;
    pub const IPV6_HDRINCL: libc::c_int = winapi::IPV6_HDRINCL;
    pub const IP_TTL: libc::c_int = winapi::IP_TTL;

    pub const IFF_UP: libc::c_int = 0x00000001;
    pub const IFF_BROADCAST: libc::c_int = 0x00000002;
    pub const IFF_LOOPBACK: libc::c_int = 0x00000004;
    pub const IFF_POINTTOPOINT: libc::c_int = 0x00000008;
    pub const IFF_POINTOPOINT: libc::c_int = IFF_POINTTOPOINT;
    pub const IFF_MULTICAST: libc::c_int = 0x00000010;

    pub const INVALID_SOCKET: CSocket = winapi::INVALID_SOCKET;

    pub unsafe fn close(sock: CSocket) {
        let _ = ws2_32::closesocket(sock);
    }

    pub unsafe fn socket(af: libc::c_int, sock: libc::c_int, proto: libc::c_int) -> CSocket {
        ws2_32::socket(af, sock, proto)
    }

    pub unsafe fn setsockopt(
        socket: CSocket,
        level: libc::c_int,
        name: libc::c_int,
        value: Buf,
        option_len: SockLen,
    ) -> libc::c_int {
        ws2_32::setsockopt(socket, level, name, value, option_len)
    }

    pub unsafe fn getsockopt(
        socket: CSocket,
        level: libc::c_int,
        name: libc::c_int,
        value: MutBuf,
        option_len: MutSockLen,
    ) -> libc::c_int {
        ws2_32::getsockopt(socket, level, name, value, option_len)
    }
}

use self::public::*;

#[inline(always)]
pub fn ipv4_addr(addr: InAddr) -> u32 {
    (addr.S_un as u32).to_be()
}

#[inline(always)]
pub fn mk_inaddr(addr: u32) -> InAddr {
    InAddr {
        S_un: addr as winapi::ULONG,
    }
}

pub unsafe fn sendto(
    socket: CSocket,
    buf: Buf,
    len: BufLen,
    flags: libc::c_int,
    to: *const SockAddr,
    tolen: SockLen,
) -> CouldFail {
    ws2_32::sendto(socket, buf, len, flags, to, tolen)
}

pub unsafe fn recvfrom(
    socket: CSocket,
    buf: MutBuf,
    len: BufLen,
    flags: libc::c_int,
    addr: *mut SockAddr,
    addrlen: *mut SockLen,
) -> CouldFail {
    ws2_32::recvfrom(socket, buf, len, flags, addr, addrlen)
}

#[inline]
pub fn retry<F>(f: &mut F) -> libc::c_int
where
    F: FnMut() -> libc::c_int,
{
    loop {
        let ret = f();
        if ret != -1 || errno() as isize != winapi::WSAEINTR as isize {
            return ret;
        }
    }
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap()
}
