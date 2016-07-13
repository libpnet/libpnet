extern crate winapi;
extern crate libc;
extern crate ws2_32;

pub type CSocket = winapi::SOCKET;
pub type Buf = *const libc::c_char;
pub type MutBuf = *mut libc::c_char;
pub type BufLen = libc::c_int;
pub type CouldFail = libc::c_int;
pub type SockLen = winapi::socklen_t;
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

pub const IFF_LOOPBACK: libc::c_int = 0x00000004;

pub const INVALID_SOCKET: CSocket = winapi::INVALID_SOCKET;

#[inline(always)]
pub fn ipv4_addr(addr: InAddr) -> u32 {
    (addr.S_un as u32).to_be()
}

#[inline(always)]
pub fn mk_inaddr(addr: u32) -> InAddr {
    InAddr {
        S_un: addr as winapi::ULONG
    }
}

pub unsafe fn close(sock: CSocket) {
    let _ = ws2_32::closesocket(sock);
}

pub unsafe fn socket(af: libc::c_int, sock: libc::c_int, proto: libc::c_int) -> CSocket {
    ws2_32::socket(af, sock, proto)
}

pub unsafe fn setsockopt(socket: CSocket, level: libc::c_int,
                         name: libc::c_int, value: Buf,
                         option_len: SockLen) -> libc::c_int {
    ws2_32::setsockopt(socket, level, name, value, option_len)
}

pub unsafe fn sendto(socket: CSocket, buf: Buf, len: BufLen,
                     flags: libc::c_int, to: *const SockAddr,
                     tolen: SockLen) -> CouldFail {
    ws2_32::sendto(socket, buf, len, flags, to, tolen)
}

pub unsafe fn recvfrom(socket: CSocket, buf: MutBuf, len: BufLen,
                       flags: libc::c_int, addr: *mut SockAddr,
                       addrlen: *mut SockLen) -> CouldFail {
    ws2_32::recvfrom(socket, buf, len, flags, addr, addrlen)
}
