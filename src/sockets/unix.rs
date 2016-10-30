extern crate libc;

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

#[inline(always)]
pub fn ipv4_addr(addr: InAddr) -> u32 {
    (addr.s_addr as u32).to_be()
}

#[inline(always)]
pub fn mk_inaddr(addr: u32) -> InAddr {
    InAddr { s_addr: addr }
}

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
