use winapi::ctypes;
use winapi::shared::minwindef;
use winapi::um::winsock2;
use std::io;

use super::{htons, ntohs};

pub mod public {

    use winapi::ctypes;
    use winapi::shared::{in6addr, inaddr, ws2def, ws2ipdef};
    use winapi::um::winsock2;
    use super::{htons, ntohs};
    use std::io;
    use std::mem;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    pub type CSocket = winsock2::SOCKET;
    pub type Buf = *const ctypes::c_char;
    pub type MutBuf = *mut ctypes::c_char;
    pub type BufLen = ctypes::c_int;
    pub type CouldFail = ctypes::c_int;
    pub type SockLen = ctypes::c_int;
    pub type MutSockLen = *mut ctypes::c_int;
    pub type SockAddr = ws2def::SOCKADDR;
    pub type SockAddrIn = ws2def::SOCKADDR_IN;
    pub type SockAddrIn6 = ws2ipdef::SOCKADDR_IN6_LH;
    pub type SockAddrStorage = ws2def::SOCKADDR_STORAGE;
    pub type SockAddrFamily = ws2def::ADDRESS_FAMILY;
    pub type SockAddrFamily6 = ws2def::ADDRESS_FAMILY;
    pub type InAddr = inaddr::IN_ADDR;
    pub type In6Addr = in6addr::IN6_ADDR;

    pub const AF_INET: ctypes::c_int = ws2def::AF_INET;
    pub const AF_INET6: ctypes::c_int = ws2def::AF_INET6;
    pub const SOCK_RAW: ctypes::c_int = winsock2::SOCK_RAW;

    pub const IPPROTO_IP: ctypes::c_int = ws2def::IPPROTO_IP;
    pub const IP_HDRINCL: ctypes::c_int = ws2ipdef::IP_HDRINCL;
    pub const IP_TTL: ctypes::c_int = ws2ipdef::IP_TTL;

    pub const IPPROTO_IPV6: ctypes::c_int = ws2def::IPPROTO_IPV6 as ctypes::c_int;
    pub const IPV6_UNICAST_HOPS: ctypes::c_int = ws2ipdef::IPV6_UNICAST_HOPS;

    pub const IFF_UP: ctypes::c_int = 0x00000001;
    pub const IFF_BROADCAST: ctypes::c_int = 0x00000002;
    pub const IFF_LOOPBACK: ctypes::c_int = 0x00000004;
    pub const IFF_POINTTOPOINT: ctypes::c_int = 0x00000008;
    pub const IFF_POINTOPOINT: ctypes::c_int = IFF_POINTTOPOINT;
    pub const IFF_MULTICAST: ctypes::c_int = 0x00000010;

    pub const INVALID_SOCKET: CSocket = winsock2::INVALID_SOCKET;

    pub unsafe fn close(sock: CSocket) {
        let _ = winsock2::closesocket(sock);
    }

    pub unsafe fn socket(af: ctypes::c_int, sock: ctypes::c_int, proto: ctypes::c_int) -> CSocket {
        winsock2::socket(af, sock, proto)
    }

    pub unsafe fn setsockopt(
        socket: CSocket,
        level: ctypes::c_int,
        name: ctypes::c_int,
        value: Buf,
        option_len: SockLen,
    ) -> ctypes::c_int {
        winsock2::setsockopt(socket, level, name, value, option_len)
    }

    pub fn make_in6_addr(segments: [u16; 8]) -> In6Addr {
        unsafe {
            let mut val: In6Addr = mem::MaybeUninit::uninit().assume_init();
            *val.u.Word_mut() = [
                htons(segments[0]),
                htons(segments[1]),
                htons(segments[2]),
                htons(segments[3]),
                htons(segments[4]),
                htons(segments[5]),
                htons(segments[6]),
                htons(segments[7]),
            ];

            val
        }
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
                    (*(*storage).u.sin6_scope_id_mut()) = sa.scope_id();
                    mem::size_of::<SockAddrIn6>()
                }
            };

            len as SockLen
        }
    }

    pub fn sockaddr_to_addr(storage: &SockAddrStorage, len: usize) -> io::Result<SocketAddr> {
        unsafe {
            match storage.ss_family as ctypes::c_int {
                AF_INET => {
                    assert!(len as usize >= mem::size_of::<SockAddrIn>());
                    let storage: &SockAddrIn = mem::transmute(storage);
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
                    let storage: &SockAddrIn6 = mem::transmute(storage);
                    let arr: [u16; 8] = mem::transmute(*storage.sin6_addr.u.Word());
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
                        *storage.u.sin6_scope_id(),
                    )))
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected IPv4 or IPv6 socket",
                )),
            }
        }
    }

    pub unsafe fn getsockopt(
        socket: CSocket,
        level: libc::c_int,
        name: libc::c_int,
        value: MutBuf,
        option_len: MutSockLen,
    ) -> libc::c_int {
        winsock2::getsockopt(socket, level, name, value, option_len)
    }
}

use self::public::*;

use std::mem;

#[inline(always)]
pub fn ipv4_addr(addr: InAddr) -> u32 {
    unsafe { (*addr.S_un.S_addr() as u32).to_be() }
}

#[inline(always)]
pub fn mk_inaddr(addr: u32) -> InAddr {
    unsafe {
        let mut val: InAddr = mem::MaybeUninit::uninit().assume_init();
        *val.S_un.S_addr_mut() = addr as minwindef::ULONG;

        val
    }
}

pub unsafe fn sendto(
    socket: CSocket,
    buf: Buf,
    len: BufLen,
    flags: ctypes::c_int,
    to: *const SockAddr,
    tolen: SockLen,
) -> CouldFail {
    winsock2::sendto(socket, buf, len, flags, to, tolen)
}

pub unsafe fn recvfrom(
    socket: CSocket,
    buf: MutBuf,
    len: BufLen,
    flags: ctypes::c_int,
    addr: *mut SockAddr,
    addrlen: *mut SockLen,
) -> CouldFail {
    winsock2::recvfrom(socket, buf, len, flags, addr, addrlen)
}

#[inline]
pub fn retry<F>(f: &mut F) -> ctypes::c_int
where
    F: FnMut() -> ctypes::c_int,
{
    loop {
        let ret = f();
        if ret != -1 || errno() as isize != winapi::shared::winerror::WSAEINTR as isize {
            return ret;
        }
    }
}

fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap()
}
