// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::io;
use std::mem;

pub mod sockets;

pub use self::native::{addr_to_sockaddr, sockaddr_to_addr};


#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use self::unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use self::windows::*;

mod native;


// Any file descriptor on unix, only sockets on Windows.
pub struct FileDesc {
    pub fd: sockets::CSocket,
}

impl Drop for FileDesc {
    fn drop(&mut self) {
        unsafe {
            sockets::close(self.fd);
        }
    }
}

pub fn send_to(socket: sockets::CSocket,
               buffer: &[u8],
               dst: *const sockets::SockAddr,
               slen: sockets::SockLen)
    -> io::Result<usize> {

    let send_len = retry(&mut || unsafe {
        sockets::sendto(socket,
                        buffer.as_ptr() as sockets::Buf,
                        buffer.len() as sockets::BufLen,
                        0,
                        dst,
                        slen)
    });

    if send_len < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(send_len as usize)
    }
}

pub fn recv_from(socket: sockets::CSocket,
                 buffer: &mut [u8],
                 caddr: *mut sockets::SockAddrStorage)
    -> io::Result<usize> {
    let mut caddrlen = mem::size_of::<sockets::SockAddrStorage>() as sockets::SockLen;
    let len = retry(&mut || unsafe {
        sockets::recvfrom(socket,
                          buffer.as_ptr() as sockets::MutBuf,
                          buffer.len() as sockets::BufLen,
                          0,
                          caddr as *mut sockets::SockAddr,
                          &mut caddrlen)
    });

    if len < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(len as usize)
    }
}
