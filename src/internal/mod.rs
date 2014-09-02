// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate libc;

use std::io::{IoResult, IoError};
use std::mem;

pub use self::native::{close, retry, addr_to_sockaddr, sockaddr_to_addr};

mod native;

#[cfg(windows)] pub type CSocket = libc::SOCKET;
#[cfg(windows)] pub type BufLen = i32;

#[cfg(not(windows))] pub type CSocket = libc::c_int;
#[cfg(not(windows))] pub type BufLen = u64;

// Any file descriptor on unix, only sockets on Windows.
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

pub fn send_to(socket: CSocket, buffer: &[u8], dst: *const libc::sockaddr, slen: libc::socklen_t)
    -> IoResult<uint> {

    let send_len = retry(|| unsafe {
        libc::sendto(socket, buffer.as_ptr() as *const libc::c_void, buffer.len() as BufLen,
                     0, dst, slen)
    });

    if send_len < 0 {
        Err(IoError::last_error())
    } else {
        Ok(send_len as uint)
    }
}

pub fn recv_from(socket: CSocket, buffer: &mut [u8], caddr: *mut libc::sockaddr_storage)
    -> IoResult<uint> {
    let mut caddrlen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    let len = retry(|| unsafe {
        libc::recvfrom(socket, buffer.as_ptr() as *mut libc::c_void, buffer.len() as BufLen,
                       0, caddr as *mut libc::sockaddr, &mut caddrlen)
    });

    if len < 0 {
        Err(IoError::last_error())
    } else {
        Ok(len as uint)
    }
}

