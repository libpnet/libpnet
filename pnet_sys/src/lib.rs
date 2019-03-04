// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// extern crate ipnetwork;
// extern crate pnet_base;

use std::io;
use std::mem;

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

pub fn send_to(socket: CSocket,
               buffer: &[u8],
               dst: *const SockAddr,
               slen: SockLen)
    -> io::Result<usize> {

    let send_len = imp::retry(&mut || unsafe {
        imp::sendto(
            socket,
            buffer.as_ptr() as Buf,
            buffer.len() as BufLen,
            0,
            dst,
            slen
        )
    });

    if send_len < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(send_len as usize)
    }
}

pub fn recv_from(socket: CSocket,
                 buffer: &mut [u8],
                 caddr: *mut SockAddrStorage)
    -> io::Result<usize> {
    let mut caddrlen = mem::size_of::<SockAddrStorage>() as SockLen;
    let len = imp::retry(&mut || unsafe {
        imp::recvfrom(
            socket,
            buffer.as_ptr() as MutBuf,
            buffer.len() as BufLen,
            0,
            caddr as *mut SockAddr,
            &mut caddrlen
        )
    });

    if len < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(len as usize)
    }
}

// These functions are taken/adapted from libnative::io::{mod, net}

fn htons(u: u16) -> u16 {
    u.to_be()
}
fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}
