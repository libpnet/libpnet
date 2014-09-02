// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate libc;

use std::collections::{RingBuf, Deque};
use std::cmp;
use std::io::{IoResult, IoError};
use std::mem;
use std::option::{Option, Some};
use std::sync::Arc;

use bindings::bpf;
use packet::ethernet::{EthernetHeader, MutableEthernetHeader};
use datalink::{DataLinkChannelType, Layer2, Layer3};
use internal;
use util::NetworkInterface;

// NOTE buffer must be word aligned.
pub fn datalink_channel(network_interface: &NetworkInterface,
                        write_buffer_size: uint,
                        read_buffer_size: uint,
                        channel_type: DataLinkChannelType)
    -> IoResult<(DataLinkSenderImpl, DataLinkReceiverImpl)> {
    #[cfg(target_os = "freebsd")]
    fn get_fd() -> libc::c_int {
        unsafe {
            libc::open("/dev/bpf".to_c_str().as_ptr(), libc::O_RDWR, 0)
        }
    }

    #[cfg(target_os = "macos")]
    fn get_fd() -> libc::c_int {
        // FIXME This is an arbitrary number of attempts
        for i in range(0, 1_000i) {
            let fd = unsafe {
                let file_name = format!("/dev/bpf{}", i);
                libc::open(file_name.to_c_str().as_ptr(), libc::O_RDWR, 0)
            };
            if fd != -1 {
                return fd;
            }
        }
        return -1;
    }

    #[cfg(target_os = "freebsd")]
    fn set_feedback(fd: libc::c_int) -> Result<(), IoError> {
        let one: libc::c_uint = 1;
        if unsafe { bpf::ioctl(fd, bpf::BIOCFEEDBACK, &one) } == -1 {
            let err = IoError::last_error();
            unsafe { libc::close(fd); }
            return Err(err);
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn set_feedback(_fd: libc::c_int) -> Result<(), IoError> {
        Ok(())
    }

    match channel_type {
        Layer2 => (),
        Layer3(_) => unimplemented!(),
    }

    let fd = get_fd();
    if fd == -1 {
        return Err(IoError::last_error());
    }
    let mut iface: bpf::ifreq = unsafe { mem::zeroed() };
    let mut i = 0;
    for c in network_interface.name.as_slice().bytes() {
        iface.ifr_name[i] = c as i8;
        i += 1;
    }

    let buflen = read_buffer_size as libc::c_uint;
    // NOTE Buffer length must be set before binding to an interface
    //      otherwise this will return Invalid Argument
    if unsafe { bpf::ioctl(fd, bpf::BIOCSBLEN, &buflen) } == -1 {
        let err = IoError::last_error();
        unsafe { libc::close(fd); }
        return Err(err);
    }

    // Set the interface to use
    if unsafe { bpf::ioctl(fd, bpf::BIOCSETIF, &iface) } == -1 {
        let err = IoError::last_error();
        unsafe { libc::close(fd); }
        return Err(err);
    }

    // Return from read as soon as packets are available - don't wait to fill the buffer
    let one: libc::c_uint = 1;
    if unsafe { bpf::ioctl(fd, bpf::BIOCIMMEDIATE, &one) } == -1 {
        let err = IoError::last_error();
        unsafe { libc::close(fd); }
        return Err(err);
    }

    let mut header_size = 0;

    // Get the device type
    let mut dlt: libc::c_uint = 0;
    if unsafe { bpf::ioctl(fd, bpf::BIOCGDLT, &mut dlt) } == -1 {
        let err = IoError::last_error();
        unsafe { libc::close(fd); }
        return Err(err);
    }

    // The loopback IoError::last_error()device does weird things
    // FIXME This should really just be another L2 packet header type
    if dlt == bpf::DLT_NULL {
        header_size = 4;

        // Allow packets to be read back after they are written
        match set_feedback(fd) {
            Err(e) => return Err(e),
            _ => ()
        }

    } else {
        // Don't fill in source MAC
        if unsafe { bpf::ioctl(fd, bpf::BIOCSHDRCMPLT, &one) } == -1 {
            let err = IoError::last_error();
            unsafe { libc::close(fd); }
            return Err(err);
        }
    }

    let fd = Arc::new(internal::FileDesc { fd: fd });
    let sender = DataLinkSenderImpl {
        fd: fd.clone(),
        write_buffer: Vec::from_elem(write_buffer_size, 0u8),
        header_size: header_size,
    };
    let receiver = DataLinkReceiverImpl {
        fd: fd,
        read_buffer: Vec::from_elem(write_buffer_size, 0u8),
        header_size: header_size,
    };

    Ok((sender, receiver))
}

pub struct DataLinkSenderImpl {
    fd: Arc<internal::FileDesc>,
    write_buffer: Vec<u8>,
    header_size: uint,
}

impl DataLinkSenderImpl {
    pub fn build_and_send(&mut self, num_packets: uint, packet_size: uint,
                          func: |MutableEthernetHeader| -> ()) -> Option<IoResult<()>> {
        let len = num_packets * (packet_size + self.header_size);
        if len >= self.write_buffer.len() {
            None
        } else {
            let min = cmp::min(self.write_buffer.len(), len);
            for chunk in self.write_buffer.mut_slice_to(min)
                                          .mut_chunks(packet_size + self.header_size) {
                // If we're sending on the loopback device, the first 4 bytes must be set to
                // AF_INET
                if self.header_size == 4 {
                    unsafe {
                        *(chunk.as_mut_ptr() as *mut u32) = libc::AF_INET as u32;
                    }
                }
                {
                    let eh = MutableEthernetHeader::new(chunk.mut_slice_from(self.header_size));
                    func(eh);
                }
                match unsafe { libc::write(self.fd.fd,
                                           chunk.as_ptr() as *const libc::c_void,
                                           chunk.len() as libc::size_t) } {
                    len if len == -1 => return Some(Err(IoError::last_error())),
                    _ => ()
                }
            }
            Some(Ok(()))
        }
    }
}

pub struct DataLinkReceiverImpl {
    fd: Arc<internal::FileDesc>,
    read_buffer: Vec<u8>,
    header_size: uint,
}

impl DataLinkReceiverImpl {
    pub fn iter<'a>(&'a mut self) -> DataLinkChannelIteratorImpl<'a> {
        let buflen = self.read_buffer.len();
        DataLinkChannelIteratorImpl {
            pc: self,
            // Enough room for minimally sized packets without reallocating
            packets: RingBuf::with_capacity(buflen / 64)
        }
    }
}

pub struct DataLinkChannelIteratorImpl<'a> {
    pc: &'a mut DataLinkReceiverImpl,
    packets: RingBuf<(uint, uint)>,
}

impl<'a> DataLinkChannelIteratorImpl<'a> {
    pub fn next<'c>(&'c mut self) -> IoResult<EthernetHeader<'c>> {
        if self.packets.is_empty() {
            let buflen = match unsafe {
                libc::read(self.pc.fd.fd,
                           self.pc.read_buffer.as_ptr() as *mut libc::c_void,
                           self.pc.read_buffer.len() as libc::size_t)
            } {
                len if len > 0 => len,
                _ => return Err(IoError::last_error())
            };
            let mut ptr = self.pc.read_buffer.as_mut_ptr();
            let end = unsafe { self.pc.read_buffer.as_ptr().offset(buflen as int) };
            while (ptr as *const u8) < end {
                unsafe {
                    let packet: *const bpf::bpf_hdr = mem::transmute(ptr);
                    let start = ptr as int +
                                (*packet).bh_hdrlen as int -
                                self.pc.read_buffer.as_ptr() as int;
                    self.packets.push((start as uint + self.pc.header_size,
                                      (*packet).bh_caplen as uint - self.pc.header_size));
                    let offset = (*packet).bh_hdrlen as int + (*packet).bh_caplen as int;
                    ptr = ptr.offset(bpf::BPF_WORDALIGN(offset));
                }
            }
        }
        let (start, len) = self.packets.pop_front().unwrap();
        Ok(EthernetHeader::new(self.pc.read_buffer.slice(start, start + len)))
    }
}

