// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate libc;

use std::collections::VecDeque;
use std::cmp;
use std::ffi::CString;
use std::io;
use std::iter::repeat;
use std::mem;
use std::sync::Arc;

use bindings::bpf;
use packet::Packet;
use packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use datalink::DataLinkChannelType;
use datalink::DataLinkChannelType::{Layer2, Layer3};
use internal;
use util::NetworkInterface;

// NOTE buffer must be word aligned.
pub fn datalink_channel(network_interface: &NetworkInterface,
                        write_buffer_size: usize,
                        read_buffer_size: usize,
                        channel_type: DataLinkChannelType)
    -> io::Result<(DataLinkSenderImpl, DataLinkReceiverImpl)> {
    #[cfg(target_os = "freebsd")]
    fn get_fd() -> libc::c_int {
        unsafe {
            libc::open(CString::new(&b"/dev/bpf"[..]).unwrap().as_ptr(), libc::O_RDWR, 0)
        }
    }

    #[cfg(target_os = "macos")]
    fn get_fd() -> libc::c_int {
        // FIXME This is an arbitrary number of attempts
        for i in (0..1_000isize) {
            let fd = unsafe {
                let file_name = format!("/dev/bpf{}", i);
                libc::open(CString::new(file_name.as_bytes()).unwrap().as_ptr(), libc::O_RDWR, 0)
            };
            if fd != -1 {
                return fd;
            }
        }
        return -1;
    }

    #[cfg(target_os = "freebsd")]
    fn set_feedback(fd: libc::c_int) -> io::Result<()> {
        let one: libc::c_uint = 1;
        if unsafe { bpf::ioctl(fd, bpf::BIOCFEEDBACK, &one) } == -1 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd); }
            return Err(err);
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn set_feedback(_fd: libc::c_int) -> io::Result<()> {
        Ok(())
    }

    match channel_type {
        Layer2 => (),
        Layer3(_) => unimplemented!(),
    }

    let fd = get_fd();
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut iface: bpf::ifreq = unsafe { mem::zeroed() };
    let mut i = 0;
    for c in network_interface.name.bytes() {
        iface.ifr_name[i] = c as i8;
        i += 1;
    }

    let buflen = read_buffer_size as libc::c_uint;
    // NOTE Buffer length must be set before binding to an interface
    //      otherwise this will return Invalid Argument
    if unsafe { bpf::ioctl(fd, bpf::BIOCSBLEN, &buflen) } == -1 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd); }
        return Err(err);
    }

    // Set the interface to use
    if unsafe { bpf::ioctl(fd, bpf::BIOCSETIF, &iface) } == -1 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd); }
        return Err(err);
    }

    // Return from read as soon as packets are available - don't wait to fill the buffer
    let one: libc::c_uint = 1;
    if unsafe { bpf::ioctl(fd, bpf::BIOCIMMEDIATE, &one) } == -1 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd); }
        return Err(err);
    }

    let mut header_size = 0;

    // Get the device type
    let mut dlt: libc::c_uint = 0;
    if unsafe { bpf::ioctl(fd, bpf::BIOCGDLT, &mut dlt) } == -1 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd); }
        return Err(err);
    }

    // The loopback device does weird things
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
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd); }
            return Err(err);
        }
    }

    let fd = Arc::new(internal::FileDesc { fd: fd });
    let sender = DataLinkSenderImpl {
        fd: fd.clone(),
        write_buffer: repeat(0u8).take(write_buffer_size).collect(),
        header_size: header_size,
    };
    let receiver = DataLinkReceiverImpl {
        fd: fd,
        read_buffer: repeat(0u8).take(read_buffer_size).collect(),
        header_size: header_size,
    };

    Ok((sender, receiver))
}

pub struct DataLinkSenderImpl {
    fd: Arc<internal::FileDesc>,
    write_buffer: Vec<u8>,
    header_size: usize,
}

impl DataLinkSenderImpl {
    pub fn build_and_send<F>(&mut self, num_packets: usize, packet_size: usize,
                          func: &mut F) -> Option<io::Result<()>>
        where F : FnMut(MutableEthernetPacket)
    {
        let len = num_packets * (packet_size + self.header_size);
        if len >= self.write_buffer.len() {
            None
        } else {
            let min = cmp::min(self.write_buffer.len(), len);
            for chunk in self.write_buffer[..min]
                                          .chunks_mut(packet_size + self.header_size) {
                // If we're sending on the loopback device, the first 4 bytes must be set to
                // AF_INET
                if self.header_size == 4 {
                    unsafe {
                        *(chunk.as_mut_ptr() as *mut u32) = libc::AF_INET as u32;
                    }
                }
                {
                    let eh = MutableEthernetPacket::new(&mut chunk[self.header_size..]).unwrap();
                    func(eh);
                }
                match unsafe { libc::write(self.fd.fd,
                                           chunk.as_ptr() as *const libc::c_void,
                                           chunk.len() as libc::size_t) } {
                    len if len == -1 => return Some(Err(io::Error::last_os_error())),
                    _ => ()
                }
            }
            Some(Ok(()))
        }
    }

    pub fn send_to(&mut self, packet: &EthernetPacket, _dst: Option<NetworkInterface>)
        -> Option<io::Result<()>> {
        match unsafe { libc::write(self.fd.fd,
                                   packet.packet().as_ptr() as *const libc::c_void,
                                   packet.packet().len() as libc::size_t) } {
            len if len == -1 => Some(Err(io::Error::last_os_error())),
            _ => Some(Ok(()))
        }
    }
}

pub struct DataLinkReceiverImpl {
    fd: Arc<internal::FileDesc>,
    read_buffer: Vec<u8>,
    header_size: usize,
}

impl DataLinkReceiverImpl {
    pub fn iter<'a>(&'a mut self) -> DataLinkChannelIteratorImpl<'a> {
        let buflen = self.read_buffer.len();
        DataLinkChannelIteratorImpl {
            pc: self,
            // Enough room for minimally sized packets without reallocating
            packets: VecDeque::with_capacity(buflen / 64)
        }
    }
}

pub struct DataLinkChannelIteratorImpl<'a> {
    pc: &'a mut DataLinkReceiverImpl,
    packets: VecDeque<(usize, usize)>,
}

impl<'a> DataLinkChannelIteratorImpl<'a> {
    pub fn next<'c>(&'c mut self) -> io::Result<EthernetPacket<'c>> {
        if self.packets.is_empty() {
            let buflen = match unsafe {
                libc::read(self.pc.fd.fd,
                           self.pc.read_buffer.as_ptr() as *mut libc::c_void,
                           self.pc.read_buffer.len() as libc::size_t)
            } {
                len if len > 0 => len,
                _ => return Err(io::Error::last_os_error())
            };
            let mut ptr = self.pc.read_buffer.as_mut_ptr();
            let end = unsafe { self.pc.read_buffer.as_ptr().offset(buflen as isize) };
            while (ptr as *const u8) < end {
                unsafe {
                    let packet: *const bpf::bpf_hdr = mem::transmute(ptr);
                    let start = ptr as isize +
                                (*packet).bh_hdrlen as isize -
                                self.pc.read_buffer.as_ptr() as isize;
                    self.packets.push_back((start as usize + self.pc.header_size,
                                      (*packet).bh_caplen as usize - self.pc.header_size));
                    let offset = (*packet).bh_hdrlen as isize + (*packet).bh_caplen as isize;
                    ptr = ptr.offset(bpf::BPF_WORDALIGN(offset));
                }
            }
        }
        let (start, len) = self.packets.pop_front().unwrap();
        Ok(EthernetPacket::new(&self.pc.read_buffer[start .. start + len]).unwrap())
    }
}

