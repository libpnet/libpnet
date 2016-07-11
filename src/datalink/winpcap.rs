// Copyright (c) 2014-2016 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support for sending and receiving data link layer packets using the WinPcap library

extern crate libc;

use std::cmp;
use std::collections::VecDeque;
use std::ffi::CString;
use std::str::from_utf8_unchecked;
use std::io;
use std::mem;
use std::slice;
use std::sync::Arc;
use std::net::IpAddr;

use bindings::{bpf, winpcap};
use datalink::{self, NetworkInterface};
use datalink::Channel::Ethernet;
use datalink::{EthernetDataLinkChannelIterator, EthernetDataLinkReceiver, EthernetDataLinkSender};
use packet::Packet;
use packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use util::MacAddr;

struct WinPcapAdapter {
    adapter: winpcap::LPADAPTER,
}

impl Drop for WinPcapAdapter {
    fn drop(&mut self) {
        unsafe {
            winpcap::PacketCloseAdapter(self.adapter);
        }
    }
}

struct WinPcapPacket {
    packet: winpcap::LPPACKET,
}

impl Drop for WinPcapPacket {
    fn drop(&mut self) {
        unsafe {
            winpcap::PacketFreePacket(self.packet);
        }
    }
}

/// WinPcap specific configuration
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Config {
    /// The size of buffer to use when writing packets. Defaults to 4096
    pub write_buffer_size: usize,

    /// The size of buffer to use when reading packets. Defaults to 4096
    pub read_buffer_size: usize,
}

impl<'a> From<&'a datalink::Config> for Config {
    fn from(config: &datalink::Config) -> Config {
        Config {
            write_buffer_size: config.write_buffer_size,
            read_buffer_size: config.read_buffer_size,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            write_buffer_size: 4096,
            read_buffer_size: 4096,
        }
    }
}

/// Create a datalink channel using the WinPcap library
#[inline]
pub fn channel(network_interface: &NetworkInterface, config: &Config)
    -> io::Result<datalink::Channel> {
    let mut read_buffer = Vec::new();
    read_buffer.resize(config.read_buffer_size, 0u8);

    let mut write_buffer = Vec::new();
    write_buffer.resize(config.write_buffer_size, 0u8);

    let adapter = unsafe {
        let net_if_str = CString::new(network_interface.name.as_bytes()).unwrap();
        winpcap::PacketOpenAdapter(net_if_str.as_ptr() as *mut libc::c_char)
    };
    if adapter.is_null() {
        return Err(io::Error::last_os_error());
    }

    let ret = unsafe { winpcap::PacketSetHwFilter(adapter, winpcap::NDIS_PACKET_TYPE_PROMISCUOUS) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // Set kernel buffer size
    let ret = unsafe { winpcap::PacketSetBuff(adapter, config.read_buffer_size as libc::c_int) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    let ret = unsafe { winpcap::PacketSetReadTimeout(adapter, 0) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    // Immediate mode
    let ret = unsafe { winpcap::PacketSetMinToCopy(adapter, 1) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    let read_packet = unsafe { winpcap::PacketAllocatePacket() };
    if read_packet.is_null() {
        unsafe {
            winpcap::PacketCloseAdapter(adapter);
        }
        return Err(io::Error::last_os_error());
    }

    unsafe {
        winpcap::PacketInitPacket(read_packet,
                                  read_buffer.as_mut_ptr() as winpcap::PVOID,
                                  config.read_buffer_size as winpcap::UINT)
    }

    let write_packet = unsafe { winpcap::PacketAllocatePacket() };
    if write_packet.is_null() {
        unsafe {
            winpcap::PacketFreePacket(read_packet);
            winpcap::PacketCloseAdapter(adapter);
        }
        return Err(io::Error::last_os_error());
    }

    unsafe {
        winpcap::PacketInitPacket(write_packet,
                                  write_buffer.as_mut_ptr() as winpcap::PVOID,
                                  config.write_buffer_size as winpcap::UINT)
    }

    let adapter = Arc::new(WinPcapAdapter { adapter: adapter });
    let sender = Box::new(DataLinkSenderImpl {
        adapter: adapter.clone(),
        _write_buffer: write_buffer,
        packet: WinPcapPacket { packet: write_packet },
    });
    let receiver = Box::new(DataLinkReceiverImpl {
        adapter: adapter,
        _read_buffer: read_buffer,
        packet: WinPcapPacket { packet: read_packet },
    });
    Ok(Ethernet(sender, receiver))
}

struct DataLinkSenderImpl {
    adapter: Arc<WinPcapAdapter>,
    _write_buffer: Vec<u8>,
    packet: WinPcapPacket,
}

impl EthernetDataLinkSender for DataLinkSenderImpl {
    #[inline]
    fn build_and_send(&mut self,
                      num_packets: usize,
                      packet_size: usize,
                      func: &mut FnMut(MutableEthernetPacket))
        -> Option<io::Result<()>> {
        let len = num_packets * packet_size;
        if len >= unsafe { (*self.packet.packet).Length } as usize {
            None
        } else {
            let min = unsafe { cmp::min((*self.packet.packet).Length as usize, len) };
            let slice: &mut [u8] = unsafe {
                slice::from_raw_parts_mut((*self.packet.packet).Buffer as *mut u8, min)
            };
            for chunk in slice.chunks_mut(packet_size) {
                {
                    let eh = MutableEthernetPacket::new(chunk).unwrap();
                    func(eh);
                }

                // Make sure the right length of packet is sent
                let old_len = unsafe { (*self.packet.packet).Length };
                unsafe {
                    (*self.packet.packet).Length = packet_size as u32;
                }

                let ret = unsafe {
                    winpcap::PacketSendPacket(self.adapter.adapter, self.packet.packet, 0)
                };

                unsafe {
                    (*self.packet.packet).Length = old_len;
                }

                if ret == 0 {
                    return Some(Err(io::Error::last_os_error()));
                }
            }
            Some(Ok(()))
        }
    }

    #[inline]
    fn send_to(&mut self,
               packet: &EthernetPacket,
               _dst: Option<NetworkInterface>)
        -> Option<io::Result<()>> {
        use packet::MutablePacket;
        self.build_and_send(1,
                            packet.packet().len(),
                            &mut |mut eh| {
                                eh.clone_from(packet);
                            })
    }
}

unsafe impl Send for DataLinkSenderImpl {}
unsafe impl Sync for DataLinkSenderImpl {}

struct DataLinkReceiverImpl {
    adapter: Arc<WinPcapAdapter>,
    _read_buffer: Vec<u8>,
    packet: WinPcapPacket,
}

impl EthernetDataLinkReceiver for DataLinkReceiverImpl {
    fn iter<'a>(&'a mut self) -> Box<EthernetDataLinkChannelIterator + 'a> {
        let buflen = unsafe { (*self.packet.packet).Length } as usize;
        Box::new(DataLinkChannelIteratorImpl {
            pc: self,
            // Enough room for minimally sized packets without reallocating
            packets: VecDeque::with_capacity(buflen / 64),
        })
    }
}

unsafe impl Send for DataLinkReceiverImpl {}
unsafe impl Sync for DataLinkReceiverImpl {}

struct DataLinkChannelIteratorImpl<'a> {
    pc: &'a mut DataLinkReceiverImpl,
    packets: VecDeque<(usize, usize)>,
}

impl<'a> EthernetDataLinkChannelIterator<'a> for DataLinkChannelIteratorImpl<'a> {
    fn next(&mut self) -> io::Result<EthernetPacket> {
        // NOTE Most of the logic here is identical to FreeBSD/OS X
        if self.packets.is_empty() {
            let ret = unsafe {
                winpcap::PacketReceivePacket(self.pc.adapter.adapter, self.pc.packet.packet, 0)
            };
            let buflen = match ret {
                0 => return Err(io::Error::last_os_error()),
                _ => unsafe { (*self.pc.packet.packet).ulBytesReceived },
            };
            let mut ptr = unsafe { (*self.pc.packet.packet).Buffer };
            let end = unsafe { (*self.pc.packet.packet).Buffer.offset(buflen as isize) };
            while ptr < end {
                unsafe {
                    let packet: *const bpf::bpf_hdr = mem::transmute(ptr);
                    let start = ptr as isize + (*packet).bh_hdrlen as isize -
                                (*self.pc.packet.packet).Buffer as isize;
                    self.packets.push_back((start as usize, (*packet).bh_caplen as usize));
                    let offset = (*packet).bh_hdrlen as isize + (*packet).bh_caplen as isize;
                    ptr = ptr.offset(bpf::BPF_WORDALIGN(offset));
                }
            }
        }
        let (start, len) = self.packets.pop_front().unwrap();
        let slice = unsafe {
            let data = (*self.pc.packet.packet).Buffer as usize + start;
            slice::from_raw_parts(data as *const u8, len)
        };
        Ok(EthernetPacket::new(slice).unwrap())
    }
}

/// Get a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<NetworkInterface> {
    use bindings::winpcap;

    let mut adapters_size = 0u32;

    unsafe {
        let mut tmp: winpcap::IP_ADAPTER_INFO = mem::zeroed();
        // FIXME [windows] This only gets IPv4 addresses - should use
        // GetAdaptersAddresses
        winpcap::GetAdaptersInfo(&mut tmp, &mut adapters_size);
    }

    let vec_size = adapters_size / mem::size_of::<winpcap::IP_ADAPTER_INFO>() as u32;

    let mut adapters = Vec::with_capacity(vec_size as usize);

    // FIXME [windows] Check return code
    unsafe {
        winpcap::GetAdaptersInfo(adapters.as_mut_ptr(), &mut adapters_size);
    }

    // Create a complete list of NetworkInterfaces for the machine
    let mut cursor = adapters.as_mut_ptr();
    let mut all_ifaces = Vec::with_capacity(vec_size as usize);
    while !cursor.is_null() {
        let mac = unsafe {
            MacAddr((*cursor).Address[0],
                    (*cursor).Address[1],
                    (*cursor).Address[2],
                    (*cursor).Address[3],
                    (*cursor).Address[4],
                    (*cursor).Address[5])
        };
        let mut ip_cursor = unsafe { &mut (*cursor).IpAddressList as winpcap::PIP_ADDR_STRING };
        let mut ips: Vec<IpAddr> = Vec::new();
        while !ip_cursor.is_null() {
            let ip_str_ptr = unsafe { &(*ip_cursor) }.IpAddress.String.as_ptr() as *const i8;
            let bytes = unsafe { CStr::from_ptr(ip_str_ptr).to_bytes() };
            let ip_str = unsafe { from_utf8_unchecked(bytes).to_owned() };
            ips.push(ip_str.parse().unwrap());
            ip_cursor = unsafe { (*ip_cursor).Next };
        }

        unsafe {
            let name_str_ptr = (*cursor).AdapterName.as_ptr() as *const i8;

            let bytes = CStr::from_ptr(name_str_ptr).to_bytes();
            let name_str = from_utf8_unchecked(bytes).to_owned();

            all_ifaces.push(NetworkInterface {
                name: name_str,
                index: (*cursor).Index,
                mac: Some(mac),
                ips: Some(ips),
                // flags: (*cursor).Type, // FIXME [windows]
                flags: 0,
            });

            cursor = (*cursor).Next;
        }
    }

    let mut buf = [0u8; 4096];
    let mut buflen = buf.len() as u32;

    // Gets list of supported adapters in form:
    // adapter1\0adapter2\0\0desc1\0desc2\0\0
    if unsafe { winpcap::PacketGetAdapterNames(buf.as_mut_ptr() as *mut i8, &mut buflen) } == 0 {
        // FIXME [windows] Should allocate a buffer big enough and try again
        //        - size should be buf.len() + buflen (buflen is overwritten)
        panic!("FIXME [windows] unable to get interface list");
    }

    let buf_str = unsafe { from_utf8_unchecked(&buf) };
    let iface_names = buf_str.split("\0\0").next();
    let mut vec = Vec::new();

    // Return only supported adapters
    match iface_names {
        Some(iface_names) => {
            for iface in iface_names.split('\0') {
                let name = iface.to_owned();
                let next = all_ifaces.iter().filter(|x| name[..].ends_with(&x.name[..])).next();
                if next.is_some() {
                    let mut iface = next.unwrap().clone();
                    iface.name = name;
                    vec.push(iface);
                }
            }
        }
        None => (),
    };

    vec
}
