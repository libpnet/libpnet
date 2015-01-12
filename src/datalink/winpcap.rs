// Copyright (c) 2014 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate libc;

use std::cmp;
use std::collections::{RingBuf};
use std::io::{IoResult, IoError};
use std::mem;
use std::raw::Slice;
use std::sync::Arc;

use bindings::{bpf, winpcap};
use datalink::{DataLinkChannelType};
use packet::Packet;
use packet::ethernet::{EthernetHeader, MutableEthernetHeader};
use util::NetworkInterface;

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

pub fn datalink_channel(network_interface: &NetworkInterface,
           read_buffer_size: usize,
           write_buffer_size: usize,
           channel_type: DataLinkChannelType)
    -> IoResult<(DataLinkSenderImpl, DataLinkReceiverImpl)> {
    let mut read_buffer = Vec::from_elem(read_buffer_size, 0u8);
    let mut write_buffer = Vec::from_elem(read_buffer_size, 0u8);

    let adapter = unsafe {
        winpcap::PacketOpenAdapter(network_interface.name.to_c_str().as_mut_ptr())
    };
    if adapter.is_null() {
        return Err(IoError::last_error());
    }

    let ret = unsafe {
        winpcap::PacketSetHwFilter(adapter, winpcap::NDIS_PACKET_TYPE_PROMISCUOUS)
    };
    if ret == 0 {
        return Err(IoError::last_error());
    }

    // Set kernel buffer size
    let ret = unsafe {
        winpcap::PacketSetBuff(adapter, read_buffer_size as libc::c_int)
    };
    if ret == 0 {
        return Err(IoError::last_error());
    }

    // FIXME [windows] This shouldn't be here - on Win32 reading seems to block indefinitely
    //       currently.
    let ret = unsafe {
        winpcap::PacketSetReadTimeout(adapter, 5000)
    };
    if ret == 0 {
        return Err(IoError::last_error());
    }

    // Immediate mode
    let ret = unsafe {
        winpcap::PacketSetMinToCopy(adapter, 1)
    };
    if ret == 0 {
        return Err(IoError::last_error());
    }

    let read_packet = unsafe { winpcap::PacketAllocatePacket() };
    if read_packet.is_null() {
        unsafe {
            winpcap::PacketCloseAdapter(adapter);
        }
        return Err(IoError::last_error());
    }

    unsafe {
        winpcap::PacketInitPacket(read_packet,
                                  read_buffer.as_mut_ptr() as winpcap::PVOID,
                                  read_buffer_size as winpcap::UINT)
    }

    let write_packet = unsafe { winpcap::PacketAllocatePacket() };
    if write_packet.is_null() {
        unsafe {
            winpcap::PacketFreePacket(read_packet);
            winpcap::PacketCloseAdapter(adapter);
        }
        return Err(IoError::last_error());
    }

    unsafe {
        winpcap::PacketInitPacket(write_packet,
                                  write_buffer.as_mut_ptr() as winpcap::PVOID,
                                  write_buffer_size as winpcap::UINT)
    }

    let adapter = Arc::new(WinPcapAdapter { adapter: adapter });
    let sender = DataLinkSenderImpl {
        adapter: adapter.clone(),
        _vec: write_buffer,
        packet: WinPcapPacket { packet: write_packet }
    };
    let receiver = DataLinkReceiverImpl {
        adapter: adapter,
        _vec: read_buffer,
        packet: WinPcapPacket { packet: read_packet }
    };
    Ok((sender, receiver))
}


pub struct DataLinkSenderImpl {
    adapter: Arc<WinPcapAdapter>,
    _vec: Vec<u8>,
    packet: WinPcapPacket,
}

pub struct DataLinkReceiverImpl {
    adapter: Arc<WinPcapAdapter>,
    _vec: Vec<u8>,
    packet: WinPcapPacket,
}

impl DataLinkSenderImpl {
    pub fn build_and_send<F>(&mut self, num_packets: usize, packet_size: usize,
                          func: &mut F) -> Option<IoResult<()>>
        where F : FnMut(MutableEthernetHeader)
    {
        use std::raw::Slice;
        let len = num_packets * packet_size;
        if len >= unsafe { (*self.packet.packet).Length } as usize {
            None
        } else {
            let min = unsafe { cmp::min((*self.packet.packet).Length as usize, len) };
            let slice: &mut [u8] = unsafe {
                    mem::transmute(
                        Slice {
                            data: (*self.packet.packet).Buffer as *const (),
                            len: min
                        }
                    )
            };
            for chunk in slice.chunks_mut(packet_size) {
                {
                    let eh = MutableEthernetHeader::new(chunk);
                    func(eh);
                }

                // Make sure the right length of packet is sent
                let old_len = unsafe { (*self.packet.packet).Length };
                unsafe { (*self.packet.packet).Length = packet_size as u32; }

                let ret = unsafe { winpcap::PacketSendPacket(self.adapter.adapter, self.packet.packet, 0) };

                unsafe { (*self.packet.packet).Length = old_len; }

                match ret {
                    0 => return Some(Err(IoError::last_error())),
                    _ => ()
                }
            }
            Some(Ok(()))
        }
    }

    pub fn send_to(&mut self, packet: EthernetHeader, _dst: Option<NetworkInterface>)
        -> Option<IoResult<()>> {
        use packet::MutablePacket;
        self.build_and_send(1, packet.packet().len(), |mut eh| {
            eh.clone_from(packet);
        })
    }
}

impl DataLinkReceiverImpl {
    pub fn iter<'a>(&'a mut self) -> DataLinkChannelIteratorImpl<'a> {
        let buflen = unsafe { (*self.packet.packet).Length } as usize;
        DataLinkChannelIteratorImpl {
            pc: self,
            // Enough room for minimally sized packets without reallocating
            packets: RingBuf::with_capacity(buflen / 64)
        }
    }
}

pub struct DataLinkChannelIteratorImpl<'a> {
    pc: &'a mut DataLinkReceiverImpl,
    packets: RingBuf<(usize, usize)>,
}

impl<'a> DataLinkChannelIteratorImpl<'a> {
    pub fn next<'c>(&'c mut self) -> IoResult<EthernetHeader<'c>> {
        // NOTE Most of the logic here is identical to FreeBSD/OS X
        if self.packets.is_empty() {
            let ret = unsafe {
                winpcap::PacketReceivePacket(self.pc.adapter.adapter, self.pc.packet.packet, 0)
            };
            let buflen = match ret {
                0 => return Err(IoError::last_error()),
                _ => unsafe { (*self.pc.packet.packet).ulBytesReceived },
            };
            let mut ptr = unsafe { (*self.pc.packet.packet).Buffer };
            let end = unsafe { (*self.pc.packet.packet).Buffer.offset(buflen as int) };
            while ptr < end {
                unsafe {
                    let packet: *const bpf::bpf_hdr = mem::transmute(ptr);
                    let start = ptr as int +
                                (*packet).bh_hdrlen as int -
                                (*self.pc.packet.packet).Buffer as int;
                    self.packets.push((start as usize, (*packet).bh_caplen as usize));
                    let offset = (*packet).bh_hdrlen as int + (*packet).bh_caplen as int;
                    ptr = ptr.offset(bpf::BPF_WORDALIGN(offset));
                }
            }
        }
        let (start, len) = self.packets.pop_front().unwrap();
        let slice = unsafe {
            let data = (*self.pc.packet.packet).Buffer as usize + start;
            mem::transmute(Slice { data: data as *const u8, len: len } )
        };
        Ok(EthernetHeader::new(slice))
    }
}

