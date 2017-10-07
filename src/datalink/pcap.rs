//! Support for sending and receiving data link layer packets using libpcap.
//! Also has support for reading pcap files.
extern crate pcap;

use std::marker::{Send, Sync};
use std::io;
use std::iter::repeat;
use self::pcap::{Active, Activated};
use datalink::{self, NetworkInterface};
use datalink::{EthernetDataLinkChannelIterator, EthernetDataLinkReceiver, EthernetDataLinkSender};
use datalink::Channel::Ethernet;
use packet::Packet;
use packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::path::Path;

/// Configuration for the pcap datalink backend
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Config {
    /// The size of buffer to use when reading packets. Defaults to 4096
    pub read_buffer_size: usize,

    /// The read timeout. Defaults to None.
    pub read_timeout: Option<Duration>,
}

impl<'a> From<&'a datalink::Config> for Config {
    fn from(config: &datalink::Config) -> Config {
        Config{
            read_buffer_size: config.read_buffer_size,
            read_timeout: config.read_timeout,
        }
    }
}

impl Default for Config {
    fn default() -> Config {
        Config{
            read_buffer_size: 4096,
            read_timeout: None,
        }
    }
}

/// Create a datalink channel from the provided pcap device
#[inline]
pub fn channel(network_interface: &NetworkInterface,
               config: Config) -> io::Result<datalink::Channel> {
    let cap = match pcap::Capture::from_device(&*network_interface.name) {
        Ok(cap) => cap,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
    }.buffer_size(config.read_buffer_size as i32);
    let cap = match config.read_timeout {
        Some(to) => cap.timeout(
            (to.as_secs() * 1000 + (to.subsec_nanos() / 1000) as u64) as i32
        ),
        None => cap
    };
    let cap = match cap.open() {
        Ok(cap) => cap,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
    };
    let cap = Arc::new(Mutex::new(cap));
    Ok(Ethernet(
        Box::new(DataLinkSenderImpl {
            capture: cap.clone(),
        }),
        Box::new(DataLinkReceiverImpl {
            capture: cap.clone(),
            read_buffer: repeat(0u8).take(config.read_buffer_size).collect(),
        })
    ))
}

/// Create a datalink channel from a pcap file
#[inline]
pub fn from_file<P: AsRef<Path>>(path: P, config: Config) -> io::Result<datalink::Channel> {
    let cap = match pcap::Capture::from_file(path) {
        Ok(cap) => cap,
        Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
    };
    let cap = Arc::new(Mutex::new(cap));
    Ok(Ethernet(
        Box::new(InvalidDataLinkSenderImpl {}),
        Box::new(DataLinkReceiverImpl {
            capture: cap.clone(),
            read_buffer: repeat(0u8).take(config.read_buffer_size).collect(),
        })
    ))
}

struct DataLinkSenderImpl {
    capture: Arc<Mutex<pcap::Capture<Active>>>,
}

impl EthernetDataLinkSender for DataLinkSenderImpl {
    #[inline]
    fn build_and_send(&mut self,
                      num_packets: usize,
                      packet_size: usize,
                      func: &mut FnMut(MutableEthernetPacket))
                      -> Option<io::Result<()>> {
        for _ in 0..num_packets {
            let mut data = vec![0; packet_size];
            {
                let eh = MutableEthernetPacket::new(&mut data).unwrap();
                func(eh);
            }
            let mut cap = self.capture.lock().unwrap();
            if let Err(e) = cap.sendpacket(data) {
                return Some(Err(io::Error::new(io::ErrorKind::Other, e)))
            }
        }
        Some(Ok(()))
    }

    #[inline]
    fn send_to(&mut self,
               packet: &EthernetPacket,
               _dst: Option<NetworkInterface>) -> Option<io::Result<()>> {
        let mut cap = self.capture.lock().unwrap();
        Some(match cap.sendpacket(packet.packet()) {
            Ok(()) => Ok(()),
            Err(e) => Err(io::Error::new(io::ErrorKind::Other, e)),
        })
    }
}

struct InvalidDataLinkSenderImpl {}

impl EthernetDataLinkSender for InvalidDataLinkSenderImpl {
    #[inline]
    fn build_and_send(&mut self,
                      _num_packets: usize,
                      _packet_size: usize,
                      _func: &mut FnMut(MutableEthernetPacket))
                      -> Option<io::Result<()>> {
        None
    }

    #[inline]
    fn send_to(&mut self,
               _packet: &EthernetPacket,
               _dst: Option<NetworkInterface>) -> Option<io::Result<()>> {
        None
    }
}

struct DataLinkReceiverImpl<T: Activated + Send + Sync> {
    capture: Arc<Mutex<pcap::Capture<T>>>,
    read_buffer: Vec<u8>,
}

impl <T: Activated + Send + Sync> EthernetDataLinkReceiver for DataLinkReceiverImpl<T> {
    fn iter<'a>(&'a mut self) -> Box<EthernetDataLinkChannelIterator + 'a> {
        Box::new(DataLinkChannelIteratorImpl { pc: self })
    }
}

struct DataLinkChannelIteratorImpl<'a, T: Activated + Send + Sync + 'a> {
    pc: &'a mut DataLinkReceiverImpl<T>,
}

impl<'a, T: Activated + Send + Sync> EthernetDataLinkChannelIterator<'a> for DataLinkChannelIteratorImpl<'a, T> {
    fn next(&mut self) -> io::Result<EthernetPacket> {
        let mut cap = self.pc.capture.lock().unwrap();
        match cap.next() {
            Ok(pkt) => {
                self.pc.read_buffer.truncate(0);
                self.pc.read_buffer.extend(pkt.data);
            },
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, e)),
        };
        Ok(EthernetPacket::new(&self.pc.read_buffer).unwrap())
    }
}

/// Get a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<NetworkInterface> {
    if let Ok(devices) = pcap::Device::list() {
        devices.iter().enumerate().map(|(i, dev)| {
            NetworkInterface {
                name: dev.name.clone(),
                index: i as u32,
                mac: None,
                ips: Vec::new(),
                flags: 0,
            }
        }).collect()
    } else {
        vec![]
    }
}
