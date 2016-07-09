// Copyright (c) 2016 Linus Färnstrand <faern@faern.net>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Support for sending and receiving data link layer packets on a fake network managed
//! by in memory FIFO queues. Useful for writing tests.

use std::io;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time;

use datalink::{self, EthernetDataLinkChannelIterator, EthernetDataLinkReceiver,
               EthernetDataLinkSender, NetworkInterface};
use packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use util::MacAddr;

/// Configuration for the dummy datalink backend
#[derive(Debug)]
pub struct Config {
    /// The fake network will pull packets (or errors) form this `Receiver`
    pub in_packets_rx: Receiver<io::Result<Box<[u8]>>>,

    in_packets_tx: Option<Sender<io::Result<Box<[u8]>>>>,

    /// All packets sent to this fake network will end up on this `Sender`
    pub out_packets_tx: Sender<Vec<u8>>,

    out_packets_rx: Option<Receiver<Vec<u8>>>,
}

impl Config {
    /// Get the `Sender` handle that can inject packets in the fake network
    pub fn inject_handle(&mut self) -> Option<Sender<io::Result<Box<[u8]>>>> {
        self.in_packets_tx.take()
    }

    /// Get the `Receiver` handle where packets sent to the fake network can be read
    pub fn read_handle(&mut self) -> Option<Receiver<Vec<u8>>> {
        self.out_packets_rx.take()
    }
}

impl<'a> From<&'a datalink::Config> for Config {
    /// This conversion will not allow injecting and reading packets from the dummy network.
    /// To do that please create your own `dummy::Config`
    fn from(_config: &datalink::Config) -> Config {
        Config::default()
    }
}

impl Default for Config {
    /// This conversion will not allow injecting and reading packets from the dummy network.
    /// To do that please create your own `dummy::Config`
    fn default() -> Config {
        let (in_tx, in_rx) = mpsc::channel();
        let (out_tx, out_rx) = mpsc::channel();
        Config {
            in_packets_rx: in_rx,
            in_packets_tx: Some(in_tx),
            out_packets_tx: out_tx,
            out_packets_rx: Some(out_rx),
        }
    }
}

/// Create a data link channel backed by FIFO queues. Useful for debugging and testing.
pub fn channel(_: &NetworkInterface, config: Config) -> io::Result<datalink::Channel> {
    let sender = Box::new(MockEthernetDataLinkSender { out_packets: config.out_packets_tx });
    let receiver =
        Box::new(MockEthernetDataLinkReceiver { in_packets: Some(config.in_packets_rx) });

    Ok(datalink::Channel::Ethernet(sender, receiver))
}


struct MockEthernetDataLinkSender {
    out_packets: Sender<Vec<u8>>,
}

impl EthernetDataLinkSender for MockEthernetDataLinkSender {
    fn build_and_send(&mut self,
                      _num_packets: usize,
                      packet_size: usize,
                      func: &mut FnMut(MutableEthernetPacket))
        -> Option<io::Result<()>> {
        let mut buffer = vec![0; packet_size];
        {
            let pkg = MutableEthernetPacket::new(&mut buffer[..]).unwrap();
            func(pkg);
        }
        // Send the data to the queue. Don't care if it's closed
        self.out_packets.send(buffer).unwrap_or(());
        Some(Ok(()))
    }

    fn send_to(&mut self,
               _packet: &EthernetPacket,
               _dst: Option<NetworkInterface>)
        -> Option<io::Result<()>> {
        panic!("Not implemented in mock");
    }
}

struct MockEthernetDataLinkReceiver {
    in_packets: Option<Receiver<io::Result<Box<[u8]>>>>,
}

impl EthernetDataLinkReceiver for MockEthernetDataLinkReceiver {
    fn iter<'a>(&'a mut self) -> Box<EthernetDataLinkChannelIterator + 'a> {
        Box::new(MockEthernetDataLinkChannelIterator {
            in_packets: self.in_packets.take().expect("Only one receiver allowed"),
            used_packets: vec![],
        })
    }
}

struct MockEthernetDataLinkChannelIterator {
    in_packets: Receiver<io::Result<Box<[u8]>>>,
    used_packets: Vec<Box<[u8]>>,
}

impl<'a> EthernetDataLinkChannelIterator<'a> for MockEthernetDataLinkChannelIterator {
    fn next(&mut self) -> io::Result<EthernetPacket> {
        match self.in_packets.recv() {
            Ok(result) => {
                match result {
                    Ok(buffer) => {
                        self.used_packets.push(buffer);
                        let buffer_ref = &*self.used_packets[self.used_packets.len() - 1];
                        let packet = EthernetPacket::new(buffer_ref).unwrap();
                        Ok(packet)
                    }
                    Err(e) => Err(e),
                }
            }
            Err(_) => {
                // When we run out of test packets we sleep forever.
                // Simulating no more packets arrive
                loop {
                    thread::sleep(time::Duration::new(1, 0));
                }
            }
        }
    }
}

/// Get three fake interfaces generated with `dummy_interface`
pub fn interfaces() -> Vec<NetworkInterface> {
    (0..3).map(|i| dummy_interface(i)).collect()
}

/// Generates a fake `NetworkInterface`.
/// The name of the interface will be `ethX` where X is the integer `i`.
/// The index will be `i`.
/// The MAC will be `01:02:03:04:05:i`.
pub fn dummy_interface(i: u8) -> NetworkInterface {
    NetworkInterface {
        name: format!("eth{}", i),
        index: i as u32,
        mac: Some(MacAddr::new(1, 2, 3, 4, 5, i)),
        ips: None,
        flags: 0,
    }
}
