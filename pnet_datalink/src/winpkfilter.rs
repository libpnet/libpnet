use super::{DataLinkSender, DataLinkReceiver, NetworkInterface};
use std::io;

/// The WinpkFilter's specific configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Config {
    /// Size of buffer to use when writing packets.
    pub write_buffer_size: usize,
    /// Size of buffer to use when reading packets.
    pub read_buffer_size: usize,
}

impl<'a> From<&'a super::Config> for Config {
    fn from(config: &super::Config) -> Config {
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

pub fn channel(
    network_interface: &NetworkInterface,
    config: Config,
) -> io::Result<super::Channel> {
    // TODO: Use ndisapi to open the adapter using network_interface.name
    // Initialize your sender/receiver objects here
    //
    // Example: You’ll likely use `Ndisapi::new()` and then `open_adapter(name)`
    
    let sender = Box::new(DataLinkSenderImpl {
        // Fill with real fields
    });

    let receiver = Box::new(DataLinkReceiverImpl {
        // Fill with real fields
    });

    Ok(super::Channel::Ethernet(sender, receiver))
}

struct DataLinkSenderImpl {
    // TODO: Fields for adapter handle, buffer, etc.
}

impl DataLinkSender for DataLinkSenderImpl {
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        // TODO: Build `num_packets` and send via ndisapi (sync or async)
        None
    }

    fn send_to(&mut self, packet: &[u8], _dst: Option<NetworkInterface>) -> Option<io::Result<()>> {
        self.build_and_send(1, packet.len(), &mut |buf| {
            buf.copy_from_slice(packet);
        })
    }
}

use std::collections::VecDeque;

struct DataLinkReceiverImpl {
    // TODO: Fields for adapter, buffers, queue, etc.
    packets: VecDeque<(usize, usize)>,
}

impl DataLinkReceiver for DataLinkReceiverImpl {
    fn next(&mut self) -> io::Result<&[u8]> {
        // TODO: Use `read_packet` or similar from ndisapi, push into `self.packets`
        Err(io::Error::new(io::ErrorKind::Other, "not implemented"))
    }
}

use super::NetworkInterface;

pub fn interfaces() -> Vec<NetworkInterface> {
    // TODO: Use ndisapi to list adapters, e.g. via `get_interface_names()` or related
    vec![]
}
