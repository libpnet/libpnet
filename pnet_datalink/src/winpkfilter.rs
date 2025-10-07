use super::{DataLinkReceiver, DataLinkSender, NetworkInterface};

use ndisapi::{IphlpNetworkAdapterInfo, MacAddress, Ndisapi, PacketOidData};
use pnet_base::MacAddr;

use std::collections::VecDeque;
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
    _network_interface: &NetworkInterface,
    _config: Config,
) -> io::Result<super::Channel> {
    // TODO: Use ndisapi to open the adapter using network_interface.name
    // Initialize your sender/receiver objects here
    //
    // Example: You’ll likely use `Ndisapi::new()` and then `open_adapter(name)`

    let sender = Box::new(DataLinkSenderImpl {
        // Fill with real fields
    });

    let receiver = Box::new(DataLinkReceiverImpl {
        packets: VecDeque::new(),
    });

    Ok(super::Channel::Ethernet(sender, receiver))
}

struct DataLinkSenderImpl {
    // TODO: Fields for adapter handle, buffer, etc.
}

impl DataLinkSender for DataLinkSenderImpl {
    fn build_and_send(
        &mut self,
        _num_packets: usize,
        _packet_size: usize,
        _func: &mut dyn FnMut(&mut [u8]),
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

pub fn interfaces() -> Vec<NetworkInterface> {
    const OID_802_3_CURRENT_ADDRESS: u32 = 0x01010102;
    IphlpNetworkAdapterInfo
    let mut interfaces = Vec::new();

    let driver = match Ndisapi::new("NDISRD") {
        Ok(d) => d,
        Err(_) => return interfaces, // No driver? Return empty
    };

    let adapters = match driver.get_tcpip_bound_adapters_info() {
        Ok(adapters) => adapters,
        Err(_) => return interfaces,
    };

    for adapter in adapters {
        let name = adapter.get_name().to_string();
        let description =
            Ndisapi::get_friendly_adapter_name(adapter.get_name()).unwrap_or_else(|_| name.clone());

        let index = adapter.get_handle().0 as u32; // this is a HANDLE, but we can treat as u32 for indexing

        // Get MAC
        let mac: Option<MacAddr> = MacAddress::from_slice(adapter.get_hw_address())
    .map(|m| {
        let bytes = m.get();
        MacAddr(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5])
    });


        // IP address info not directly available from `ndisapi` — leave empty for now
        let ips = vec![];

        interfaces.push(NetworkInterface {
            name,
            description,
            index,
            mac,
            ips,
            flags: 0,
        });
    }

    interfaces
}
