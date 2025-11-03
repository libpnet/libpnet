use super::{DataLinkReceiver, DataLinkSender, NetworkInterface};

use ndisapi::{MacAddress, Ndisapi, IphlpNetworkAdapterInfo};
use pnet_base::MacAddr;
use ipnetwork::IpNetwork;

use std::collections::VecDeque;
use std::io;
use std::net::IpAddr;

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
    #[allow(dead_code)]
    packets: VecDeque<(usize, usize)>,
}

impl DataLinkReceiver for DataLinkReceiverImpl {
    fn next(&mut self) -> io::Result<&[u8]> {
        // TODO: Use `read_packet` or similar from ndisapi, push into `self.packets`
        Err(io::Error::new(io::ErrorKind::Other, "not implemented"))
    }
}

pub fn interfaces() -> Vec<NetworkInterface> {
    let mut interfaces = Vec::new();

    let driver = match Ndisapi::new("NDISRD") {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to open WinPkFilter driver: {:?}", e);
            eprintln!("Make sure the Windows Packet Filter driver is installed and running.");
            return Vec::new();
        }
    };

    let adapters = match driver.get_tcpip_bound_adapters_info() {
        Ok(adapters) => adapters,
        Err(e) => {
            eprintln!("Failed to get adapter information: {:?}", e);
            return Vec::new();
        }
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

        // Get IP addresses using ndisapi-rs IP Helper functionality
        let ips: Vec<IpNetwork> = if let Some(mac_addr) = MacAddress::from_slice(adapter.get_hw_address()) {
            if let Some(ip_info) = IphlpNetworkAdapterInfo::get_connection_by_hw_address(&mac_addr) {
                ip_info.unicast_address_list()
                    .iter()
                    .filter_map(|ip_addr| {
                        // Convert IpAddr to IpNetwork with default prefix lengths
                        match ip_addr {
                            IpAddr::V4(_) => IpNetwork::new(*ip_addr, 24).ok(), // Default /24 for IPv4
                            IpAddr::V6(_) => IpNetwork::new(*ip_addr, 64).ok(), // Default /64 for IPv6
                        }
                    })
                    .collect()
            } else {
                vec![]
            }
        } else {
            vec![]
        };

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
