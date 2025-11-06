use super::{DataLinkReceiver, DataLinkSender, NetworkInterface};

use ndisapi::{MacAddress, Ndisapi, IphlpNetworkAdapterInfo, EthRequest, IntermediateBuffer};
use pnet_base::MacAddr;
use ipnetwork::IpNetwork;
use windows::Win32::Foundation::HANDLE;

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
    network_interface: &NetworkInterface,
    config: Config,
) -> io::Result<super::Channel> {
    let driver = Ndisapi::new("NDISRD").map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to open WinPkFilter driver: {}", e))
    })?;

    let adapters = driver.get_tcpip_bound_adapters_info().map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("Failed to get adapter information: {}", e))
    })?;

    // Find the adapter by name
    let adapter = adapters.iter().find(|adapter| {
        adapter.get_name() == &network_interface.name
    }).ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "Network interface not found")
    })?;

    let adapter_handle = adapter.get_handle();

    let sender = Box::new(DataLinkSenderImpl {
        driver: driver.clone(),
        adapter_handle,
        write_buffer: vec![0u8; config.write_buffer_size],
    });

    let receiver = Box::new(DataLinkReceiverImpl {
        packets: VecDeque::new(),
    });

    Ok(super::Channel::Ethernet(sender, receiver))
}

struct DataLinkSenderImpl {
    driver: Ndisapi,
    adapter_handle: HANDLE,
    write_buffer: Vec<u8>,
}

impl DataLinkSender for DataLinkSenderImpl {
    fn build_and_send(
        &mut self,
        num_packets: usize,
        packet_size: usize,
        func: &mut dyn FnMut(&mut [u8]),
    ) -> Option<io::Result<()>> {
        let total_len = num_packets * packet_size;
        if total_len > self.write_buffer.len() {
            return None;
        }

        // Build packets using the provided function
        for i in 0..num_packets {
            let start = i * packet_size;
            let end = start + packet_size;
            func(&mut self.write_buffer[start..end]);
            
            // Create an IntermediateBuffer and copy the packet data
            let mut intermediate_buffer = IntermediateBuffer::default();
            
            // Check if packet size is within limits (MAX_ETHER_FRAME is the buffer size)
            const MAX_FRAME_SIZE: usize = 1514; // Standard Ethernet frame size
            if packet_size > MAX_FRAME_SIZE {
                return Some(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Packet size exceeds maximum frame size"
                )));
            }
            
            intermediate_buffer.set_length(packet_size as u32);
            intermediate_buffer.get_data_mut()
                .copy_from_slice(&self.write_buffer[start..end]);
            
            // Create EthRequest and send the packet
            let mut request = EthRequest::new(self.adapter_handle);
            request.set_packet(&intermediate_buffer);
            
            if let Err(e) = self.driver.send_packet_to_adapter(&request) {
                return Some(Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Failed to send packet: {}", e)
                )));
            }
        }
        
        Some(Ok(()))
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
                ip_info.unicast_address_list_with_prefix()
                    .iter()
                    .filter_map(|(ip_addr, prefix_len)| {
                        IpNetwork::new(*ip_addr, *prefix_len).ok()
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

unsafe impl Send for DataLinkSenderImpl {}
unsafe impl Sync for DataLinkSenderImpl {}
