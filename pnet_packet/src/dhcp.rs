use crate::PrimitiveValues;

use alloc::vec::Vec;

use pnet_base::core_net::Ipv4Addr;
use pnet_base::MacAddr;
use pnet_macros::packet;
use pnet_macros_support::types::*;

/// Represents an Dhcp operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DhcpOperation(pub u8);

impl DhcpOperation {
    /// Create a new `ArpOperation`.
    pub fn new(value: u8) -> Self {
        DhcpOperation(value)
    }
}

impl PrimitiveValues for DhcpOperation {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

/// The Dhcp protocol operations.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod DhcpOperations {
    use super::DhcpOperation;

    /// DHCP request
    pub const Request: DhcpOperation = DhcpOperation(1);

    /// Dhcp reply
    pub const Reply: DhcpOperation = DhcpOperation(2);
}

/// Represents the Dhcp hardware types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DhcpHardwareType(pub u8);

impl DhcpHardwareType {
    /// Create a new `DhcpHardwareType`.
    pub fn new(value: u8) -> Self {
        DhcpHardwareType(value)
    }
}

impl PrimitiveValues for DhcpHardwareType {
    type T = (u8,);
    fn to_primitive_values(&self) -> (u8,) {
        (self.0,)
    }
}

/// The Dhcp protocol hardware types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod DhcpHardwareTypes {
    use super::DhcpHardwareType;

    /// Ethernet
    pub const Ethernet: DhcpHardwareType = DhcpHardwareType(1);
}

/// Represents the Dhcp magic cookie.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DhcpMagicCookie(pub u32);

impl DhcpMagicCookie {
    /// Create a new `DhcpMagicCookie`.
    pub fn new(value: u32) -> Self {
        DhcpMagicCookie(value)
    }
}

impl PrimitiveValues for DhcpMagicCookie {
    type T = (u32,);
    fn to_primitive_values(&self) -> (u32,) {
        (self.0,)
    }
}

/// The Dhcp protocol hardware types.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod DhcpMagicCookies {
    use super::DhcpMagicCookie;

    /// Cookie default
    pub const cookie: DhcpMagicCookie = DhcpMagicCookie(0x63825363);
}

/// Represents an DHCP Packet.
#[packet]
#[allow(non_snake_case)]
pub struct Dhcp {
    #[construct_with(u8)]
    pub op_code: DhcpOperation,
    #[construct_with(u8)]
    pub hw_type: DhcpHardwareType,
    pub hw_address_length: u8,
    pub hop_count: u8,
    pub transaction_id: u32be,
    pub number_of_seconds: u16be,
    pub flags: u16be,
    #[construct_with(u8, u8, u8, u8)]
    pub client_ip_addr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub your_ip_addr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub server_ip_addr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub reply_agent_ip_addr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8, u8, u8)]
    pub client_hw_addr: MacAddr,
    #[length = "10"]
    pub client_hw_addr_pad: Vec<u8>,
    #[length = "64"]
    pub server_host_name: Vec<u8>,
    #[length = "128"]
    pub boot_file_name: Vec<u8>,
    #[construct_with(u32)]
    pub magic_cookie: DhcpMagicCookie,
    #[payload]
    pub payload: Vec<u8>,
}