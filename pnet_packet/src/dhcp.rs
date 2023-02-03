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

/// Represents an DHCP Packet.
#[packet]
#[allow(non_snake_case)]
pub struct Dhcp {
    #[construct_with(u8)]
    pub op: DhcpOperation,
    #[construct_with(u8)]
    pub htype: DhcpHardwareType,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32be,
    pub secs: u16be,
    pub flags: u16be,
    #[construct_with(u8, u8, u8, u8)]
    pub ciaddr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub yiaddr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub siaddr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8)]
    pub giaddr: Ipv4Addr,
    #[construct_with(u8, u8, u8, u8, u8, u8)]
    pub chaddr: MacAddr,
    #[length = "10"]
    pub chaddr_pad: Vec<u8>,
    #[length = "64"]
    pub sname: Vec<u8>,
    #[length = "128"]
    pub file: Vec<u8>,
    #[payload]
    pub options: Vec<u8>,
}