//! A VLAN packet abstraction.

use crate::PrimitiveValues;
use crate::ethernet::EtherType;

use alloc::vec::Vec;

use pnet_macros::packet;
use pnet_macros_support::types::*;

/// Represents an IEEE 802.1p class of a service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClassOfService(pub u3);

impl ClassOfService {
    /// Create a new `ClassOfService` instance.
    pub fn new(value: u3) -> ClassOfService {
        ClassOfService(value)
    }
}

impl PrimitiveValues for ClassOfService {
    type T = (u3,);
    fn to_primitive_values(&self) -> (u3,) {
        (self.0,)
    }
}

/// IEEE 802.1p classes of service as defined in
/// <https://en.wikipedia.org/wiki/IEEE_P802.1p>.
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod ClassesOfService {
    use super::ClassOfService;

    /// Background
    pub const BK: ClassOfService = ClassOfService(1);

    /// Best Effort
    pub const BE: ClassOfService = ClassOfService(0);

    /// Excellent Effort
    pub const EE: ClassOfService = ClassOfService(2);

    /// Critical Applications
    pub const CA: ClassOfService = ClassOfService(3);

    /// Video, < 100 ms latency
    pub const VI: ClassOfService = ClassOfService(4);

    /// Voice, < 10 ms latency
    pub const VO: ClassOfService = ClassOfService(5);

    /// Internetwork Control
    pub const IC: ClassOfService = ClassOfService(6);

    /// Network Control
    pub const NC: ClassOfService = ClassOfService(7);
}

/// Represents a VLAN-tagged packet.
#[packet]
pub struct Vlan {
    #[construct_with(u3)]
    pub priority_code_point: ClassOfService,
    pub drop_eligible_indicator: u1,
    pub vlan_identifier: u12be,
    #[construct_with(u16be)]
    pub ethertype: EtherType,
    #[payload]
    pub payload: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use crate::ethernet::EtherTypes;
    use super::*;

    #[test]
    fn vlan_packet_test() {
        let mut packet = [0u8; 4];
        {
            let mut vlan_header = MutableVlanPacket::new(&mut packet[..]).unwrap();
            vlan_header.set_priority_code_point(ClassesOfService::BE);
            assert_eq!(vlan_header.get_priority_code_point(), ClassesOfService::BE);

            vlan_header.set_drop_eligible_indicator(0);
            assert_eq!(vlan_header.get_drop_eligible_indicator(), 0);

            vlan_header.set_ethertype(EtherTypes::Ipv4);
            assert_eq!(vlan_header.get_ethertype(), EtherTypes::Ipv4);

            vlan_header.set_vlan_identifier(0x100);
            assert_eq!(vlan_header.get_vlan_identifier(), 0x100);
        }

        let ref_packet = [0x01,  // PCP, DEI, and first nibble of VID
                          0x00,  // Remainder of VID
                          0x08,  // First byte of ethertype
                          0x00]; // Second byte of ethertype
        assert_eq!(&ref_packet[..], &packet[..]);
    }
}
