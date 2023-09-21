// Copyright (c) 2023 Anson Mansfield <amansfield@mantaro.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Ethernet Flow Control \[IEEE 802.3x\] abstraction.

use crate::PrimitiveValues;

use alloc::vec::Vec;
use core::fmt;

use pnet_macros::packet;
use pnet_macros_support::types::u16be;

/// Represents the opcode field in an Ethernet Flow Control packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FlowControlOpcode(pub u16);

impl FlowControlOpcode {
    pub fn new(value: u16) -> Self {
        FlowControlOpcode(value)
    }
}
impl PrimitiveValues for FlowControlOpcode {
    type T = (u16,);
    fn to_primitive_values(&self) -> (u16,) {
        (self.0,)
    }
}
impl fmt::Display for FlowControlOpcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "{}",
            match self {
                &FlowControlOpcodes::Pause => "pause",
                _ => "unknown",
            })
    }
}

/// Flow control opcodes are defined in IEEE 802.3x
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
pub mod FlowControlOpcodes {
    use super::FlowControlOpcode;

    /// Request the other station pause for 512*quanta bit times.
    pub const Pause: FlowControlOpcode = FlowControlOpcode(1);
}

/// Represents an Ethernet Flow Control packet defined by IEEE 802.3x.
/// ([wikipedia](https://en.wikipedia.org/wiki/Ethernet_flow_control))
/// 
/// Use with the [EtherTypes::FlowControl](crate::ethernet::EtherTypes::FlowControl) ethertype (0x8808).
#[packet]
#[allow(non_snake_case)]
pub struct FlowControl {
    #[construct_with(u16)]
    pub command: FlowControlOpcode,
    pub quanta: u16be,
    #[payload]
    pub payload: Vec<u8>,
}
