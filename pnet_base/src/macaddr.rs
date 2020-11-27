// Copyright (c) 2014-2016 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::error::Error;
use std::fmt;
use std::str::FromStr;

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// The number of bytes in an ethernet (MAC) address.
pub const ETHER_ADDR_LEN: usize = 6;

/// Structure of a 48-bit Ethernet address.
type EtherAddr = [u8; ETHER_ADDR_LEN];

const LOCAL_ADDR_BIT: u8 = 0x02;
const MULTICAST_ADDR_BIT: u8 = 0x01;

/// A MAC address.
#[derive(PartialEq, Eq, Clone, Copy, Default, Hash, Ord, PartialOrd)]
pub struct MacAddr(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddr {
    /// Construct a new `MacAddr` instance.
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddr {
        MacAddr(a, b, c, d, e, f)
    }

    /// Construct an all-zero `MacAddr` instance.
    pub fn zero() -> MacAddr {
        Default::default()
    }

    /// Construct a broadcast `MacAddr` instance.
    pub fn broadcast() -> MacAddr {
        [0xff; ETHER_ADDR_LEN].into()
    }

    /// Returns true if a `MacAddr` is an all-zero address.
    pub fn is_zero(&self) -> bool {
        *self == Self::zero()
    }

    /// Returns true if the MacAddr is a universally administered addresses (UAA).
    pub fn is_universal(&self) -> bool {
        !self.is_local()
    }

    /// Returns true if the MacAddr is a locally administered addresses (LAA).
    pub fn is_local(&self) -> bool {
        (self.0 & LOCAL_ADDR_BIT) == LOCAL_ADDR_BIT
    }

    /// Returns true if the MacAddr is a unicast address.
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    /// Returns true if the MacAddr is a multicast address.
    pub fn is_multicast(&self) -> bool {
        (self.0 & MULTICAST_ADDR_BIT) == MULTICAST_ADDR_BIT
    }

    /// Returns true if the MacAddr is a broadcast address.
    pub fn is_broadcast(&self) -> bool {
        *self == Self::broadcast()
    }
}

impl From<EtherAddr> for MacAddr {
    fn from(addr: EtherAddr) -> MacAddr {
        MacAddr(addr[0], addr[1], addr[2], addr[3], addr[4], addr[5])
    }
}

impl From<MacAddr> for EtherAddr {
    fn from(addr: MacAddr) -> Self {
        [addr.0, addr.1, addr.2, addr.3, addr.4, addr.5]
    }
}

impl PartialEq<EtherAddr> for MacAddr {
    fn eq(&self, other: &EtherAddr) -> bool {
        *self == MacAddr::from(*other)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0, self.1, self.2, self.3, self.4, self.5
        )
    }
}

#[cfg(feature = "serde")]
impl Serialize for MacAddr {
    /// Serializes the MAC address.
    ///
    /// It serializes either to a string or its binary representation, depending on what the format
    /// prefers.
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&format!("{}", self))
        } else {
            serializer.serialize_bytes(&[self.0, self.1, self.2, self.3, self.4, self.5])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for MacAddr {
    /// Deserializes the MAC address.
    ///
    /// It deserializes it from either a byte array (of size 6) or a string. If the format is
    /// self-descriptive (like JSON or MessagePack), it auto-detects it. If not, it obeys the
    /// human-readable property of the deserializer.
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MacAddrVisitor;
        impl<'de> de::Visitor<'de> for MacAddrVisitor {
            type Value = MacAddr;

            fn visit_str<E: de::Error>(self, value: &str) -> Result<MacAddr, E> {
                value.parse().map_err(|err| E::custom(&format!("{}", err)))
            }

            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<MacAddr, E> {
                if v.len() == 6 {
                    Ok(MacAddr::new(v[0], v[1], v[2], v[3], v[4], v[5]))
                } else {
                    Err(E::invalid_length(v.len(), &self))
                }
            }

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(
                    formatter,
                    "either a string representation of a MAC address or 6-element byte array"
                )
            }
        }

        // Decide what hint to provide to the deserializer based on if it is human readable or not
        if deserializer.is_human_readable() {
            deserializer.deserialize_str(MacAddrVisitor)
        } else {
            deserializer.deserialize_bytes(MacAddrVisitor)
        }
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

/// Represents an error which occurred whilst parsing a MAC address.
#[derive(Copy, Debug, PartialEq, Eq, Clone)]
pub enum ParseMacAddrErr {
    /// The MAC address has too many components, eg. 00:11:22:33:44:55:66.
    TooManyComponents,
    /// The MAC address has too few components, eg. 00:11.
    TooFewComponents,
    /// One of the components contains an invalid value, eg. 00:GG:22:33:44:55.
    InvalidComponent,
}

impl Error for ParseMacAddrErr {}

impl ParseMacAddrErr {
    fn description(&self) -> &str {
        match *self {
            ParseMacAddrErr::TooManyComponents => "Too many components in a MAC address string",
            ParseMacAddrErr::TooFewComponents => "Too few components in a MAC address string",
            ParseMacAddrErr::InvalidComponent => "Invalid component in a MAC address string",
        }
    }
}

impl fmt::Display for ParseMacAddrErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl FromStr for MacAddr {
    type Err = ParseMacAddrErr;
    fn from_str(s: &str) -> Result<MacAddr, ParseMacAddrErr> {
        let mut parts = [0u8; 6];
        let splits = s.split(':');
        let mut i = 0;
        for split in splits {
            if i == 6 {
                return Err(ParseMacAddrErr::TooManyComponents);
            }
            match u8::from_str_radix(split, 16) {
                Ok(b) if split.len() != 0 => parts[i] = b,
                _ => return Err(ParseMacAddrErr::InvalidComponent),
            }
            i += 1;
        }

        if i == 6 {
            Ok(MacAddr(
                parts[0], parts[1], parts[2], parts[3], parts[4], parts[5],
            ))
        } else {
            Err(ParseMacAddrErr::TooFewComponents)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_addr_from_str() {
        assert_eq!("00:00:00:00:00:00".parse(), Ok(MacAddr::zero()));
        assert_eq!("ff:ff:ff:ff:ff:ff".parse(), Ok(MacAddr::broadcast()));
        assert_eq!(
            "12:34:56:78:90:ab".parse(),
            Ok(MacAddr(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB))
        );
        assert_eq!(
            "::::::".parse::<MacAddr>(),
            Err(ParseMacAddrErr::InvalidComponent)
        );
        assert_eq!(
            "0::::::".parse::<MacAddr>(),
            Err(ParseMacAddrErr::InvalidComponent)
        );
        assert_eq!(
            "::::0::".parse::<MacAddr>(),
            Err(ParseMacAddrErr::InvalidComponent)
        );
        assert_eq!(
            "12:34:56:78".parse::<MacAddr>(),
            Err(ParseMacAddrErr::TooFewComponents)
        );
        assert_eq!(
            "12:34:56:78:".parse::<MacAddr>(),
            Err(ParseMacAddrErr::InvalidComponent)
        );
        assert_eq!(
            "12:34:56:78:90".parse::<MacAddr>(),
            Err(ParseMacAddrErr::TooFewComponents)
        );
        assert_eq!(
            "12:34:56:78:90:".parse::<MacAddr>(),
            Err(ParseMacAddrErr::InvalidComponent)
        );
        assert_eq!(
            "12:34:56:78:90:00:00".parse::<MacAddr>(),
            Err(ParseMacAddrErr::TooManyComponents)
        );
        assert_eq!(
            "xx:xx:xx:xx:xx:xx".parse::<MacAddr>(),
            Err(ParseMacAddrErr::InvalidComponent)
        );
    }

    #[test]
    fn str_from_mac_addr() {
        assert_eq!(format!("{}", MacAddr::zero()), "00:00:00:00:00:00");
        assert_eq!(format!("{}", MacAddr::broadcast()), "ff:ff:ff:ff:ff:ff");
        assert_eq!(
            format!("{}", MacAddr(0x12, 0x34, 0x56, 0x78, 0x09, 0xAB)),
            "12:34:56:78:09:ab"
        );
    }

    #[test]
    fn type_of_addr() {
        assert!(MacAddr::zero().is_zero());
        assert!(MacAddr::broadcast().is_broadcast());

        let mac = MacAddr(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB);
        assert!(mac.is_local());
        assert!(mac.is_unicast());

        let mac = MacAddr(0xac, 0x87, 0xa3, 0x07, 0x32, 0xb8);
        assert!(mac.is_universal());
        assert!(mac.is_unicast());
    }

    #[test]
    fn convertion() {
        let mac = MacAddr(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB);
        let addr = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB];

        assert_eq!(mac, MacAddr::from(addr));
        assert_eq!(addr, EtherAddr::from(mac));
        assert!(mac == addr);
    }

    #[cfg(feature = "serde")]
    mod serde {
        extern crate serde_test;
        use self::serde_test::{
            assert_de_tokens, assert_de_tokens_error, assert_tokens, Compact, Configure, Readable,
            Token,
        };
        use super::*;

        #[test]
        fn string() {
            let mac = MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
            assert_tokens(&mac.readable(), &[Token::Str("11:22:33:44:55:66")]);
            assert_de_tokens(&mac.readable(), &[Token::String("11:22:33:44:55:66")]);
            assert_de_tokens(&mac.readable(), &[Token::BorrowedStr("11:22:33:44:55:66")]);
            assert_de_tokens_error::<Readable<MacAddr>>(
                &[Token::Str("not an address")],
                "Invalid component in a MAC address string",
            );
            // It still can detect bytes if provided
            assert_de_tokens(
                &mac.readable(),
                &[Token::Bytes(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66])],
            );
        }

        #[test]
        fn bytes() {
            let mac = MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
            assert_tokens(
                &mac.compact(),
                &[Token::Bytes(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66])],
            );
            assert_de_tokens(
                &mac.compact(),
                &[Token::BorrowedBytes(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66])],
            );
            let err = "invalid length 2, expected either a string representation of a MAC address or 6-element byte array";
            assert_de_tokens_error::<Compact<MacAddr>>(&[Token::Bytes(&[0x11, 0x33])], err);
            let err = "invalid length 7, expected either a string representation of a MAC address or 6-element byte array";
            assert_de_tokens_error::<Compact<MacAddr>>(
                &[Token::Bytes(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77])],
                err,
            );
            // Still can decode string in the compact mode
            assert_de_tokens(&mac.compact(), &[Token::Str("11:22:33:44:55:66")]);
        }
    }
}
