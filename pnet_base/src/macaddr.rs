use std::fmt;
use std::str::FromStr;

/// A MAC address
#[derive(PartialEq, Eq, Clone, Copy, Hash)]
pub struct MacAddr(pub u8, pub u8, pub u8, pub u8, pub u8, pub u8);

impl MacAddr {
    /// Construct a new MacAddr
    pub fn new(a: u8, b: u8, c: u8, d: u8, e: u8, f: u8) -> MacAddr {
        MacAddr(a, b, c, d, e, f)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,
               "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
               self.0,
               self.1,
               self.2,
               self.3,
               self.4,
               self.5)
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, fmt)
    }
}

// FIXME Is this the right way to do this? Which occurs is an implementation
//       issue rather than actually defined - is it useful to provide these
//       errors, or would it be better to just give ()?
/// Represents an error which occurred whilst parsing a MAC address
#[derive(Copy, Debug, PartialEq, Eq, Clone)]
pub enum ParseMacAddrErr {
    /// The MAC address has too many components, eg. 00:11:22:33:44:55:66
    TooManyComponents,
    /// The MAC address has too few components, eg. 00:11
    TooFewComponents,
    /// One of the components contains an invalid value, eg. 00:GG:22:33:44:55
    InvalidComponent,
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
            Ok(MacAddr(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]))
        } else {
            Err(ParseMacAddrErr::TooFewComponents)
        }
    }
}

#[test]
fn mac_addr_from_str() {
    assert_eq!("00:00:00:00:00:00".parse(), Ok(MacAddr(0, 0, 0, 0, 0, 0)));
    assert_eq!("ff:ff:ff:ff:ff:ff".parse(),
               Ok(MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)));
    assert_eq!("12:34:56:78:90:ab".parse(),
               Ok(MacAddr(0x12, 0x34, 0x56, 0x78, 0x90, 0xAB)));
    assert_eq!("::::::".parse::<MacAddr>(),
               Err(ParseMacAddrErr::InvalidComponent));
    assert_eq!("0::::::".parse::<MacAddr>(),
               Err(ParseMacAddrErr::InvalidComponent));
    assert_eq!("::::0::".parse::<MacAddr>(),
               Err(ParseMacAddrErr::InvalidComponent));
    assert_eq!("12:34:56:78".parse::<MacAddr>(),
               Err(ParseMacAddrErr::TooFewComponents));
    assert_eq!("12:34:56:78:".parse::<MacAddr>(),
               Err(ParseMacAddrErr::InvalidComponent));
    assert_eq!("12:34:56:78:90".parse::<MacAddr>(),
               Err(ParseMacAddrErr::TooFewComponents));
    assert_eq!("12:34:56:78:90:".parse::<MacAddr>(),
               Err(ParseMacAddrErr::InvalidComponent));
    assert_eq!("12:34:56:78:90:00:00".parse::<MacAddr>(),
               Err(ParseMacAddrErr::TooManyComponents));
    assert_eq!("xx:xx:xx:xx:xx:xx".parse::<MacAddr>(),
               Err(ParseMacAddrErr::InvalidComponent));
}

#[test]
fn str_from_mac_addr() {
    assert_eq!(format!("{}", MacAddr(0, 0, 0, 0, 0, 0)),
               "00:00:00:00:00:00");
    assert_eq!(format!("{}", MacAddr(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)),
               "ff:ff:ff:ff:ff:ff");
    assert_eq!(format!("{}", MacAddr(0x12, 0x34, 0x56, 0x78, 0x09, 0xAB)),
               "12:34:56:78:09:ab");
}
