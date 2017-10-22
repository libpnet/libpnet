//! VLAN packet abstraction

#[cfg(feature = "with-syntex")]
include!(concat!(env!("OUT_DIR"), "/vlan.rs"));

#[cfg(not(feature = "with-syntex"))]
include!("vlan.rs.in");
