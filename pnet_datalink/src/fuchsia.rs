//! Fuchsia: interface listing only; datalink channels are not implemented.

use std::io;

use crate::{Channel, NetworkInterface};

/// Fuchsia has no backend-specific channel configuration.
#[derive(Clone, Copy, Debug, Default)]
pub struct Config;

impl<'a> From<&'a super::Config> for Config {
    fn from(_: &super::Config) -> Config {
        Config
    }
}

/// Datalink channels are not implemented for Fuchsia.
pub fn channel(_: &NetworkInterface, _: Config) -> io::Result<Channel> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "datalink channels are not implemented for Fuchsia",
    ))
}

/// Get a list of available network interfaces for the current machine.
pub fn interfaces() -> Vec<NetworkInterface> {
    #[path = "unix_interfaces.rs"]
    mod interfaces;
    interfaces::interfaces()
}
