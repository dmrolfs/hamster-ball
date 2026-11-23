// ABOUTME: Port: a TCP port number in 1..=65535, built from the signed integers TOML produces.
// ABOUTME: Raw config ports arrive as i64 so a bad value yields a typed error instead of an untyped serde message.
//! The [`Port`] value type.

use std::fmt;
use std::num::NonZeroU16;

use snafu::{OptionExt, Snafu, ensure};

/// Why an integer is not a valid port.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PortError {
    /// The value is outside 1..=65535.
    #[snafu(display("port {value} is out of range; ports are 1 to 65535"))]
    OutOfRange {
        /// The rejected value.
        value: i64,
    },
    /// The value is below 1024, which an unprivileged process may bind on every interface.
    #[snafu(display(
        "port {value} is privileged; Seatbelt cannot confine a listener to loopback, and any user can bind a port below 1024 on every interface. Use 1024 or above"
    ))]
    Privileged {
        /// The rejected value.
        value: i64,
    },
}

/// A TCP port number from 1 to 65535.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Port(NonZeroU16);

impl Port {
    /// The port number.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0.get()
    }
}

impl From<Port> for u16 {
    fn from(port: Port) -> Self {
        port.get()
    }
}

impl Port {
    /// 443, the port an allowlist entry without one allows.
    pub const HTTPS: Self = Self(match NonZeroU16::new(443) {
        Some(port) => port,
        None => NonZeroU16::MIN,
    });

    /// Parses a port written as one to five ASCII digits (no sign, no `0x`), from 1 to 65535.
    #[must_use]
    pub fn from_decimal(text: &str) -> Option<Self> {
        if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        text.parse::<u16>().ok().and_then(NonZeroU16::new).map(Self)
    }
}

impl TryFrom<i64> for Port {
    type Error = PortError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        u16::try_from(value)
            .ok()
            .and_then(NonZeroU16::new)
            .map(Self)
            .context(OutOfRangeSnafu { value })
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The lowest port a [`BindPort`] may name.
const FIRST_UNPRIVILEGED_PORT: u16 = 1024;

/// A TCP port a server may listen on: 1024 to 65535.
///
/// macOS lets any user bind a port below 1024 on the wildcard address, and Seatbelt's
/// `localhost:<port>` filter matches every local address, so a privileged bind would be a
/// LAN-visible listener on a well-known port (design 7.1, D58).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BindPort(Port);

impl BindPort {
    /// The port number.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0.get()
    }

    /// The same port as a plain [`Port`].
    #[must_use]
    pub fn port(self) -> Port {
        self.0
    }
}

impl From<BindPort> for Port {
    fn from(port: BindPort) -> Self {
        port.0
    }
}

impl TryFrom<i64> for BindPort {
    type Error = PortError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        let port = Port::try_from(value)?;
        ensure!(
            port.get() >= FIRST_UNPRIVILEGED_PORT,
            PrivilegedSnafu { value }
        );
        Ok(Self(port))
    }
}

impl fmt::Display for BindPort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    #[test]
    fn port_accepts_the_bounds() {
        assert_eq!(assert_ok!(Port::try_from(1)).get(), 1);
        assert_eq!(assert_ok!(Port::try_from(65535)).get(), 65535);
        assert_eq!(assert_ok!(Port::try_from(8080)).get(), 8080);
    }

    #[test]
    fn port_converts_into_u16() {
        assert_eq!(u16::from(assert_ok!(Port::try_from(443))), 443);
    }

    #[test]
    fn port_rejects_zero_negative_and_too_large() {
        for bad in [0, -1, i64::MIN, 65536, 100_000, i64::MAX] {
            let err = assert_err!(Port::try_from(bad), "{bad}");
            assert!(matches!(err, PortError::OutOfRange { value } if value == bad));
        }
    }

    #[test]
    fn port_error_names_the_value() {
        assert_eq!(
            assert_err!(Port::try_from(70000)).to_string(),
            "port 70000 is out of range; ports are 1 to 65535"
        );
    }

    #[test]
    fn a_bind_port_accepts_1024_and_above() {
        assert_eq!(assert_ok!(BindPort::try_from(1024)).get(), 1024);
        assert_eq!(assert_ok!(BindPort::try_from(65535)).get(), 65535);
        assert_eq!(assert_ok!(BindPort::try_from(24282)).port().get(), 24282);
    }

    #[test]
    fn a_bind_port_rejects_every_privileged_port() {
        for bad in [1, 22, 80, 443, 1023] {
            let err = assert_err!(BindPort::try_from(bad), "{bad}");
            assert!(
                matches!(err, PortError::Privileged { value } if value == bad),
                "{err}"
            );
        }
    }

    #[test]
    fn a_bind_port_keeps_the_range_errors_of_a_port() {
        for bad in [0, -1, 65536] {
            let err = assert_err!(BindPort::try_from(bad), "{bad}");
            assert!(
                matches!(err, PortError::OutOfRange { value } if value == bad),
                "{err}"
            );
        }
    }

    #[test]
    fn the_privileged_error_says_why_and_what_to_do() {
        assert_eq!(
            assert_err!(BindPort::try_from(80)).to_string(),
            "port 80 is privileged; Seatbelt cannot confine a listener to loopback, and any user can \
             bind a port below 1024 on every interface. Use 1024 or above"
        );
    }

    #[test]
    fn a_bind_port_converts_to_its_port_and_displays_as_a_number() {
        let bind = assert_ok!(BindPort::try_from(8080));
        assert_eq!(Port::from(bind), assert_ok!(Port::try_from(8080)));
        assert_eq!(bind.to_string(), "8080");
    }

    #[test]
    fn ports_order_numerically_and_display_as_numbers() {
        assert!(assert_ok!(Port::try_from(80)) < assert_ok!(Port::try_from(443)));
        assert_eq!(assert_ok!(Port::try_from(443)).to_string(), "443");
    }
}
