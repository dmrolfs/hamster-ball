// ABOUTME: Port: a TCP port number in 1..=65535, built from the signed integers TOML produces.
// ABOUTME: Raw config ports arrive as i64 so a bad value yields a typed error instead of an untyped serde message.
//! The [`Port`] value type.

use std::fmt;
use std::num::NonZeroU16;

use snafu::{OptionExt, Snafu};

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
    fn ports_order_numerically_and_display_as_numbers() {
        assert!(assert_ok!(Port::try_from(80)) < assert_ok!(Port::try_from(443)));
        assert_eq!(assert_ok!(Port::try_from(443)).to_string(), "443");
    }
}
