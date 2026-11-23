// ABOUTME: Probes the loopback ports a config lists and says which nobody is listening on, so a stopped service is noticed.
// ABOUTME: A connect from hb (outside the ball) that is closed at once; it sends nothing, but a service may log the connection.
//! `net.loopback_ports` health (design 9.2).
//!
//! The profile lets the agent reach exactly the listed loopback ports. If a service the user
//! meant to have running is not, the agent fails in a way that looks like a sandbox problem, so
//! `hb` checks at start and warns. It never refuses to run: the service may be started later.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

use crate::policy::Port;

/// How long one connection attempt may take. Loopback answers at once or refuses at once.
const PROBE_TIMEOUT: Duration = Duration::from_millis(250);

/// Whether something accepts a connection on `port` on loopback (IPv4 or IPv6).
#[must_use]
pub fn is_listening(port: Port) -> bool {
    [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]
    .into_iter()
    .any(|ip| TcpStream::connect_timeout(&SocketAddr::new(ip, port.get()), PROBE_TIMEOUT).is_ok())
}

/// The ports in `ports` that nothing is listening on, in the order given.
#[must_use]
pub fn closed_ports(ports: &[Port]) -> Vec<Port> {
    ports
        .iter()
        .copied()
        .filter(|port| !is_listening(*port))
        .collect()
}

/// The start-up warning for `closed`, or `None` when every port is open.
#[must_use]
pub fn closed_ports_warning(closed: &[Port]) -> Option<String> {
    if closed.is_empty() {
        return None;
    }
    let list = closed
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    let (noun, verb) = if closed.len() == 1 {
        ("port", "is")
    } else {
        ("ports", "are")
    };
    Some(format!(
        "net.loopback_ports {noun} {list} {verb} not listening; start the service or remove the port"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::net::TcpListener;

    fn port(n: u16) -> Port {
        assert_ok!(Port::try_from(i64::from(n)))
    }

    fn free_port() -> Port {
        let listener = assert_ok!(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
        port(assert_ok!(listener.local_addr()).port())
    }

    #[test]
    fn a_listening_port_is_open_and_a_port_nobody_holds_is_closed() {
        let listener = assert_ok!(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
        let open = port(assert_ok!(listener.local_addr()).port());
        let closed = free_port();
        assert!(is_listening(open));
        assert!(!is_listening(closed));
        assert_eq!(closed_ports(&[open, closed]), [closed]);
    }

    #[test]
    fn a_service_that_listens_on_ipv6_only_counts_as_listening() {
        let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else {
            return;
        };
        assert!(is_listening(port(assert_ok!(listener.local_addr()).port())));
    }

    #[test]
    fn the_closed_ports_keep_the_order_they_were_listed_in() {
        let (a, b, c) = (free_port(), free_port(), free_port());
        assert_eq!(closed_ports(&[c, a, b]), [c, a, b]);
        assert!(closed_ports(&[]).is_empty());
    }

    #[test]
    fn the_warning_names_every_closed_port_and_says_nothing_when_none_is() {
        assert_eq!(closed_ports_warning(&[]), None);
        assert_eq!(
            closed_ports_warning(&[port(5432)]).as_deref(),
            Some(
                "net.loopback_ports port 5432 is not listening; start the service or remove the port"
            )
        );
        assert_eq!(
            closed_ports_warning(&[port(3030), port(5432)]).as_deref(),
            Some(
                "net.loopback_ports ports 3030, 5432 are not listening; start the service or remove the port"
            )
        );
    }
}
