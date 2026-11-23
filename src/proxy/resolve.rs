// ABOUTME: Resolver: turns a host name into socket addresses; the system resolver in production, a table in tests.
// ABOUTME: Synchronous by design: getaddrinfo blocks, so the server runs it on tokio's blocking pool.
//! Name resolution for the proxy.
//!
//! The proxy resolves names itself so the sandbox needs no DNS (design 12). It uses the system
//! resolver, so split-horizon DNS and corporate search domains behave as they do for any other
//! program on the machine (design 12.1).

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};

use crate::policy::{HostName, Port};

/// Looks up the addresses of a host.
///
/// Implementations may block; the proxy calls them from a blocking thread.
pub trait Resolver: Send + Sync + 'static {
    /// The addresses of `host`, each with `port`, in the order they should be tried.
    ///
    /// # Errors
    /// Whatever the lookup reports.
    fn resolve(&self, host: &HostName, port: Port) -> io::Result<Vec<SocketAddr>>;
}

/// The operating system's resolver (`getaddrinfo`).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &HostName, port: Port) -> io::Result<Vec<SocketAddr>> {
        Ok((host.as_str(), port.get()).to_socket_addrs()?.collect())
    }
}
