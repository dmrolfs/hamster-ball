// ABOUTME: The accept loop, per-connection handler and shutdown of the proxy, on a dedicated single-threaded tokio runtime.
// ABOUTME: One task per connection, bounded by a permit count; stopping aborts every task and joins the thread.
//! The proxy server.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener as StdListener};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Builder;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::authority::Authority;
use super::refusal::Refusal;
use super::request::{Request, parse_head};
use super::resolve::{Resolver, SystemResolver};
use crate::policy::HostPattern;

/// The most connections served at once; more are answered `503` and closed.
const DEFAULT_MAX_CONNECTIONS: usize = 512;
/// The most addresses of one host tried before giving up.
const MAX_ADDRESSES_TRIED: usize = 4;
/// How long a refusal reply may take to write before the connection is dropped.
const REPLY_TIMEOUT: Duration = Duration::from_secs(5);
/// How long to wait before accepting again after the system refused one.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
/// The file-descriptor limit asked for at start: each tunnel holds two sockets.
const WANTED_FD_LIMIT: u64 = 8192;

/// How long each step of a connection may take. There is no limit on an established tunnel:
/// a long-lived streaming response must not be cut off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// The client sending its request head.
    pub head: Duration,
    /// Looking up the host's addresses.
    pub resolve: Duration,
    /// Each connection attempt.
    pub connect: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            head: Duration::from_secs(10),
            resolve: Duration::from_secs(10),
            connect: Duration::from_secs(10),
        }
    }
}

/// What the proxy allows and how it behaves.
#[derive(Clone)]
pub struct ProxyConfig {
    allow: Vec<HostPattern>,
    resolver: Arc<dyn Resolver>,
    timeouts: Timeouts,
    max_connections: usize,
}

impl ProxyConfig {
    /// A config that allows `allow` and nothing else, using the system resolver.
    #[must_use]
    pub fn new(allow: Vec<HostPattern>) -> Self {
        Self {
            allow,
            resolver: Arc::new(SystemResolver),
            timeouts: Timeouts::default(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }

    /// Uses `resolver` instead of the system's.
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// Uses `timeouts` instead of the defaults.
    #[must_use]
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Serves at most `max` connections at once (at least one).
    #[must_use]
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max.max(1);
        self
    }
}

impl std::fmt::Debug for ProxyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyConfig")
            .field("allow", &self.allow)
            .field("timeouts", &self.timeouts)
            .field("max_connections", &self.max_connections)
            .finish_non_exhaustive()
    }
}

/// Why the proxy could not start.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ProxyError {
    /// The loopback listener could not be created.
    #[snafu(display("could not listen on 127.0.0.1"))]
    Bind {
        /// The OS error.
        source: io::Error,
    },

    /// The runtime or its thread could not be created.
    #[snafu(display("could not start the proxy thread"))]
    Thread {
        /// The OS error.
        source: io::Error,
    },
}

/// State shared by every connection.
struct Shared {
    allow: Vec<HostPattern>,
    resolver: Arc<dyn Resolver>,
    timeouts: Timeouts,
}

/// A running proxy. Dropping it stops it.
#[derive(Debug)]
pub struct ProxyHandle {
    addr: SocketAddr,
    live: Arc<AtomicUsize>,
    stop: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl ProxyHandle {
    /// Binds `127.0.0.1` on a port the system chooses and starts serving.
    ///
    /// # Errors
    /// See [`ProxyError`].
    pub fn start(config: ProxyConfig) -> Result<Self, ProxyError> {
        raise_fd_limit();
        let listener = StdListener::bind((Ipv4Addr::LOCALHOST, 0)).context(BindSnafu)?;
        listener.set_nonblocking(true).context(BindSnafu)?;
        let addr = listener.local_addr().context(BindSnafu)?;
        let live = Arc::new(AtomicUsize::new(0));
        let (stop, stopped) = oneshot::channel();
        let runtime = Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .context(ThreadSnafu)?;
        let thread_live = Arc::clone(&live);
        let thread = std::thread::Builder::new()
            .name("hb-proxy".to_owned())
            .spawn(move || {
                runtime.block_on(serve(listener, config, thread_live, stopped));
            })
            .context(ThreadSnafu)?;
        Ok(Self {
            addr,
            live,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// The address the proxy listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The port the proxy listens on.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    /// How many connections are open right now.
    #[must_use]
    pub fn live_connections(&self) -> usize {
        self.live.load(Ordering::SeqCst)
    }

    /// Ends every open connection and the listener, and waits for the thread. Does nothing the
    /// second time.
    pub fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Counts an open connection for as long as it lives.
struct LiveGuard(Arc<AtomicUsize>);

impl LiveGuard {
    fn new(counter: &Arc<AtomicUsize>) -> Self {
        counter.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(counter))
    }
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

async fn serve(
    std_listener: StdListener,
    config: ProxyConfig,
    live: Arc<AtomicUsize>,
    mut stopped: oneshot::Receiver<()>,
) {
    let Ok(listener) = TcpListener::from_std(std_listener) else {
        return;
    };
    let shared = Arc::new(Shared {
        allow: config.allow,
        resolver: config.resolver,
        timeouts: config.timeouts,
    });
    let permits = Arc::new(Semaphore::new(config.max_connections));
    let mut tasks: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stopped => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    while tasks.try_join_next().is_some() {}
                    let guard = LiveGuard::new(&live);
                    match Arc::clone(&permits).try_acquire_owned() {
                        Ok(permit) => {
                            tasks.spawn(connection(stream, Arc::clone(&shared), permit, guard));
                        }
                        Err(_) => {
                            tasks.spawn(refuse_busy(stream, guard));
                        }
                    }
                }
                Err(_) => tokio::time::sleep(ACCEPT_BACKOFF).await,
            }
        }
    }
    drop(listener);
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

async fn refuse_busy(mut client: TcpStream, _live: LiveGuard) {
    reply(&mut client, &Refusal::Busy).await;
}

async fn connection(
    mut client: TcpStream,
    shared: Arc<Shared>,
    _permit: OwnedSemaphorePermit,
    _live: LiveGuard,
) {
    let _ = client.set_nodelay(true);
    if let Err(refusal) = serve_connection(&mut client, &shared).await {
        reply(&mut client, &refusal).await;
    }
}

async fn reply(client: &mut TcpStream, refusal: &Refusal) {
    let _ = timeout(REPLY_TIMEOUT, async {
        let _ = client.write_all(&refusal.response()).await;
        let _ = client.shutdown().await;
    })
    .await;
}

/// Serves one connection: read the head, decide, connect, then copy both ways until either ends.
async fn serve_connection(client: &mut TcpStream, shared: &Shared) -> Result<(), Refusal> {
    let (request, leftover) = read_head(client, shared.timeouts.head).await?;
    let (authority, opening) = match &request {
        Request::Connect(authority) => (authority, None),
        Request::Forward { authority, head } => (authority, Some(head)),
    };
    if !shared.allow.iter().any(|p| p.matches(&authority.host)) {
        return Err(Refusal::NotAllowed {
            host: authority.host.clone(),
        });
    }
    let mut upstream = connect(shared, authority).await?;
    match opening {
        None => {
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return Ok(());
            }
        }
        Some(head) => {
            if upstream.write_all(head).await.is_err() {
                return Ok(());
            }
        }
    }
    if !leftover.is_empty() && upstream.write_all(&leftover).await.is_err() {
        return Ok(());
    }
    let _ = copy_bidirectional(client, &mut upstream).await;
    Ok(())
}

/// Reads until the request head is complete; returns it with any bytes read past it.
async fn read_head(client: &mut TcpStream, limit: Duration) -> Result<(Request, Vec<u8>), Refusal> {
    let read = async {
        let mut buf: Vec<u8> = Vec::with_capacity(2048);
        loop {
            if let Some((request, used)) = parse_head(&buf)? {
                return Ok((request, buf.split_off(used)));
            }
            let n = client
                .read_buf(&mut buf)
                .await
                .map_err(|_| super::request::RequestError::Malformed)?;
            if n == 0 {
                return Err(Refusal::from(super::request::RequestError::Malformed));
            }
        }
    };
    timeout(limit, read)
        .await
        .map_err(|_| Refusal::HeadTimeout)?
}

/// Resolves the host and connects to the first address that answers.
async fn connect(shared: &Shared, authority: &Authority) -> Result<TcpStream, Refusal> {
    let resolver = Arc::clone(&shared.resolver);
    let (host, port) = (authority.host.clone(), authority.port);
    let lookup = tokio::task::spawn_blocking(move || resolver.resolve(&host, port));
    let addrs = match timeout(shared.timeouts.resolve, lookup).await {
        Err(_) => {
            return Err(Refusal::TimedOut {
                host: authority.host.clone(),
                port: authority.port,
            });
        }
        Ok(Ok(Ok(addrs))) if !addrs.is_empty() => addrs,
        Ok(_) => {
            return Err(Refusal::Unresolved {
                host: authority.host.clone(),
            });
        }
    };
    let mut timed_out = false;
    for addr in addrs.into_iter().take(MAX_ADDRESSES_TRIED) {
        match timeout(shared.timeouts.connect, TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Ok(Err(_)) => {}
            Err(_) => timed_out = true,
        }
    }
    let (host, port) = (authority.host.clone(), authority.port);
    Err(if timed_out {
        Refusal::TimedOut { host, port }
    } else {
        Refusal::Unreachable { host, port }
    })
}

/// Raises the soft limit on open files, best effort: each tunnel holds two sockets and the
/// default soft limit on macOS is low.
fn raise_fd_limit() {
    use rustix::process::{Resource, getrlimit, setrlimit};
    let mut limit = getrlimit(Resource::Nofile);
    if let Some(wanted) = fd_limit_to_set(limit.current, limit.maximum) {
        limit.current = Some(wanted);
        let _ = setrlimit(Resource::Nofile, limit);
    }
}

/// The soft limit to ask for, or `None` when the current one is already enough.
///
/// `None` for a limit means unlimited.
fn fd_limit_to_set(current: Option<u64>, maximum: Option<u64>) -> Option<u64> {
    let wanted = maximum.map_or(WANTED_FD_LIMIT, |max| max.min(WANTED_FD_LIMIT));
    current
        .is_some_and(|current| current < wanted)
        .then_some(wanted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_low_soft_limit_is_raised_to_the_wanted_value_or_the_hard_limit() {
        assert_eq!(fd_limit_to_set(Some(256), None), Some(WANTED_FD_LIMIT));
        assert_eq!(
            fd_limit_to_set(Some(256), Some(1_000_000)),
            Some(WANTED_FD_LIMIT)
        );
        assert_eq!(fd_limit_to_set(Some(256), Some(4096)), Some(4096));
    }

    #[test]
    fn a_soft_limit_that_is_enough_or_unlimited_is_left_alone() {
        assert_eq!(fd_limit_to_set(Some(WANTED_FD_LIMIT), None), None);
        assert_eq!(fd_limit_to_set(Some(1_048_576), None), None);
        assert_eq!(fd_limit_to_set(None, None), None);
        assert_eq!(fd_limit_to_set(Some(4096), Some(4096)), None);
    }

    #[test]
    fn the_config_debug_output_names_its_allowlist_and_limits_but_not_the_resolver() {
        let config = ProxyConfig::new(Vec::new()).with_max_connections(0);
        let shown = format!("{config:?}");
        assert!(
            shown.contains("allow") && shown.contains("max_connections: 1"),
            "{shown}"
        );
    }
}
