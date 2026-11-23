// ABOUTME: Shared helpers for the proxy tests: a table resolver, a loopback dial map, echo upstreams and HTTP head readers.
// ABOUTME: The resolver answers with a global-looking address and the dial map sends it to loopback, so the real address checks run.
//! Helpers for `tests/proxy_*.rs`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use claims::assert_ok;
use hamster_ball::policy::{HostName, HostPattern, HostRule, Port};
use hamster_ball::proxy::{DialMap, ProxyConfig, ProxyHandle, Resolver};

/// A public address (example.com's old one) that the table resolver hands out by default.
pub const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));

/// Answers from a table; any other name does not resolve.
pub struct Table(HashMap<String, Vec<IpAddr>>);

impl Table {
    /// Every name in `names` resolves to [`PUBLIC`].
    pub fn of(names: &[&str]) -> Arc<Self> {
        Arc::new(Self(
            names
                .iter()
                .map(|n| ((*n).to_owned(), vec![PUBLIC]))
                .collect(),
        ))
    }

    /// `name` resolves to `addresses`, in that order.
    pub fn answering(name: &str, addresses: &[&str]) -> Arc<Self> {
        let ips = addresses
            .iter()
            .map(|a| assert_ok!(a.parse::<IpAddr>()))
            .collect();
        Arc::new(Self(HashMap::from([(name.to_owned(), ips)])))
    }
}

impl Resolver for Table {
    fn resolve(&self, host: &HostName, port: Port) -> std::io::Result<Vec<SocketAddr>> {
        self.0
            .get(host.as_str())
            .map(|ips| {
                ips.iter()
                    .map(|ip| SocketAddr::new(*ip, port.get()))
                    .collect()
            })
            .ok_or_else(|| std::io::Error::other("no such host"))
    }
}

/// A dial map that sends every address to loopback on the same port.
pub fn to_loopback() -> DialMap {
    Arc::new(|addr| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port()))
}

/// A dial map that sends every address to loopback and records what the proxy chose.
pub fn recording(chosen: &Arc<Mutex<Vec<SocketAddr>>>) -> DialMap {
    let chosen = Arc::clone(chosen);
    Arc::new(move |addr| {
        if let Ok(mut list) = chosen.lock() {
            list.push(addr);
        }
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    })
}

pub fn rules(entries: &[&str]) -> Vec<HostRule> {
    entries
        .iter()
        .map(|e| assert_ok!(HostRule::parse(e)))
        .collect()
}

pub fn patterns(entries: &[&str]) -> Vec<HostPattern> {
    entries
        .iter()
        .map(|e| assert_ok!(HostPattern::parse(e)))
        .collect()
}

/// A config that allows `allow`, resolves `names` to a public address and dials loopback.
pub fn config(allow: &[&str], names: &[&str]) -> ProxyConfig {
    ProxyConfig::new(rules(allow))
        .with_resolver(Table::of(names))
        .with_dial_map(to_loopback())
}

pub fn start(config: ProxyConfig) -> ProxyHandle {
    assert_ok!(ProxyHandle::start(config))
}

/// Entries that name no port, written for `port`; entries that name one are kept.
fn on_port(port: u16, allow: &[&str]) -> Vec<String> {
    allow
        .iter()
        .map(|entry| {
            if entry.contains(':') {
                (*entry).to_owned()
            } else {
                format!("{entry}:{port}")
            }
        })
        .collect()
}

/// Like [`config`], for upstreams that listen on `port` instead of 443.
pub fn config_on(port: u16, allow: &[&str], names: &[&str]) -> ProxyConfig {
    let allow = on_port(port, allow);
    let refs: Vec<&str> = allow.iter().map(String::as_str).collect();
    config(&refs, names)
}

/// Like [`proxy`], for upstreams that listen on `port` instead of 443.
pub fn proxy_on(port: u16, allow: &[&str], names: &[&str]) -> ProxyHandle {
    start(config_on(port, allow, names))
}

/// A proxy that allows `allow` and resolves `names`.
pub fn proxy(allow: &[&str], names: &[&str]) -> ProxyHandle {
    start(config(allow, names))
}

/// An echo server: every byte read is written back; at end of input it writes `bye` and closes.
pub fn echo_upstream() -> u16 {
    let listener = assert_ok!(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
    let port = assert_ok!(listener.local_addr()).port();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            thread::spawn(move || echo(stream));
        }
    });
    port
}

fn echo(mut stream: TcpStream) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stream.write_all(&buf[..n]).is_err() {
                    return;
                }
            }
        }
    }
    let _ = stream.write_all(b"bye");
}

pub fn connect_to(proxy: &ProxyHandle) -> TcpStream {
    let stream = assert_ok!(TcpStream::connect(proxy.addr()));
    assert_ok!(stream.set_read_timeout(Some(Duration::from_secs(20))));
    stream
}

/// Reads a reply head; returns it as text and the bytes read past the blank line.
pub fn read_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(at + 4);
            return (String::from_utf8_lossy(&buf).into_owned(), rest);
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return (String::from_utf8_lossy(&buf).into_owned(), Vec::new()),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

pub fn read_to_end(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    out
}

/// The `Proxy-Authorization` header line (with its line ending) for `proxy`'s token.
pub fn auth_line(proxy: &ProxyHandle) -> String {
    format!(
        "Proxy-Authorization: {}\r\n",
        proxy.token().authorization_value()
    )
}

/// A CONNECT request for `target` with the right credentials.
pub fn connect_request(proxy: &ProxyHandle, target: &str) -> String {
    format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{}\r\n",
        auth_line(proxy)
    )
}

/// Sends an authenticated CONNECT and returns the stream and the reply head.
pub fn tunnel(proxy: &ProxyHandle, target: &str) -> (TcpStream, String) {
    let mut stream = connect_to(proxy);
    assert_ok!(stream.write_all(connect_request(proxy, target).as_bytes()));
    let (head, _) = read_head(&mut stream);
    (stream, head)
}

/// Sends `request` as it is and returns the reply head.
pub fn send_raw(proxy: &ProxyHandle, request: &str) -> String {
    let mut stream = connect_to(proxy);
    assert_ok!(stream.write_all(request.as_bytes()));
    read_head(&mut stream).0
}

pub fn status(head: &str) -> &str {
    head.lines().next().unwrap_or_default()
}

pub fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

/// Keeps every audit event for the test to read.
#[derive(Default)]
pub struct Collect(std::sync::Mutex<Vec<hamster_ball::proxy::AuditEvent>>);

impl Collect {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The events so far.
    pub fn events(&self) -> Vec<hamster_ball::proxy::AuditEvent> {
        self.0.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Waits until at least `count` events have arrived, up to five seconds.
    pub fn wait_for(&self, count: usize) -> Vec<hamster_ball::proxy::AuditEvent> {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while self.events().len() < count && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        self.events()
    }
}

impl hamster_ball::proxy::AuditSink for Collect {
    fn record(&self, event: &hamster_ball::proxy::AuditEvent) {
        if let Ok(mut events) = self.0.lock() {
            events.push(event.clone());
        }
    }
}

/// A resolver that counts its calls and answers like [`Table`].
pub struct Counting {
    pub calls: std::sync::atomic::AtomicUsize,
    pub inner: Arc<Table>,
}

impl Resolver for Counting {
    fn resolve(&self, host: &HostName, port: Port) -> std::io::Result<Vec<SocketAddr>> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.inner.resolve(host, port)
    }
}
