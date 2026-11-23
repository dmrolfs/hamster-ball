// ABOUTME: The proxy core over real loopback sockets: allowlist, CONNECT, plain HTTP, streaming, limits and shutdown.
// ABOUTME: Upstreams are std threads on 127.0.0.1; a table resolver maps test names to them, so nothing leaves the machine.
//! Black-box tests of [`hamster_ball::proxy`] (hb-ghd.3.1).
//!
//! The proxy under test is the real one on a real port. The upstream servers are threads in this
//! test process and a table resolver sends the test host names to them.

#![cfg(target_os = "macos")]

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use claims::assert_ok;
use hamster_ball::policy::{HostName, HostPattern, Port};
use hamster_ball::proxy::{ProxyConfig, ProxyHandle, Resolver, Timeouts};
use pretty_assertions::assert_eq;

const LOCAL: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Resolves the names in its table to loopback and fails every other name.
struct Table(HashMap<String, IpAddr>);

impl Table {
    fn of(names: &[&str]) -> Arc<Self> {
        Arc::new(Self(
            names.iter().map(|n| ((*n).to_owned(), LOCAL)).collect(),
        ))
    }
}

impl Resolver for Table {
    fn resolve(&self, host: &HostName, port: Port) -> std::io::Result<Vec<SocketAddr>> {
        self.0
            .get(host.as_str())
            .map(|ip| vec![SocketAddr::new(*ip, port.get())])
            .ok_or_else(|| std::io::Error::other("no such host"))
    }
}

fn patterns(entries: &[&str]) -> Vec<HostPattern> {
    entries
        .iter()
        .map(|e| assert_ok!(HostPattern::parse(e)))
        .collect()
}

/// A proxy that allows `allow` and resolves `names` to loopback.
fn proxy(allow: &[&str], names: &[&str]) -> ProxyHandle {
    start(ProxyConfig::new(patterns(allow)).with_resolver(Table::of(names)))
}

fn start(config: ProxyConfig) -> ProxyHandle {
    assert_ok!(ProxyHandle::start(config))
}

/// An echo server: every byte read is written back; at end of input it writes `bye` and closes.
fn echo_upstream() -> u16 {
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

fn connect_to(proxy: &ProxyHandle) -> TcpStream {
    let stream = assert_ok!(TcpStream::connect(proxy.addr()));
    assert_ok!(stream.set_read_timeout(Some(Duration::from_secs(20))));
    stream
}

/// Reads a reply head; returns it as text and the bytes read past the blank line.
fn read_head(stream: &mut TcpStream) -> (String, Vec<u8>) {
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

fn read_to_end(stream: &mut TcpStream) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = stream.read_to_end(&mut out);
    out
}

/// Sends a CONNECT and returns the stream and the reply head.
fn tunnel(proxy: &ProxyHandle, target: &str) -> (TcpStream, String) {
    let mut stream = connect_to(proxy);
    assert_ok!(
        stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
    );
    let (head, _) = read_head(&mut stream);
    (stream, head)
}

fn status(head: &str) -> &str {
    head.lines().next().unwrap_or_default()
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (n, v) = l.split_once(':')?;
        n.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

// ====================================================================================
// CONNECT and the allowlist
// ====================================================================================

#[test]
fn a_connect_to_an_allowed_host_becomes_a_tunnel_that_carries_bytes_both_ways() {
    let upstream = echo_upstream();
    let proxy = proxy(&["allowed.test"], &["allowed.test"]);
    let (mut stream, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    assert_ok!(stream.write_all(b"hello"));
    let mut got = [0u8; 5];
    assert_ok!(stream.read_exact(&mut got));
    assert_eq!(&got, b"hello");
}

#[test]
fn a_host_that_is_not_allowed_gets_a_403_that_says_which_host_and_why() {
    let proxy = proxy(&["allowed.test"], &["allowed.test", "other.test"]);
    let (_, head) = tunnel(&proxy, "other.test:443");
    assert!(status(&head).starts_with("HTTP/1.1 403"), "{head}");
    assert_eq!(header(&head, "X-Hb-Refusal"), Some("not_allowed"));
    let mut stream = connect_to(&proxy);
    assert_ok!(stream.write_all(b"CONNECT other.test:443 HTTP/1.1\r\n\r\n"));
    let reply = String::from_utf8_lossy(&read_to_end(&mut stream)).into_owned();
    assert!(
        reply.contains("other.test is not on the allowlist"),
        "{reply}"
    );
}

#[test]
fn the_allowlist_is_exact_or_wildcard_case_blind_and_label_safe() {
    let upstream = echo_upstream();
    let names = [
        "api.kiro.test",
        "a.b.kiro.test",
        "kiro.test",
        "evil-kiro.test",
        "kiro.test.evil.test",
        "exact.test",
    ];
    let proxy = proxy(&["*.kiro.test", "exact.test"], &names);
    let reaches = |target: &str| {
        let (_, head) = tunnel(&proxy, &format!("{target}:{upstream}"));
        status(&head).starts_with("HTTP/1.1 200")
    };
    for allowed in [
        "api.kiro.test",
        "API.Kiro.TEST",
        "a.b.kiro.test",
        "api.kiro.test.",
        "EXACT.test",
    ] {
        assert!(reaches(allowed), "{allowed} should be allowed");
    }
    for denied in [
        "kiro.test",
        "evil-kiro.test",
        "kiro.test.evil.test",
        "xexact.test",
    ] {
        assert!(!reaches(denied), "{denied} should be refused");
    }
}

#[test]
fn address_literals_are_refused_even_when_the_allowlist_is_not_consulted() {
    let proxy = proxy(&["allowed.test"], &["allowed.test"]);
    for target in [
        "127.0.0.1:443",
        "[::1]:443",
        "169.254.169.254:80",
        "2130706433:443",
    ] {
        let (_, head) = tunnel(&proxy, target);
        let code = header(&head, "X-Hb-Refusal");
        assert!(
            status(&head).starts_with("HTTP/1.1 403") || status(&head).starts_with("HTTP/1.1 400"),
            "{target}: {head}"
        );
        assert!(
            code == Some("ip_literal") || code == Some("bad_target"),
            "{target}: {head}"
        );
    }
}

#[test]
fn a_name_that_does_not_resolve_is_a_502_and_one_that_refuses_connections_is_a_502() {
    let closed = {
        let l = assert_ok!(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
        assert_ok!(l.local_addr()).port()
    };
    let proxy = proxy(&["gone.test", "closed.test"], &["closed.test"]);
    let (_, head) = tunnel(&proxy, "gone.test:443");
    assert!(status(&head).starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(header(&head, "X-Hb-Refusal"), Some("unresolved"));
    let (_, head) = tunnel(&proxy, &format!("closed.test:{closed}"));
    assert!(status(&head).starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(header(&head, "X-Hb-Refusal"), Some("unreachable"));
}

#[test]
fn an_empty_answer_from_the_resolver_is_unresolved_and_the_port_is_the_one_listened_on() {
    struct Empty;
    impl Resolver for Empty {
        fn resolve(&self, _: &HostName, _: Port) -> std::io::Result<Vec<SocketAddr>> {
            Ok(Vec::new())
        }
    }
    let proxy = start(ProxyConfig::new(patterns(&["allowed.test"])).with_resolver(Arc::new(Empty)));
    assert_eq!(proxy.port(), proxy.addr().port());
    assert_ne!(proxy.port(), 0);
    let (_, head) = tunnel(&proxy, "allowed.test:443");
    assert!(status(&head).starts_with("HTTP/1.1 502"), "{head}");
    assert_eq!(header(&head, "X-Hb-Refusal"), Some("unresolved"));
}

#[test]
fn bytes_sent_right_after_the_connect_head_reach_the_upstream() {
    let upstream = echo_upstream();
    let proxy = proxy(&["allowed.test"], &["allowed.test"]);
    let mut stream = connect_to(&proxy);
    let target = format!("allowed.test:{upstream}");
    assert_ok!(stream.write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\nearly").as_bytes()));
    let (head, mut rest) = read_head(&mut stream);
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    while rest.len() < 5 {
        let mut chunk = [0u8; 16];
        let n = assert_ok!(stream.read(&mut chunk));
        rest.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(&rest[..5], b"early");
}

#[test]
fn a_half_close_from_the_client_still_lets_the_upstream_finish_its_answer() {
    let upstream = echo_upstream();
    let proxy = proxy(&["allowed.test"], &["allowed.test"]);
    let (mut stream, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    assert_ok!(stream.write_all(b"ping"));
    assert_ok!(stream.shutdown(Shutdown::Write));
    // The echo server answers "ping", sees the end of input and adds "bye" before closing.
    assert_eq!(read_to_end(&mut stream), b"pingbye");
}

#[test]
fn a_client_that_hangs_up_ends_the_upstream_connection_too() {
    let listener = assert_ok!(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
    let port = assert_ok!(listener.local_addr()).port();
    let ended = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&ended);
    thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 8];
            while matches!(s.read(&mut buf), Ok(n) if n > 0) {}
            seen.store(true, Ordering::SeqCst);
        }
    });
    let proxy = proxy(&["allowed.test"], &["allowed.test"]);
    let (stream, head) = tunnel(&proxy, &format!("allowed.test:{port}"));
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    drop(stream);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ended.load(Ordering::SeqCst) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        ended.load(Ordering::SeqCst),
        "the upstream never saw the end of the tunnel"
    );
}

// ====================================================================================
// Plain HTTP
// ====================================================================================

/// A one-shot HTTP upstream: records the request it receives (head plus `body_len` bytes) and
/// answers `200` with `body`, then closes.
fn http_upstream(body_len: usize, body: &'static str) -> (u16, thread::JoinHandle<Vec<u8>>) {
    let listener = assert_ok!(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
    let port = assert_ok!(listener.local_addr()).port();
    let handle = thread::spawn(move || {
        let (mut s, _) = assert_ok!(listener.accept());
        assert_ok!(s.set_read_timeout(Some(Duration::from_secs(10))));
        let mut got = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                if got.len() >= at + 4 + body_len {
                    break;
                }
            }
            match s.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&chunk[..n]),
            }
        }
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = s.write_all(reply.as_bytes());
        got
    });
    (port, handle)
}

#[test]
fn a_plain_get_is_forwarded_in_origin_form_without_the_proxys_own_headers() {
    let (port, upstream) = http_upstream(0, "page");
    let proxy = proxy(&["allowed.test"], &["allowed.test"]);
    let mut stream = connect_to(&proxy);
    let request = format!(
        "GET http://allowed.test:{port}/a/b?q=1 HTTP/1.1\r\nHost: evil.test\r\nProxy-Authorization: Basic eDp5\r\nProxy-Connection: keep-alive\r\nAccept: */*\r\n\r\n"
    );
    assert_ok!(stream.write_all(request.as_bytes()));
    let reply = String::from_utf8_lossy(&read_to_end(&mut stream)).into_owned();
    assert!(reply.starts_with("HTTP/1.1 200 OK"), "{reply}");
    assert!(reply.ends_with("page"), "{reply}");
    let received = String::from_utf8_lossy(&assert_ok!(upstream.join())).into_owned();
    assert_eq!(
        received,
        format!(
            "GET /a/b?q=1 HTTP/1.1\r\nHost: allowed.test:{port}\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        )
    );
}

#[test]
fn a_post_body_sent_with_or_after_the_head_reaches_the_upstream_whole() {
    for split in [false, true] {
        let (port, upstream) = http_upstream(5, "ok");
        let proxy = proxy(&["allowed.test"], &["allowed.test"]);
        let mut stream = connect_to(&proxy);
        let head =
            format!("POST http://allowed.test:{port}/submit HTTP/1.1\r\nContent-Length: 5\r\n\r\n");
        if split {
            assert_ok!(stream.write_all(head.as_bytes()));
            thread::sleep(Duration::from_millis(100));
            assert_ok!(stream.write_all(b"hello"));
        } else {
            assert_ok!(stream.write_all(format!("{head}hello").as_bytes()));
        }
        let reply = String::from_utf8_lossy(&read_to_end(&mut stream)).into_owned();
        assert!(reply.ends_with("ok"), "split={split}: {reply}");
        let received = assert_ok!(upstream.join());
        assert!(received.ends_with(b"\r\n\r\nhello"), "split={split}");
    }
}

#[test]
fn a_plain_request_to_a_host_that_is_not_allowed_is_refused_before_any_connection() {
    let (port, upstream) = http_upstream(0, "secret");
    let proxy = proxy(&["allowed.test"], &["allowed.test", "other.test"]);
    let mut stream = connect_to(&proxy);
    assert_ok!(
        stream.write_all(format!("GET http://other.test:{port}/ HTTP/1.1\r\n\r\n").as_bytes())
    );
    let reply = String::from_utf8_lossy(&read_to_end(&mut stream)).into_owned();
    assert!(reply.starts_with("HTTP/1.1 403"), "{reply}");
    assert!(!reply.contains("secret"));
    drop(upstream);
}

// ====================================================================================
// Malformed and hostile requests
// ====================================================================================

fn refusal_for(proxy: &ProxyHandle, bytes: &[u8]) -> (String, Option<String>) {
    let mut stream = connect_to(proxy);
    assert_ok!(stream.write_all(bytes));
    let (head, _) = read_head(&mut stream);
    let code = header(&head, "X-Hb-Refusal").map(str::to_owned);
    (status(&head).to_owned(), code)
}

#[test]
fn requests_that_are_not_proxy_requests_get_a_400_with_a_code() {
    let proxy = proxy(&["allowed.test"], &["allowed.test"]);
    let cases: [(&[u8], &str, &str); 4] = [
        (
            b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n",
            "400",
            "not_a_proxy_request",
        ),
        (
            b"GET https://allowed.test/ HTTP/1.1\r\n\r\n",
            "400",
            "unsupported_scheme",
        ),
        (
            b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03 \r\n\r\n",
            "400",
            "malformed",
        ),
        (
            b"CONNECT allowed.test HTTP/1.1\r\n\r\n",
            "400",
            "bad_target",
        ),
    ];
    for (bytes, status, code) in cases {
        let (line, got) = refusal_for(&proxy, bytes);
        assert!(line.contains(status), "{bytes:?}: {line}");
        assert_eq!(got.as_deref(), Some(code), "{bytes:?}");
    }
}

#[test]
fn an_oversized_head_is_a_431_and_a_slow_one_is_a_408() {
    let config = ProxyConfig::new(patterns(&["allowed.test"]))
        .with_resolver(Table::of(&["allowed.test"]))
        .with_timeouts(Timeouts {
            head: Duration::from_millis(300),
            ..Timeouts::default()
        });
    let proxy = start(config);
    let mut big = b"GET http://allowed.test/ HTTP/1.1\r\nX: ".to_vec();
    big.resize(20_000, b'a');
    let (line, code) = refusal_for(&proxy, &big);
    assert!(line.contains("431"), "{line}");
    assert_eq!(code.as_deref(), Some("too_large"));
    // A client that sends half a head and then waits.
    let (line, code) = refusal_for(&proxy, b"CONNECT allowed.test:44");
    assert!(line.contains("408"), "{line}");
    assert_eq!(code.as_deref(), Some("head_timeout"));
}

// ====================================================================================
// Limits, concurrency and shutdown
// ====================================================================================

#[test]
fn two_hundred_tunnels_at_once_all_carry_their_own_bytes() {
    let upstream = echo_upstream();
    let proxy = proxy(&["allowed.test"], &["allowed.test"]);
    let addr = proxy.addr();
    let workers: Vec<_> = (0..200u32)
        .map(|i| {
            thread::spawn(move || {
                let mut s = assert_ok!(TcpStream::connect(addr));
                assert_ok!(s.set_read_timeout(Some(Duration::from_secs(30))));
                let target = format!("allowed.test:{upstream}");
                assert_ok!(s.write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes()));
                let (head, _) = read_head(&mut s);
                assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
                let payload: Vec<u8> = (0..1024u32).map(|n| (n + i) as u8).collect();
                assert_ok!(s.write_all(&payload));
                let mut back = vec![0u8; payload.len()];
                assert_ok!(s.read_exact(&mut back));
                assert_eq!(back, payload);
            })
        })
        .collect();
    for worker in workers {
        assert_ok!(worker.join());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while proxy.live_connections() != 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(proxy.live_connections(), 0);
}

#[test]
fn connections_beyond_the_limit_get_a_503_and_a_closed_slot_is_reused() {
    let upstream = echo_upstream();
    let config = ProxyConfig::new(patterns(&["allowed.test"]))
        .with_resolver(Table::of(&["allowed.test"]))
        .with_max_connections(2);
    let proxy = start(config);
    let target = format!("allowed.test:{upstream}");
    let (a, ha) = tunnel(&proxy, &target);
    let (_b, hb) = tunnel(&proxy, &target);
    assert!(status(&ha).starts_with("HTTP/1.1 200") && status(&hb).starts_with("HTTP/1.1 200"));
    let (_c, hc) = tunnel(&proxy, &target);
    assert!(status(&hc).starts_with("HTTP/1.1 503"), "{hc}");
    assert_eq!(header(&hc, "X-Hb-Refusal"), Some("busy"));
    drop(a);
    thread::sleep(Duration::from_millis(300));
    let (_d, hd) = tunnel(&proxy, &target);
    assert!(status(&hd).starts_with("HTTP/1.1 200"), "{hd}");
}

#[test]
fn stopping_ends_every_open_tunnel_leaves_no_task_behind_and_closes_the_port() {
    let upstream = echo_upstream();
    let mut proxy = proxy(&["allowed.test"], &["allowed.test"]);
    let addr = proxy.addr();
    let target = format!("allowed.test:{upstream}");
    let mut open: Vec<TcpStream> = (0..50)
        .map(|_| {
            let (s, head) = tunnel(&proxy, &target);
            assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
            s
        })
        .collect();
    assert_eq!(proxy.live_connections(), 50);
    let started = Instant::now();
    proxy.stop();
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "stop took {:?}",
        started.elapsed()
    );
    assert_eq!(proxy.live_connections(), 0);
    for stream in &mut open {
        let mut byte = [0u8; 1];
        assert!(
            matches!(stream.read(&mut byte), Ok(0) | Err(_)),
            "a tunnel survived stop"
        );
    }
    assert!(TcpStream::connect(addr).is_err(), "the port is still open");
    proxy.stop();
}

#[test]
fn dropping_the_handle_stops_the_proxy() {
    let addr = {
        let proxy = proxy(&["allowed.test"], &["allowed.test"]);
        proxy.addr()
    };
    assert!(TcpStream::connect(addr).is_err());
}

// ====================================================================================
// Streaming
// ====================================================================================

/// An upstream that reads until end of input and answers with the number of bytes it saw.
fn counting_upstream() -> u16 {
    let listener = assert_ok!(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
    let port = assert_ok!(listener.local_addr()).port();
    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            thread::spawn(move || {
                let total = Arc::new(AtomicU64::new(0));
                let mut buf = vec![0u8; 64 * 1024];
                while let Ok(n) = s.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    total.fetch_add(n as u64, Ordering::Relaxed);
                }
                let _ = s.write_all(total.load(Ordering::Relaxed).to_string().as_bytes());
            });
        }
    });
    port
}

/// This process's resident memory in bytes, as `ps` reports it.
fn rss_bytes() -> u64 {
    let out = assert_ok!(
        std::process::Command::new("/bin/ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
    );
    let kib: u64 = String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .unwrap_or(0);
    kib * 1024
}

/// Samples [`rss_bytes`] until told to stop and returns the largest value seen.
fn watch_memory() -> (Arc<AtomicBool>, thread::JoinHandle<u64>) {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        let mut peak = rss_bytes();
        while !flag.load(Ordering::SeqCst) {
            peak = peak.max(rss_bytes());
            thread::sleep(Duration::from_millis(50));
        }
        peak.max(rss_bytes())
    });
    (stop, handle)
}

#[test]
fn a_gibibyte_streams_through_a_tunnel_in_bounded_memory() {
    const TOTAL: u64 = 1 << 30;
    let upstream = counting_upstream();
    let proxy = proxy(&["allowed.test"], &["allowed.test"]);
    let (mut stream, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    let before = rss_bytes();
    let (stop_watching, watcher) = watch_memory();
    let mut writer = assert_ok!(stream.try_clone());
    let sender = thread::spawn(move || {
        let chunk = vec![0xA5u8; 256 * 1024];
        let mut sent = 0u64;
        while sent < TOTAL {
            assert_ok!(writer.write_all(&chunk));
            sent += chunk.len() as u64;
        }
        assert_ok!(writer.shutdown(Shutdown::Write));
    });
    let answer = read_to_end(&mut stream);
    assert_ok!(sender.join());
    assert_eq!(String::from_utf8_lossy(&answer), TOTAL.to_string());
    stop_watching.store(true, Ordering::SeqCst);
    let grown = assert_ok!(watcher.join()).saturating_sub(before);
    assert!(
        grown < 64 * 1024 * 1024,
        "peak memory grew by {} MiB while streaming a GiB",
        grown / (1024 * 1024)
    );
}
