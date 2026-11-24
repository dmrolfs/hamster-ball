// ABOUTME: The proxy's defences over real loopback sockets: credentials, port rules, address classes and the audit trail.
// ABOUTME: A table resolver answers with the addresses under test and a recording dial map shows which one the proxy chose.
//! Black-box tests of the hardening in [`hamster_ball::proxy`] (hb-ghd.3.2).

#![cfg(target_os = "macos")]

mod common;

use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use claims::assert_ok;
use common::proxy::{
    Collect, Counting, PUBLIC, Table, auth_line, config, config_on, connect_request, connect_to,
    echo_upstream, header, patterns, read_head, read_to_end, recording, rules, send_raw, start,
    status, tunnel,
};
use hamster_ball::policy::{HostName, Port};
use hamster_ball::proxy::{Decision, ProxyConfig, ProxyHandle, Resolver};
use pretty_assertions::assert_eq;

fn code(head: &str) -> Option<&str> {
    header(head, "X-Hb-Refusal")
}

// ====================================================================================
// Credentials
// ====================================================================================

#[test]
fn a_request_without_credentials_gets_a_407_with_a_basic_challenge_for_connect_and_plain_http() {
    let proxy = start(config(&["allowed.test"], &["allowed.test"]));
    for request in [
        "CONNECT allowed.test:443 HTTP/1.1\r\n\r\n",
        "GET http://allowed.test/ HTTP/1.1\r\n\r\n",
    ] {
        let head = send_raw(&proxy, request);
        assert!(status(&head).starts_with("HTTP/1.1 407"), "{head}");
        assert_eq!(
            header(&head, "Proxy-Authenticate"),
            Some("Basic realm=\"hb\"")
        );
        assert_eq!(code(&head), Some("proxy_auth_required"));
    }
}

#[test]
fn wrong_credentials_in_any_form_get_a_407() {
    let proxy = start(config(&["allowed.test"], &["allowed.test"]));
    let other = start(config(&["allowed.test"], &["allowed.test"]));
    let own = proxy.token().authorization_value();
    let credentials = own.strip_prefix("Basic ").unwrap_or_default().to_owned();
    let wrong: Vec<String> = vec![
        other.token().authorization_value(),
        format!("Bearer {credentials}"),
        credentials.clone(),
        format!("Basic {}x", credentials),
        "Basic".to_owned(),
        "Basic aGI6".to_owned(),
    ];
    for header_value in wrong {
        let request = format!(
            "CONNECT allowed.test:443 HTTP/1.1\r\nProxy-Authorization: {header_value}\r\n\r\n"
        );
        let head = send_raw(&proxy, &request);
        assert!(
            status(&head).starts_with("HTTP/1.1 407"),
            "{header_value}: {head}"
        );
    }
    // Two credential headers are ambiguous, even when one of them is right.
    let request = format!(
        "CONNECT allowed.test:443 HTTP/1.1\r\n{0}{0}\r\n",
        auth_line(&proxy)
    );
    let head = send_raw(&proxy, &request);
    assert!(status(&head).starts_with("HTTP/1.1 407"), "{head}");
}

#[test]
fn the_right_credentials_are_accepted_whatever_the_case_of_the_scheme() {
    let upstream = echo_upstream();
    let proxy = start(config_on(upstream, &["allowed.test"], &["allowed.test"]));
    let credentials = proxy
        .token()
        .authorization_value()
        .strip_prefix("Basic ")
        .unwrap_or_default()
        .to_owned();
    for scheme in ["Basic", "basic", "BASIC"] {
        let request = format!(
            "CONNECT allowed.test:{upstream} HTTP/1.1\r\nProxy-Authorization: {scheme}  {credentials}\r\n\r\n"
        );
        let head = send_raw(&proxy, &request);
        assert!(
            status(&head).starts_with("HTTP/1.1 200"),
            "{scheme}: {head}"
        );
    }
}

#[test]
fn authentication_comes_before_the_allowlist_and_before_any_lookup() {
    let resolver = Arc::new(Counting {
        calls: 0.into(),
        inner: Table::of(&["allowed.test"]),
    });
    let proxy = start(
        ProxyConfig::new(rules(&["allowed.test"]))
            .with_resolver(Arc::clone(&resolver) as Arc<dyn Resolver>),
    );
    // Unlisted host and listed host look the same without credentials: a 407, no lookup.
    for host in ["allowed.test", "unlisted.test"] {
        let head = send_raw(&proxy, &format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n"));
        assert!(status(&head).starts_with("HTTP/1.1 407"), "{host}: {head}");
    }
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    // With credentials the unlisted host is a 403.
    let (_, head) = tunnel(&proxy, "unlisted.test:443");
    assert!(status(&head).starts_with("HTTP/1.1 403"), "{head}");
}

#[test]
fn the_proxy_url_has_the_documented_shape_and_nothing_prints_the_token() {
    let proxy = start(config(&["allowed.test"], &["allowed.test"]));
    let token = proxy.token().expose().to_owned();
    assert_eq!(
        proxy.url().expose(),
        format!("http://hb:{token}@127.0.0.1:{}", proxy.port())
    );
    for shown in [
        format!("{proxy:?}"),
        format!("{:?}", proxy.url()),
        format!("{:?}", proxy.token()),
    ] {
        assert!(!shown.contains(&token), "{shown}");
    }
    assert_ne!(token, start(config(&[], &[])).token().expose());
}

// ====================================================================================
// Port rules
// ====================================================================================

#[test]
fn only_the_listed_ports_are_reachable_and_the_refusal_says_what_to_write() {
    let upstream = echo_upstream();
    let allowed = format!("allowed.test:{upstream}");
    let proxy = start(config(
        &["allowed.test", &allowed],
        &["allowed.test", "other.test"],
    ));
    // The port the rule names works, the default 443 reaches the (closed) port 443 and is not refused by policy.
    let (_, head) = tunnel(&proxy, &allowed);
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    let (_, head) = tunnel(&proxy, "allowed.test:443");
    assert_ne!(code(&head), Some("port_not_allowed"), "{head}");
    assert_ne!(code(&head), Some("not_allowed"), "{head}");
    // Any other port on a listed host is a port refusal that names the rule to add.
    let (_, head) = tunnel(&proxy, "allowed.test:9999");
    assert!(status(&head).starts_with("HTTP/1.1 403"), "{head}");
    assert_eq!(code(&head), Some("port_not_allowed"));
    let mut stream = connect_to(&proxy);
    assert_ok!(stream.write_all(connect_request(&proxy, "allowed.test:9999").as_bytes()));
    let reply = String::from_utf8_lossy(&read_to_end(&mut stream)).into_owned();
    assert!(
        reply.contains("add \"allowed.test:9999\" to net.allow"),
        "{reply}"
    );
    // An unlisted host is a host refusal whatever the port.
    let (_, head) = tunnel(&proxy, &format!("other.test:{upstream}"));
    assert_eq!(code(&head), Some("not_allowed"));
}

#[test]
fn a_wildcard_rule_carries_its_port_and_443_is_not_implied_by_another_port() {
    let upstream = echo_upstream();
    let rule = format!("*.corp.test:{upstream}");
    let proxy = start(config(&[&rule], &["a.corp.test"]));
    let (_, head) = tunnel(&proxy, &format!("a.corp.test:{upstream}"));
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    let (_, head) = tunnel(&proxy, "a.corp.test:443");
    assert_eq!(code(&head), Some("port_not_allowed"));
}

// ====================================================================================
// Address classes
// ====================================================================================

/// A proxy whose only host resolves to `addresses`, with a record of what it dialled.
fn rebinding(
    addresses: &[&str],
    internal: &[&str],
) -> (ProxyHandle, Arc<Mutex<Vec<SocketAddr>>>, u16) {
    let upstream = echo_upstream();
    let chosen = Arc::new(Mutex::new(Vec::new()));
    let config = config_on(upstream, &["allowed.test"], &[])
        .with_resolver(Table::answering("allowed.test", addresses))
        .with_dial_map(recording(&chosen))
        .with_internal_hosts(patterns(internal));
    (start(config), chosen, upstream)
}

fn dialled(chosen: &Arc<Mutex<Vec<SocketAddr>>>) -> Vec<SocketAddr> {
    chosen.lock().map(|c| c.clone()).unwrap_or_default()
}

#[test]
fn a_name_that_resolves_to_this_machine_or_a_reserved_range_is_refused_and_never_dialled() {
    for address in [
        "127.0.0.1",
        "::1",
        "::ffff:127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "192.0.0.170",
        "64:ff9b::7f00:1",
        "2002:7f00:1::1",
        "fe80::1",
    ] {
        let (proxy, chosen, upstream) = rebinding(&[address], &[]);
        let (_, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
        assert!(
            status(&head).starts_with("HTTP/1.1 403"),
            "{address}: {head}"
        );
        assert_eq!(code(&head), Some("address_refused"), "{address}");
        assert!(dialled(&chosen).is_empty(), "{address} was dialled");
    }
}

#[test]
fn private_and_tunnel_addresses_are_refused_unless_the_host_is_internal_and_the_refusal_says_how_to_fix_it()
 {
    for address in [
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.1",
        "100.64.1.3",
        "198.18.0.1",
        "fd00::1",
        "::ffff:10.1.2.3",
        "64:ff9b::a00:1",
    ] {
        let (proxy, chosen, upstream) = rebinding(&[address], &[]);
        let target = format!("allowed.test:{upstream}");
        let mut stream = connect_to(&proxy);
        assert_ok!(stream.write_all(connect_request(&proxy, &target).as_bytes()));
        let reply = String::from_utf8_lossy(&read_to_end(&mut stream)).into_owned();
        assert!(reply.starts_with("HTTP/1.1 403"), "{address}: {reply}");
        assert!(
            reply.contains("X-Hb-Refusal: internal_address"),
            "{address}: {reply}"
        );
        assert!(
            reply.contains("add \"allowed.test\" to net.internal_hosts in your own config"),
            "{address}: {reply}"
        );
        assert!(dialled(&chosen).is_empty(), "{address} was dialled");

        // The same host, once listed, may use it.
        let (proxy, chosen, upstream) = rebinding(&[address], &["allowed.test"]);
        let (_, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
        assert!(
            status(&head).starts_with("HTTP/1.1 200"),
            "{address}: {head}"
        );
        let dialled = dialled(&chosen);
        assert_eq!(dialled.len(), 1, "{address}");
        assert_eq!(
            dialled[0].ip(),
            assert_ok!(address.parse::<std::net::IpAddr>())
        );
    }
}

#[test]
fn listing_a_host_as_internal_never_opens_loopback_or_link_local() {
    for address in ["127.0.0.1", "169.254.169.254", "::1", "fe80::1"] {
        let (proxy, chosen, upstream) = rebinding(&[address], &["allowed.test"]);
        let (_, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
        assert_eq!(code(&head), Some("address_refused"), "{address}: {head}");
        assert!(dialled(&chosen).is_empty());
    }
}

#[test]
fn the_internal_list_is_per_host_and_a_wildcard_covers_subdomains_only() {
    let upstream = echo_upstream();
    for (internal, name, ok) in [
        (&["other.test"][..], "allowed.test", false),
        (&["*.corp.test"][..], "corp.test", false),
        (&["*.corp.test"][..], "git.corp.test", true),
        (&["git.corp.test"][..], "git.corp.test", true),
    ] {
        let chosen = Arc::new(Mutex::new(Vec::new()));
        let proxy = start(
            config_on(upstream, &["allowed.test", "corp.test", "*.corp.test"], &[])
                .with_resolver(Table::answering(name, &["10.1.2.3"]))
                .with_dial_map(recording(&chosen))
                .with_internal_hosts(patterns(internal)),
        );
        let (_, head) = tunnel(&proxy, &format!("{name}:{upstream}"));
        let served = status(&head).starts_with("HTTP/1.1 200");
        assert_eq!(served, ok, "{internal:?} {name}: {head}");
    }
}

#[test]
fn a_mixed_answer_is_filtered_and_the_connection_goes_to_the_one_address_that_is_allowed() {
    let (proxy, chosen, upstream) = rebinding(&["127.0.0.1", "10.0.0.5", "93.184.216.34"], &[]);
    let (_, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(dialled(&chosen), [SocketAddr::new(PUBLIC, upstream)]);
}

#[test]
fn a_nat64_address_that_carries_a_public_ipv4_address_is_allowed() {
    let (proxy, chosen, upstream) = rebinding(&["64:ff9b::808:808", "::ffff:8.8.4.4"], &[]);
    let (_, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(
        dialled(&chosen)[0].ip(),
        assert_ok!("64:ff9b::808:808".parse::<std::net::IpAddr>())
    );
}

#[test]
fn the_name_is_looked_up_once_and_the_address_dialled_is_the_one_that_came_back() {
    let upstream = echo_upstream();
    let resolver = Arc::new(Counting {
        calls: 0.into(),
        inner: Table::answering("allowed.test", &["93.184.216.34"]),
    });
    let chosen = Arc::new(Mutex::new(Vec::new()));
    let proxy = start(
        config_on(upstream, &["allowed.test"], &[])
            .with_resolver(Arc::clone(&resolver) as Arc<dyn Resolver>)
            .with_dial_map(recording(&chosen)),
    );
    let (mut stream, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    assert_ok!(stream.write_all(b"x"));
    let mut byte = [0u8; 1];
    assert_ok!(stream.read_exact(&mut byte));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    assert_eq!(dialled(&chosen), [SocketAddr::new(PUBLIC, upstream)]);
}

// ====================================================================================
// The audit trail
// ====================================================================================

fn audited(allow: &[&str], names: &[&str], upstream: u16) -> (ProxyHandle, Arc<Collect>) {
    let sink = Collect::new();
    let proxy = start(config_on(upstream, allow, names).with_audit(Arc::clone(&sink) as _));
    (proxy, sink)
}

#[test]
fn a_served_connection_is_one_event_with_the_bytes_that_crossed_in_each_direction() {
    let upstream = echo_upstream();
    let (proxy, sink) = audited(&["allowed.test"], &["allowed.test"], upstream);
    let (mut stream, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    assert_ok!(stream.write_all(&[7u8; 1000]));
    let mut back = vec![0u8; 1000];
    assert_ok!(stream.read_exact(&mut back));
    assert_ok!(stream.shutdown(std::net::Shutdown::Write));
    // The echo server adds "bye" when it sees the end of its input.
    assert_eq!(read_to_end(&mut stream), b"bye");
    let events = sink.wait_for(1);
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(event.decision, Decision::Allowed);
    assert_eq!(
        event.host.as_ref().map(HostName::as_str),
        Some("allowed.test")
    );
    assert_eq!(event.port.map(Port::get), Some(upstream));
    assert_eq!((event.bytes_up, event.bytes_down), (1000, 1003));
}

#[test]
fn a_tunnel_still_open_when_the_proxy_stops_is_audited_with_the_bytes_so_far() {
    let upstream = echo_upstream();
    let (mut proxy, sink) = audited(&["allowed.test"], &["allowed.test"], upstream);
    let (mut stream, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    assert_ok!(stream.write_all(&[7u8; 100]));
    let mut back = vec![0u8; 100];
    assert_ok!(stream.read_exact(&mut back));
    proxy.stop();
    let events = sink.events();
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].decision, Decision::Allowed);
    assert_eq!(
        events[0].host.as_ref().map(HostName::as_str),
        Some("allowed.test")
    );
    assert_eq!((events[0].bytes_up, events[0].bytes_down), (100, 100));
}

#[test]
fn bytes_sent_with_the_connect_head_are_counted_as_sent_upstream() {
    let upstream = echo_upstream();
    let (proxy, sink) = audited(&["allowed.test"], &["allowed.test"], upstream);
    let mut stream = connect_to(&proxy);
    let request = format!(
        "{}hello",
        connect_request(&proxy, &format!("allowed.test:{upstream}"))
    );
    assert_ok!(stream.write_all(request.as_bytes()));
    let (head, mut rest) = read_head(&mut stream);
    assert!(status(&head).starts_with("HTTP/1.1 200"), "{head}");
    while rest.len() < 5 {
        let mut chunk = [0u8; 8];
        let n = assert_ok!(stream.read(&mut chunk));
        rest.extend_from_slice(&chunk[..n]);
    }
    drop(stream);
    let events = sink.wait_for(1);
    // The echo upstream sends the five bytes back and `bye` when it sees the end of its input.
    assert_eq!(
        (events[0].bytes_up, events[0].bytes_down),
        (5, 8),
        "{events:?}"
    );
}

#[test]
fn every_kind_of_refusal_is_one_event_with_its_code_and_a_malformed_request_names_no_target() {
    let upstream = echo_upstream();
    let (proxy, sink) = audited(&["allowed.test"], &["allowed.test"], upstream);
    let _ = send_raw(&proxy, "CONNECT allowed.test:443 HTTP/1.1\r\n\r\n");
    let _ = tunnel(&proxy, "other.test:443");
    let _ = tunnel(&proxy, "allowed.test:9999");
    let _ = send_raw(&proxy, "GET /nothing HTTP/1.1\r\n\r\n");
    let events = sink.wait_for(4);
    let codes: Vec<(&str, String)> = events
        .iter()
        .map(|e| match &e.decision {
            Decision::Refused { code, .. } => (*code, e.target()),
            Decision::Allowed => ("allowed", e.target()),
        })
        .collect();
    assert_eq!(codes.len(), 4, "{events:?}");
    let mut sorted = codes.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        [
            ("not_a_proxy_request", "-".to_owned()),
            ("not_allowed", "other.test:443".to_owned()),
            ("port_not_allowed", "allowed.test:9999".to_owned()),
            ("proxy_auth_required", "allowed.test:443".to_owned()),
        ]
    );
    assert!(events.iter().all(|e| (e.bytes_up, e.bytes_down) == (0, 0)));
}

#[test]
fn no_event_and_no_reply_ever_contains_the_token_or_the_credentials_header() {
    let upstream = echo_upstream();
    let (proxy, sink) = audited(&["allowed.test"], &["allowed.test"], upstream);
    let token = proxy.token().expose().to_owned();
    let header_value = proxy.token().authorization_value();
    let credentials = header_value.trim_start_matches("Basic ").to_owned();
    let mut replies = Vec::new();
    // A served connection, a refusal after authentication, one before it, and a malformed one.
    let (mut served, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
    replies.push(head);
    assert_ok!(served.write_all(b"x"));
    drop(served);
    replies.push(tunnel(&proxy, "other.test:443").1);
    replies.push(send_raw(
        &proxy,
        "CONNECT allowed.test:443 HTTP/1.1\r\nProxy-Authorization: Basic eDp5\r\n\r\n",
    ));
    replies.push(send_raw(
        &proxy,
        &format!("GET /x HTTP/1.1\r\n{}\r\n", auth_line(&proxy)),
    ));
    let events = sink.wait_for(4);
    assert_eq!(events.len(), 4, "{events:?}");
    let everything: String = events
        .iter()
        .map(|e| format!("{e} {e:?}"))
        .chain(replies)
        .collect::<Vec<_>>()
        .join("\n");
    for secret in [&token, &header_value, &credentials] {
        assert!(
            !everything.contains(secret.as_str()),
            "a secret leaked:\n{everything}"
        );
    }
}

#[test]
fn a_connection_over_the_limit_is_an_event_too() {
    let upstream = echo_upstream();
    let sink = Collect::new();
    let proxy = start(
        config_on(upstream, &["allowed.test"], &["allowed.test"])
            .with_max_connections(1)
            .with_audit(Arc::clone(&sink) as _),
    );
    let (_a, _) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
    let (_b, head) = tunnel(&proxy, &format!("allowed.test:{upstream}"));
    assert_eq!(code(&head), Some("busy"));
    let events = sink.wait_for(1);
    assert!(
        events
            .iter()
            .any(|e| matches!(&e.decision, Decision::Refused { code: "busy", .. })),
        "{events:?}"
    );
}
