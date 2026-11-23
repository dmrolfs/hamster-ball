// ABOUTME: Classifies resolved addresses (never, internal or global) and filters a host's addresses by policy; pure.
// ABOUTME: An allowed name must not lead the agent into this machine or its network; the classes decide what "into" means.
//! Address classes for DNS-rebinding protection (design 12, 12.1).
//!
//! The proxy resolves names itself and connects to the address it chose, so a name that the
//! allowlist permits cannot be turned into a connection to a service on this machine or its
//! network unless the user has said that host may resolve there.
//!
//! - **Never**: addresses that mean this machine or have no business being a destination
//!   (loopback, link-local including the cloud metadata address, multicast, reserved,
//!   documentation, the unspecified address). No setting allows them.
//! - **Internal**: addresses of private networks (RFC 1918, unique-local IPv6), of tunnels that
//!   hand out synthetic addresses (`100.64.0.0/10`, `198.18.0.0/15`) and site-local IPv6. Allowed
//!   only for hosts listed in `net.internal_hosts`.
//! - **Global**: everything else.
//!
//! IPv4-mapped (`::ffff:a.b.c.d`), NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) addresses are
//! classified by the IPv4 address they carry.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use strum::Display;

use crate::policy::{HostName, HostPattern};

/// Addresses no setting allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum Never {
    /// 127.0.0.0/8 and ::1: this machine.
    #[strum(to_string = "loopback, this machine")]
    Loopback,
    /// 0.0.0.0/8 and ::.
    #[strum(to_string = "the unspecified address")]
    Unspecified,
    /// 169.254.0.0/16 and fe80::/10, which includes the cloud metadata address.
    #[strum(to_string = "link-local, which includes cloud metadata services")]
    LinkLocal,
    /// 224.0.0.0/4 and ff00::/8.
    #[strum(to_string = "multicast")]
    Multicast,
    /// 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 and 2001:db8::/32.
    #[strum(to_string = "a documentation range")]
    Documentation,
    /// 2001::/32, a tunnelling protocol.
    #[strum(to_string = "Teredo tunnel space")]
    Teredo,
    /// Reserved, special-purpose or not yet allocated.
    #[strum(to_string = "a reserved range")]
    Reserved,
}

/// Addresses only hosts in `net.internal_hosts` may resolve to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum Internal {
    /// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
    #[strum(to_string = "a private network (RFC 1918)")]
    Private,
    /// fc00::/7.
    #[strum(to_string = "a unique-local IPv6 network")]
    UniqueLocal,
    /// 100.64.0.0/10, used by carrier-grade NAT, Tailscale and some TLS-inspecting tunnels.
    #[strum(to_string = "tunnel or shared address space (100.64.0.0/10)")]
    SharedAddressSpace,
    /// 198.18.0.0/15, used by some fake-IP proxies.
    #[strum(to_string = "benchmarking or fake-IP address space (198.18.0.0/15)")]
    Benchmarking,
    /// fec0::/10, deprecated site-local IPv6.
    #[strum(to_string = "a site-local IPv6 network")]
    SiteLocal,
}

/// What an address is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// An ordinary public address.
    Global,
    /// A private or tunnel address.
    Internal(Internal),
    /// An address nobody may reach through the proxy.
    Never(Never),
}

/// Classifies `ip`.
#[must_use]
pub fn classify(ip: IpAddr) -> Class {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> Class {
    let [a, b, c, _] = ip.octets();
    match (a, b, c) {
        (0, _, _) => Class::Never(Never::Unspecified),
        (10, _, _) => Class::Internal(Internal::Private),
        (100, 64..=127, _) => Class::Internal(Internal::SharedAddressSpace),
        (127, _, _) => Class::Never(Never::Loopback),
        (169, 254, _) => Class::Never(Never::LinkLocal),
        (172, 16..=31, _) => Class::Internal(Internal::Private),
        (192, 0, 0 | 2) | (192, 88, 99) => Class::Never(Never::Reserved),
        (192, 168, _) => Class::Internal(Internal::Private),
        (198, 18 | 19, _) => Class::Internal(Internal::Benchmarking),
        (198, 51, 100) | (203, 0, 113) => Class::Never(Never::Documentation),
        (224..=239, _, _) => Class::Never(Never::Multicast),
        (240..=255, _, _) => Class::Never(Never::Reserved),
        _ => Class::Global,
    }
}

fn classify_v6(ip: Ipv6Addr) -> Class {
    let segments = ip.segments();
    let octets = ip.octets();
    let embedded = |at: usize| {
        classify_v4(Ipv4Addr::new(
            octets[at],
            octets[at + 1],
            octets[at + 2],
            octets[at + 3],
        ))
    };
    if ip.is_unspecified() {
        return Class::Never(Never::Unspecified);
    }
    if ip.is_loopback() {
        return Class::Never(Never::Loopback);
    }
    // ::ffff:a.b.c.d (IPv4-mapped).
    if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
        return embedded(12);
    }
    // ::a.b.c.d (the deprecated IPv4-compatible form) and the rest of ::/96.
    if segments[..6] == [0, 0, 0, 0, 0, 0] {
        return Class::Never(Never::Reserved);
    }
    // 64:ff9b::/96 (NAT64): the IPv4 address it carries decides.
    if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return embedded(12);
    }
    // 64:ff9b:1::/48 (local-use NAT64) is not a public translation.
    if segments[..3] == [0x64, 0xff9b, 1] {
        return Class::Never(Never::Reserved);
    }
    // 2002::/16 (6to4): the IPv4 address it carries decides.
    if segments[0] == 0x2002 {
        return embedded(2);
    }
    if segments[0] == 0x2001 && segments[1] == 0 {
        return Class::Never(Never::Teredo);
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return Class::Never(Never::Documentation);
    }
    if segments[0] == 0x2001 && segments[1] < 0x0200 {
        return Class::Never(Never::Reserved);
    }
    match segments[0] {
        0xfe80..=0xfebf => Class::Never(Never::LinkLocal),
        0xfec0..=0xfeff => Class::Internal(Internal::SiteLocal),
        0xfc00..=0xfdff => Class::Internal(Internal::UniqueLocal),
        0xff00..=0xffff => Class::Never(Never::Multicast),
        0x2000..=0x3fff => Class::Global,
        _ => Class::Never(Never::Reserved),
    }
}

/// Why none of a host's addresses may be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressRefusal {
    /// An address of a class no setting allows.
    Never {
        /// The address.
        address: IpAddr,
        /// Its class.
        kind: Never,
    },
    /// An internal address for a host that is not in `net.internal_hosts`.
    Internal {
        /// The address.
        address: IpAddr,
        /// Its class.
        kind: Internal,
    },
}

/// Which resolved addresses a host may be connected to.
#[derive(Debug, Clone, Default)]
pub struct AddressPolicy {
    internal_hosts: Vec<HostPattern>,
}

impl AddressPolicy {
    /// A policy that lets the hosts matching `internal_hosts` use internal addresses.
    #[must_use]
    pub fn new(internal_hosts: Vec<HostPattern>) -> Self {
        Self { internal_hosts }
    }

    /// Keeps the addresses `host` may be connected to, in their order.
    ///
    /// # Errors
    /// When none is left: the refusal for the most useful dropped address. An internal address
    /// is reported before a forbidden one, because it is the one a setting can fix.
    pub fn filter(
        &self,
        host: &HostName,
        addrs: Vec<SocketAddr>,
    ) -> Result<Vec<SocketAddr>, AddressRefusal> {
        let internal_ok = self.internal_hosts.iter().any(|p| p.matches(host));
        let mut kept = Vec::with_capacity(addrs.len());
        let mut internal = None;
        let mut never = None;
        for addr in addrs {
            match classify(addr.ip()) {
                Class::Global => kept.push(addr),
                Class::Internal(_) if internal_ok => kept.push(addr),
                Class::Internal(kind) => {
                    internal.get_or_insert(AddressRefusal::Internal {
                        address: addr.ip(),
                        kind,
                    });
                }
                Class::Never(kind) => {
                    never.get_or_insert(AddressRefusal::Never {
                        address: addr.ip(),
                        kind,
                    });
                }
            }
        }
        if kept.is_empty() {
            return Err(internal.or(never).unwrap_or(AddressRefusal::Never {
                address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                kind: Never::Unspecified,
            }));
        }
        Ok(kept)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn ip(text: &str) -> IpAddr {
        assert_ok!(text.parse())
    }

    fn sock(text: &str) -> SocketAddr {
        SocketAddr::new(ip(text), 443)
    }

    fn host(text: &str) -> HostName {
        assert_ok!(HostName::parse(text))
    }

    fn pattern(text: &str) -> HostPattern {
        assert_ok!(HostPattern::parse(text))
    }

    #[test]
    fn ordinary_public_addresses_are_global() {
        for text in [
            "8.8.8.8",
            "93.184.216.34",
            "151.101.1.1",
            "100.63.255.255",
            "100.128.0.1",
            "172.15.255.255",
            "172.32.0.1",
            "192.169.0.1",
            "198.17.255.255",
            "198.20.0.1",
            "223.255.255.255",
            "2606:4700::1111",
            "2a00:1450:4001::200e",
            "2001:4860:4860::8888",
            "3fff::1",
            "2001:200::1",
            "2001:4860::1",
        ] {
            assert_eq!(classify(ip(text)), Class::Global, "{text}");
        }
    }

    #[test]
    fn this_machine_and_special_ranges_are_never_allowed() {
        let cases = [
            ("127.0.0.1", Never::Loopback),
            ("127.255.255.254", Never::Loopback),
            ("::1", Never::Loopback),
            ("0.0.0.0", Never::Unspecified),
            ("0.1.2.3", Never::Unspecified),
            ("::", Never::Unspecified),
            ("169.254.169.254", Never::LinkLocal),
            ("169.254.0.1", Never::LinkLocal),
            ("fe80::1", Never::LinkLocal),
            ("febf::1", Never::LinkLocal),
            ("224.0.0.1", Never::Multicast),
            ("239.255.255.255", Never::Multicast),
            ("ff02::1", Never::Multicast),
            ("240.0.0.1", Never::Reserved),
            ("255.255.255.255", Never::Reserved),
            ("192.0.0.170", Never::Reserved),
            ("192.0.2.1", Never::Reserved),
            ("192.88.99.1", Never::Reserved),
            ("198.51.100.7", Never::Documentation),
            ("203.0.113.7", Never::Documentation),
            ("2001:db8::1", Never::Documentation),
            ("2001::1", Never::Teredo),
            ("2001:1::1", Never::Reserved),
            ("2001:1ff::1", Never::Reserved),
            ("::2", Never::Reserved),
            ("::1.2.3.4", Never::Reserved),
            ("64:ff9b:1::1", Never::Reserved),
            ("4000::1", Never::Reserved),
            ("1::1", Never::Reserved),
        ];
        for (text, kind) in cases {
            assert_eq!(classify(ip(text)), Class::Never(kind), "{text}");
        }
    }

    #[test]
    fn private_and_tunnel_ranges_are_internal() {
        let cases = [
            ("10.0.0.1", Internal::Private),
            ("10.255.255.255", Internal::Private),
            ("172.16.0.1", Internal::Private),
            ("172.31.255.255", Internal::Private),
            ("192.168.104.1", Internal::Private),
            ("100.64.0.1", Internal::SharedAddressSpace),
            ("100.64.1.3", Internal::SharedAddressSpace),
            ("100.127.255.255", Internal::SharedAddressSpace),
            ("198.18.0.1", Internal::Benchmarking),
            ("198.19.255.255", Internal::Benchmarking),
            ("fd00::1", Internal::UniqueLocal),
            ("fc00::1", Internal::UniqueLocal),
            ("fdff:ffff::1", Internal::UniqueLocal),
            ("fec0::1", Internal::SiteLocal),
        ];
        for (text, kind) in cases {
            assert_eq!(classify(ip(text)), Class::Internal(kind), "{text}");
        }
    }

    #[test]
    fn addresses_that_carry_an_ipv4_address_are_classified_by_it() {
        let cases = [
            ("::ffff:127.0.0.1", Class::Never(Never::Loopback)),
            ("::ffff:7f00:1", Class::Never(Never::Loopback)),
            ("::ffff:10.1.2.3", Class::Internal(Internal::Private)),
            ("::ffff:169.254.169.254", Class::Never(Never::LinkLocal)),
            ("::ffff:8.8.8.8", Class::Global),
            (
                "::ffff:100.64.1.3",
                Class::Internal(Internal::SharedAddressSpace),
            ),
            ("::ffff:172.16.0.1", Class::Internal(Internal::Private)),
            ("::ffff:192.0.2.1", Class::Never(Never::Reserved)),
            ("::ffff:198.51.100.9", Class::Never(Never::Documentation)),
            (
                "64:ff9b::6440:103",
                Class::Internal(Internal::SharedAddressSpace),
            ),
            ("64:ff9b::c633:6409", Class::Never(Never::Documentation)),
            (
                "2002:6440:103::1",
                Class::Internal(Internal::SharedAddressSpace),
            ),
            ("2002:c633:6409::1", Class::Never(Never::Documentation)),
            ("64:ff9b::7f00:1", Class::Never(Never::Loopback)),
            ("64:ff9b::a00:1", Class::Internal(Internal::Private)),
            ("64:ff9b::808:808", Class::Global),
            ("2002:7f00:1::1", Class::Never(Never::Loopback)),
            ("2002:a00:1::1", Class::Internal(Internal::Private)),
            ("2002:808:808::1", Class::Global),
        ];
        for (text, class) in cases {
            assert_eq!(classify(ip(text)), class, "{text}");
        }
    }

    fn filter(
        internal: &[&str],
        name: &str,
        addrs: &[&str],
    ) -> Result<Vec<SocketAddr>, AddressRefusal> {
        let policy = AddressPolicy::new(internal.iter().map(|p| pattern(p)).collect());
        policy.filter(&host(name), addrs.iter().map(|a| sock(a)).collect())
    }

    #[test]
    fn a_host_with_only_global_addresses_keeps_them_all_in_order() {
        let kept = assert_ok!(filter(
            &[],
            "a.example.com",
            &["8.8.8.8", "2606:4700::1111"]
        ));
        assert_eq!(kept, [sock("8.8.8.8"), sock("2606:4700::1111")]);
    }

    #[test]
    fn forbidden_and_internal_addresses_are_dropped_and_the_rest_are_tried() {
        let kept = assert_ok!(filter(
            &[],
            "a.example.com",
            &["127.0.0.1", "10.0.0.5", "8.8.8.8", "169.254.169.254"]
        ));
        assert_eq!(kept, [sock("8.8.8.8")]);
    }

    #[test]
    fn an_internal_host_may_use_internal_addresses_but_never_the_forbidden_ones() {
        let kept = assert_ok!(filter(
            &["*.in.example.com", "github.com"],
            "git.in.example.com",
            &[
                "10.0.0.5",
                "100.64.1.3",
                "fd00::1",
                "127.0.0.1",
                "169.254.169.254"
            ]
        ));
        assert_eq!(
            kept,
            [sock("10.0.0.5"), sock("100.64.1.3"), sock("fd00::1")]
        );
        assert_eq!(
            assert_err!(filter(&["github.com"], "github.com", &["127.0.0.1"])),
            AddressRefusal::Never {
                address: ip("127.0.0.1"),
                kind: Never::Loopback
            }
        );
    }

    #[test]
    fn a_host_that_is_not_listed_is_refused_an_internal_address_with_the_class_to_fix() {
        assert_eq!(
            assert_err!(filter(&["github.com"], "api.github.com", &["100.64.1.4"])),
            AddressRefusal::Internal {
                address: ip("100.64.1.4"),
                kind: Internal::SharedAddressSpace
            }
        );
        // The apex entry does not cover a subdomain, and a wildcard does not cover the apex.
        assert_err!(filter(&["*.example.com"], "example.com", &["10.0.0.1"]));
    }

    #[test]
    fn when_both_kinds_were_dropped_the_internal_one_is_reported_because_a_setting_can_fix_it() {
        assert_eq!(
            assert_err!(filter(&[], "a.example.com", &["127.0.0.1", "10.0.0.5"])),
            AddressRefusal::Internal {
                address: ip("10.0.0.5"),
                kind: Internal::Private
            }
        );
    }

    #[test]
    fn no_addresses_at_all_is_a_refusal_not_a_connection() {
        assert_err!(filter(&[], "a.example.com", &[]));
    }
}
