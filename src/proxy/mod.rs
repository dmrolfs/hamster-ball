// ABOUTME: The egress proxy: one loopback listener per session that serves CONNECT and plain HTTP for allowlisted hosts only.
// ABOUTME: Runs on its own tokio runtime thread behind a ProxyHandle; the rest of hb stays synchronous.
//! The network proxy (design 12, hb-ghd.3).
//!
//! Seatbelt can allow a connection to one address and port but cannot say "only
//! `app.kiro.dev`", so the profile lets the agent reach exactly one local port and this proxy
//! decides, per connection, by host name. It resolves names itself, so the sandbox needs no
//! DNS. It never looks inside a tunnel (no TLS interception).
//!
//! [`ProxyHandle::start`] binds `127.0.0.1:0` in the calling thread, so the port is known when it
//! returns and a bind error is an ordinary error, then runs the accept loop on a dedicated
//! thread with a single-threaded tokio runtime. Dropping the handle (or [`ProxyHandle::stop`])
//! ends every open connection and joins the thread.
//!
//! Every connection goes through, in order: the request head, the proxy credential
//! ([`Authorizer`]; a missing or wrong one is a `407` before anything else is said), the allowlist
//! rules ([`crate::policy::HostRule`]: host and port), name resolution, the address classes
//! ([`classify`], [`AddressPolicy`]) and the connection to the address chosen. One
//! [`AuditEvent`] is sent per connection to the optional [`AuditSink`]. Starting the proxy from
//! `session::run`, the proxy variables and the user-visible summary are hb-ghd.3.3.

mod address;
mod audit;
mod auth;
mod authority;
mod refusal;
mod request;
mod resolve;
mod server;

pub use address::{AddressPolicy, AddressRefusal, Class, Internal, Never, classify};
pub use audit::{AuditEvent, AuditSink, Decision};
pub use auth::{Authorizer, ProxyUrl, Token, USER};
pub use authority::{Authority, AuthorityError};
pub use refusal::Refusal;
pub use request::{Head, MAX_HEAD_BYTES, ProxyAuthorization, Request, RequestError, parse_head};
pub use resolve::{Resolver, SystemResolver};
pub use server::{DialMap, ProxyConfig, ProxyError, ProxyHandle, Timeouts};
