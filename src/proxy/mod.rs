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
//! Scope of this module as built so far (hb-ghd.3.1): the allowlist, `CONNECT`, one-request
//! plain HTTP, streaming with half-close, limits and shutdown. Address checks, port policy,
//! credentials and the audit trail follow in hb-ghd.3.2.

mod authority;
mod refusal;
mod request;
mod resolve;
mod server;

pub use authority::{Authority, AuthorityError};
pub use refusal::Refusal;
pub use request::{MAX_HEAD_BYTES, Request, RequestError, parse_head};
pub use resolve::{Resolver, SystemResolver};
pub use server::{ProxyConfig, ProxyError, ProxyHandle, Timeouts};
