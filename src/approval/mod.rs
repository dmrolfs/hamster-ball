// ABOUTME: Approval of a project's config: fingerprint of the writable closure, the store, the grant summary and the prompt.
// ABOUTME: The agent can write the project, so `hb` runs a project config only if its exact bytes were approved by the owner.
//! Approval by hash (design section 5, decision D4).

mod digest;
mod gate;
mod store;
mod summary;

pub use digest::{Digest, FileDigest, Fingerprint};
pub use gate::{
    ApproveError, Candidate, GateError, NoTerminal, StdTerminal, Terminal, Verdict, require,
};
pub use store::{ApprovalStore, Changes, RecordProblem, Standing, StoreError, Why};
pub use summary::{Addition, GrantSummary, MAX_VALUE_CHARS};
