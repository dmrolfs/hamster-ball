// ABOUTME: Temporary deliberate failure proving that the hosted application gate rejects failed tests.
// ABOUTME: Removed in the next validation commit; never intended for merge.
//! Negative control for CI test-failure propagation.

#[test]
fn deliberate_ci_gate_failure() {
    assert_eq!(
        std::env::var("HB_CI_DELIBERATE_FAILURE_PROOF").ok(),
        Some("intentional failure".to_owned())
    );
}
