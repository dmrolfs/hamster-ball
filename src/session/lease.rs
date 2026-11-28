// ABOUTME: A supervisor lease measures UI progress, not queued socket traffic.
// ABOUTME: Darwin's monotonic clock includes sleep and is shared by both local processes.
//! Freshness of supervisor control, independent of agent output and socket buffering.
use std::time::Duration;

use nix::time::{ClockId, clock_gettime};
use snafu::{ResultExt, Snafu};

/// Interval between UI-produced renewals.
pub const HEARTBEAT: Duration = Duration::from_secs(5);
/// Time without UI progress before hb requests session shutdown.
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// Nanoseconds on the host's sleep-inclusive monotonic clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Progress(pub u64);

/// Failure to establish fresh UI progress.
#[derive(Debug, Snafu)]
pub enum LeaseError {
    /// The host clock could not be read.
    #[snafu(display("supervisor lease clock failed"))]
    Clock {
        /// OS error.
        source: nix::errno::Errno,
    },
    /// Clock value cannot be represented.
    #[snafu(display("supervisor lease timestamp is out of range"))]
    Range,
    /// The old deadline passed. A late renewal cannot revive it.
    #[snafu(display("supervisor made no progress before its lease expired"))]
    Expired,
    /// A renewal did not name fresh, increasing, nonfuture progress.
    #[snafu(display("supervisor heartbeat is stale or invalid"))]
    Invalid,
}

impl Progress {
    /// Reads the same host clock in both supervisor and hb.
    ///
    /// # Errors
    /// Clock failure or an unrepresentable timestamp.
    pub fn now() -> Result<Self, LeaseError> {
        let t = clock_gettime(ClockId::CLOCK_MONOTONIC).context(ClockSnafu)?;
        let seconds = u64::try_from(t.tv_sec()).map_err(|_| LeaseError::Range)?;
        let nanos = u64::try_from(t.tv_nsec()).map_err(|_| LeaseError::Range)?;
        seconds
            .checked_mul(1_000_000_000)
            .and_then(|s| s.checked_add(nanos))
            .map(Self)
            .ok_or(LeaseError::Range)
    }
}

pub(crate) struct Lease {
    deadline: u64,
    last: Option<Progress>,
    duration: u64,
}

impl Lease {
    pub(crate) fn new(now: Progress, duration: Duration) -> Result<Self, LeaseError> {
        let duration = u64::try_from(duration.as_nanos()).map_err(|_| LeaseError::Range)?;
        Ok(Self {
            deadline: now.0.checked_add(duration).ok_or(LeaseError::Range)?,
            last: None,
            duration,
        })
    }

    pub(crate) fn remaining(&self, now: Progress) -> Result<Duration, LeaseError> {
        self.deadline
            .checked_sub(now.0)
            .filter(|n| *n > 0)
            .map(Duration::from_nanos)
            .ok_or(LeaseError::Expired)
    }

    pub(crate) fn renew(&mut self, progress: Progress, now: Progress) -> Result<(), LeaseError> {
        self.remaining(now)?;
        let deadline = progress
            .0
            .checked_add(self.duration)
            .ok_or(LeaseError::Invalid)?;
        if progress > now || self.last.is_some_and(|last| progress <= last) || deadline <= now.0 {
            return Err(LeaseError::Invalid);
        }
        self.deadline = deadline;
        self.last = Some(progress);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    fn at(seconds: u64) -> Progress {
        Progress(seconds * 1_000_000_000)
    }

    #[test]
    fn handshake_starts_expiry_even_without_a_first_heartbeat() {
        let lease = assert_ok!(Lease::new(at(0), TIMEOUT));
        assert_eq!(assert_ok!(lease.remaining(at(59))), Duration::from_secs(1));
        assert!(matches!(
            assert_err!(lease.remaining(at(60))),
            LeaseError::Expired
        ));
    }

    #[test]
    fn delayed_progress_does_not_gain_delivery_time_or_revive_expired_lease() {
        let mut lease = assert_ok!(Lease::new(at(0), TIMEOUT));
        assert_ok!(lease.renew(at(5), at(50)));
        assert_eq!(assert_ok!(lease.remaining(at(50))), Duration::from_secs(15));
        assert!(matches!(
            assert_err!(lease.renew(at(64), at(65))),
            LeaseError::Expired
        ));
        assert_err!(lease.remaining(at(65)));
    }

    #[test]
    fn invalid_timestamps_cannot_renew_but_fresh_progress_can() {
        let mut lease = assert_ok!(Lease::new(at(0), TIMEOUT));
        assert_err!(lease.renew(at(6), at(5)));
        assert_ok!(lease.renew(at(5), at(5)));
        assert_err!(lease.renew(at(5), at(6)));
        assert_err!(lease.renew(at(4), at(6)));
        assert_ok!(lease.renew(at(10), at(10)));
        assert_ok!(lease.remaining(at(69)));
        assert_err!(lease.remaining(at(70)));
    }
}
