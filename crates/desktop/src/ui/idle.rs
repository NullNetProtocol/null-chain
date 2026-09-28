//! Locking an unlocked wallet after a period without input.

use std::time::{Duration, Instant};

/// Tracks the last user input against an optional timeout.
pub struct IdleLock {
    after: Option<Duration>,
    last_input: Instant,
}

impl IdleLock {
    /// Starts the clock at `now`; `after` of `None` never expires.
    pub fn new(after: Option<Duration>, now: Instant) -> Self {
        Self {
            after,
            last_input: now,
        }
    }

    /// Records input at `now`.
    pub fn touch(&mut self, now: Instant) {
        self.last_input = now;
    }

    /// Whether the timeout has passed since the last input.
    pub fn expired(&self, now: Instant) -> bool {
        self.after
            .is_some_and(|after| now.saturating_duration_since(self.last_input) >= after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    #[test]
    fn expires_only_after_the_full_timeout_without_input() {
        let start = Instant::now();
        let mut idle = IdleLock::new(Some(MINUTE), start);
        assert!(!idle.expired(start + Duration::from_secs(59)));
        assert!(idle.expired(start + MINUTE));
        idle.touch(start + MINUTE);
        assert!(!idle.expired(start + MINUTE + Duration::from_secs(30)));
    }

    #[test]
    fn a_disabled_timeout_never_expires() {
        let start = Instant::now();
        let idle = IdleLock::new(None, start);
        assert!(!idle.expired(start + MINUTE * 10_000));
    }

    #[test]
    fn a_clock_before_the_last_input_does_not_expire() {
        let start = Instant::now() + MINUTE;
        let idle = IdleLock::new(Some(MINUTE), start);
        assert!(!idle.expired(Instant::now()));
    }
}
