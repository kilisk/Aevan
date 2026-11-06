//! A 64-packet sliding replay window for the ESP receive path.
//!
//! The window follows the usual RFC 4303 anti-replay algorithm: a bitmap of the
//! last [`ReplayWindow::WINDOW_BITS`] sequence numbers plus the highest sequence
//! seen. A packet is accepted once, rejected as a duplicate if its bit is set,
//! and rejected as too old when it falls outside the window. The highest
//! sequence advances only when a packet is accepted.
//!
//! The window is state only. It has no timers and performs no I/O; the caller
//! feeds it sequence numbers after the ESP ICV has been verified.

/// Number of sequence numbers tracked by the window.
pub const WINDOW_BITS: u32 = 64;

/// Why a sequence number was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayError {
    /// This sequence number was already accepted.
    #[error("ESP sequence {sequence} is a replay (highest accepted {highest})")]
    Replay {
        /// Rejected sequence number.
        sequence: u64,
        /// Highest sequence number accepted so far.
        highest: u64,
    },
    /// This sequence number is older than the window.
    #[error(
        "ESP sequence {sequence} is older than the 64-packet window (highest accepted {highest})"
    )]
    TooOld {
        /// Rejected sequence number.
        sequence: u64,
        /// Highest sequence number accepted so far.
        highest: u64,
    },
}

/// A 64-packet sliding replay window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    /// Create an empty window. No sequence number has been accepted yet.
    pub const fn new() -> Self {
        Self {
            highest: None,
            bitmap: 0,
        }
    }

    /// The highest accepted sequence number, if any.
    pub const fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// The bitmap of accepted sequence numbers. Bit 0 is [`Self::highest`],
    /// bit `n` is `highest - n`.
    pub const fn bitmap(&self) -> u64 {
        self.bitmap
    }

    /// Forget all state. This is what a new SA or a completed rekey does.
    pub fn reset(&mut self) {
        self.highest = None;
        self.bitmap = 0;
    }

    /// Check `sequence` and, if accepted, mark it as received.
    ///
    /// This mutates state only on success, so a rejected packet leaves the
    /// window untouched.
    pub fn check_and_update(&mut self, sequence: u64) -> Result<(), ReplayError> {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.bitmap = 1;
            return Ok(());
        };

        if sequence > highest {
            let advance = sequence - highest;
            if advance >= u64::from(WINDOW_BITS) {
                self.bitmap = 1;
            } else {
                self.bitmap = (self.bitmap << advance) | 1;
            }
            self.highest = Some(sequence);
            return Ok(());
        }

        let behind = highest - sequence;
        if behind >= u64::from(WINDOW_BITS) {
            return Err(ReplayError::TooOld { sequence, highest });
        }

        let bit = 1u64 << behind;
        if self.bitmap & bit != 0 {
            return Err(ReplayError::Replay { sequence, highest });
        }
        self.bitmap |= bit;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_packet_is_accepted_and_sets_the_window() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.highest(), None);
        assert_eq!(window.check_and_update(0), Ok(()));
        assert_eq!(window.highest(), Some(0));
        assert_eq!(window.bitmap(), 1);
    }

    #[test]
    fn in_order_packets_are_accepted_and_advance() {
        let mut window = ReplayWindow::new();
        for sequence in 0..100 {
            assert_eq!(window.check_and_update(sequence), Ok(()), "seq {sequence}");
            assert_eq!(window.highest(), Some(sequence));
            assert_eq!(window.bitmap() & 1, 1);
        }
    }

    #[test]
    fn reordered_packets_within_the_window_are_accepted_once() {
        let mut window = ReplayWindow::new();
        for sequence in [0, 1, 2, 5, 3, 4] {
            assert_eq!(window.check_and_update(sequence), Ok(()), "seq {sequence}");
        }
        assert_eq!(window.highest(), Some(5));
        // Every accepted packet is now a duplicate.
        for sequence in 0..=5 {
            assert!(matches!(
                window.check_and_update(sequence),
                Err(ReplayError::Replay { .. })
            ));
        }
    }

    #[test]
    fn duplicate_of_the_highest_is_rejected() {
        let mut window = ReplayWindow::new();
        window.check_and_update(10).expect("first");
        window.check_and_update(11).expect("second");
        assert_eq!(
            window.check_and_update(11),
            Err(ReplayError::Replay {
                sequence: 11,
                highest: 11
            })
        );
    }

    #[test]
    fn far_behind_is_rejected_as_too_old() {
        let mut window = ReplayWindow::new();
        window.check_and_update(100).expect("first");
        assert_eq!(
            window.check_and_update(36),
            Err(ReplayError::TooOld {
                sequence: 36,
                highest: 100
            })
        );
        // 63 behind is still inside the 64-packet window.
        assert_eq!(window.check_and_update(37), Ok(()));
        // 64 behind has fallen out.
        assert!(matches!(
            window.check_and_update(36),
            Err(ReplayError::TooOld { .. })
        ));
    }

    #[test]
    fn a_large_forward_jump_clears_the_old_window() {
        let mut window = ReplayWindow::new();
        window.check_and_update(10).expect("first");
        assert_eq!(window.check_and_update(10 + WINDOW_BITS as u64), Ok(()));
        assert_eq!(window.bitmap(), 1);
        // Old sequence numbers are now outside the window.
        assert!(matches!(
            window.check_and_update(10),
            Err(ReplayError::TooOld { .. })
        ));
        assert_eq!(
            window.check_and_update(10 + WINDOW_BITS as u64),
            Err(ReplayError::Replay {
                sequence: 74,
                highest: 74
            })
        );
    }

    #[test]
    fn window_tracks_the_top_of_the_sequence_space() {
        let mut window = ReplayWindow::new();
        let start = u64::MAX - 10;
        for sequence in start..=u64::MAX {
            assert_eq!(window.check_and_update(sequence), Ok(()), "seq {sequence}");
        }
        assert_eq!(window.highest(), Some(u64::MAX));
        assert_eq!(
            window.check_and_update(u64::MAX),
            Err(ReplayError::Replay {
                sequence: u64::MAX,
                highest: u64::MAX
            })
        );
        assert_eq!(window.check_and_update(u64::MAX - 63), Ok(()));
        assert!(matches!(
            window.check_and_update(u64::MAX - 64),
            Err(ReplayError::TooOld { .. })
        ));
    }

    #[test]
    fn reset_accepts_a_repeated_sequence_for_a_new_sa() {
        let mut window = ReplayWindow::new();
        window.check_and_update(7).expect("first");
        window.reset();
        assert_eq!(window.highest(), None);
        assert_eq!(window.check_and_update(7), Ok(()));
    }
}
