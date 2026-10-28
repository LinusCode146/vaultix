//! Hybrid logical clock: wall-clock time that never goes backwards and is
//! always ahead of anything this device has already seen from other devices.
//! Gives a total order for "last writer wins" even if a Mac's clock is wrong.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Hlc {
    pub wall_ms: i64,
    pub counter: u32,
    /// Tie-breaker so two devices can never produce equal timestamps.
    pub device: Uuid,
}

impl Hlc {
    pub fn zero(device: Uuid) -> Self {
        Hlc { wall_ms: 0, counter: 0, device }
    }

    /// Timestamp for a new local change, given the last timestamp issued or seen.
    pub fn tick(last: Hlc, now_ms: i64, device: Uuid) -> Hlc {
        if now_ms > last.wall_ms {
            Hlc { wall_ms: now_ms, counter: 0, device }
        } else {
            Hlc { wall_ms: last.wall_ms, counter: last.counter + 1, device }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_even_if_clock_goes_back() {
        let d = Uuid::new_v4();
        let a = Hlc::tick(Hlc::zero(d), 1000, d);
        let b = Hlc::tick(a, 500, d);
        let c = Hlc::tick(b, 500, d);
        assert!(a < b && b < c);
        assert!(Hlc::tick(c, 2000, d) > c);
    }

    #[test]
    fn ahead_of_remote_timestamps() {
        let (me, other) = (Uuid::new_v4(), Uuid::new_v4());
        let remote = Hlc { wall_ms: 9_999_999, counter: 3, device: other };
        // Our clock is behind, but the new local change still sorts after what we saw.
        assert!(Hlc::tick(remote, 1000, me) > remote);
    }
}
