//! How long one unlock takes with given Argon2id settings: `cargo run --release --example kdf_bench`.
use std::time::Instant;
use vaultix_core::crypto::{KdfParams, derive_kek};

fn main() {
    for (m_mib, t, p) in [
        (64, 3, 4),
        (128, 3, 4),
        (256, 3, 4),
        (256, 4, 4),
        (512, 3, 4),
    ] {
        let params = KdfParams {
            m_cost: m_mib * 1024,
            t_cost: t,
            p_cost: p,
        };
        let start = Instant::now();
        derive_kek("benchmark password", &[0u8; 16], params).unwrap();
        println!(
            "{m_mib:>4} MiB, t={t}, p={p}: {:>5} ms",
            start.elapsed().as_millis()
        );
    }
}
