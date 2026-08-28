//! cadabra, the Abra daemon (stub).
//!
//! Phase 1 ships the core primitives only. The daemon will later own the device
//! identity, the capsule store, and the outbox -> health-check -> transfer ->
//! ack delivery loop.

fn main() {
    println!(
        "cadabra {} (abra-core {}, abra_spec {})",
        env!("CARGO_PKG_VERSION"),
        abra_core::VERSION,
        abra_core::ABRA_SPEC,
    );
    println!("no daemon loop in phase 1; exiting");
}
