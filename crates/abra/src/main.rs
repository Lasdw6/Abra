//! Abra CLI (stub).
//!
//! Phase 1 ships the core primitives only; this binary exists so the workspace
//! shape is stable for the transport phase, which will add the real
//! `abra send` / `abra recv` / `abra capsule` subcommands.

fn main() {
    println!(
        "abra {} (abra-core {}, abra_spec {})",
        env!("CARGO_PKG_VERSION"),
        abra_core::VERSION,
        abra_core::ABRA_SPEC,
    );
}
