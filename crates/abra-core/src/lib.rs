//! Core primitives for **Abra**, infrastructure for teleportation.
//!
//! Abra moves files, workspaces, and app state between one user's devices and
//! their cloud agents. This crate is the local half: identity, content-addressed
//! storage, the snapshot envelope, and the capsule/snapshot DAG. There is no
//! network code here.
//!
//! Two rules shape everything below:
//!
//! - **Carry the data, don't prescribe the experience.** A snapshot carries
//!   maximal structured data; receivers derive renderings at receive time.
//! - **Execute nothing.** Recipes and native blobs are stored and moved as
//!   data. This crate never runs a process.
//!
//! See `DESIGN.md` and `SPEC.md` at the repository root.

#![forbid(unsafe_code)]

pub mod canonical;
pub mod capsule;
pub mod cas;
pub mod error;
pub mod identity;
pub mod link;
pub mod manifest;
pub mod restore;
pub mod store;
mod util;

pub use error::{Error, Result};
pub use util::{atomic_write, now_ms};

/// This crate's version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The envelope format version this build implements, as it appears in a
/// manifest's `spec` field. See `SPEC.md`.
pub const SPEC: &str = "abra/0.1";
