//! Sandbox helpers that run without an Abra daemon or a language interpreter.

/// Observation collection reads `/proc` and drives fd-relative syscalls, so it
/// exists on Unix only. Windows callers get a clear error from the CLI.
#[cfg(unix)]
pub mod observe;
pub mod process;
pub mod sandbox;
