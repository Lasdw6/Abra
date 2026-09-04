//! Abra's authenticated wire protocol (SPEC §§6–7).
#![forbid(unsafe_code)]

pub mod auth;
pub mod control;
pub mod delivery;
pub mod error;
pub mod framing;
pub mod outbox;
pub mod relay;
pub mod transport;

pub use auth::*;
pub use control::*;
pub use delivery::*;
pub use error::{Error, Result};
pub use framing::{read_frame, read_frame_timeout, write_frame};
pub use outbox::*;
pub use relay::*;
pub use transport::*;

pub const ALPN: &[u8] = b"abra/1";
pub const WIRE_VERSION: u32 = 1;
