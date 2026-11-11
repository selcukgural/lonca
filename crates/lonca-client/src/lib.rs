#![doc = include_str!("../README.md")]

pub mod client;
pub mod protocol;
pub mod real;
pub mod session;
pub mod sys;
pub mod trust;

pub use client::{CallError, Client, ErrorKind};
pub use real::real_path;
pub use session::HumanSession;
pub use trust::Trust;

/// The runner-facing protocol number (`docs/protocol.md`), the one the
/// daemon answers in `ping.protocol`. It goes up when a shape changes in a
/// way a client must know about; adding a field does not count.
pub const PROTOCOL: u32 = 1;
