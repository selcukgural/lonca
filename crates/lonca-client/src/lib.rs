//! A client of the Lonca daemon socket, for harnesses and runners.
//!
//! Only what a client needs: the protocol's request and response types and
//! its number ([`PROTOCOL`]), the socket client with the checks that make
//! sure the daemon is on the other end ([`trust`]), framing, timeouts and
//! typed errors ([`client`]), and the human session file ([`session`]). No
//! store, no policy evaluation, no daemon: a client is never a second writer.
//!
//! Versions: a change of [`PROTOCOL`] is a major version of this crate
//! (while it is 0.x, a minor one). Fields added to a shape are not a
//! change of the number. Pin an exact version and read the release notes
//! when you move.

pub mod client;
pub mod protocol;
pub mod session;
pub mod sys;
pub mod trust;

pub use client::{CallError, Client, ErrorKind};
pub use session::HumanSession;
pub use trust::Trust;

/// The runner-facing protocol number (`docs/protocol.md`), the one the
/// daemon answers in `ping.protocol`. It goes up when a shape changes in a
/// way a client must know about; adding a field does not count.
pub const PROTOCOL: u32 = 1;
