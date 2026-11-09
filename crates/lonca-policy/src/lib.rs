//! Lonca's deterministic decision layer.
//!
//! - [`state::State`] is a pure fold over the operation log.
//! - [`decide::decide`] is a pure function from (state, request, recorded
//!   evidence, time, policy) to a decision.
//! - [`chain::Chain`] combines both into the single-writer sequencer the daemon
//!   runs; the auditor replays the same functions over a stored log.
//! - [`whatif::compare`] decides a log again with another policy.

#![forbid(unsafe_code)]
// The trusted core: a panic in the single writer stops every repository,
// so bad input must become an error or a denial (clippy.toml lets tests panic).
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

pub mod chain;
pub mod config;
pub mod decide;
pub mod details;
pub mod events;
pub mod harness;
pub mod human;
pub mod refs;
pub mod state;
pub mod symbols;
pub mod whatif;

pub use chain::Chain;
pub use config::{Config, PolicyBundle};
pub use decide::{Ctx, decide};
pub use state::State;
