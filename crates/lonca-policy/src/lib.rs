//! Lonca's deterministic decision layer.
//!
//! - [`state::State`] is a pure fold over the operation log.
//! - [`decide::decide`] is a pure function from (state, request, recorded
//!   evidence, time, policy) to a decision.
//! - [`chain::Chain`] combines both into the single-writer sequencer the daemon
//!   runs; the auditor replays the same functions over a stored log.

pub mod chain;
pub mod config;
pub mod decide;
pub mod human;
pub mod state;
pub mod symbols;

pub use chain::Chain;
pub use config::{Config, PolicyBundle};
pub use decide::{Ctx, decide};
pub use state::State;
