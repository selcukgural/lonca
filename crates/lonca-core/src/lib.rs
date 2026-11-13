//! Lonca core: deterministic building blocks shared by the daemon, the
//! policy engine and the auditor.
//!
//! Nothing in this crate talks to the network, calls an AI model or reads the
//! clock. Time enters only as data (`time_ms` fields) chosen by the daemon.

#![forbid(unsafe_code)]
// The trusted core: a panic in the single writer stops every repository,
// so bad input must become an error or a denial (clippy.toml lets tests panic).
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

pub mod canonical;
pub mod changeid;
pub mod error;
#[cfg(feature = "keyed")]
pub mod keyed;
pub mod keys;
pub mod objects;
pub mod oplog;
pub mod ops;
pub mod paths;
#[cfg(feature = "store")]
pub mod store;
pub mod terminal;
mod threads;

pub use changeid::ChangeId;
pub use error::{Error, Result};
pub use objects::{FileEntry, FileMap, FileMode, GitId};
#[cfg(feature = "store")]
pub use store::Store;
