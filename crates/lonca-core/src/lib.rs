//! Lonca core: deterministic building blocks shared by the daemon, the
//! policy engine and the auditor.
//!
//! Nothing in this crate talks to the network, calls an AI model or reads the
//! clock. Time enters only as data (`time_ms` fields) chosen by the daemon.

pub mod canonical;
pub mod changeid;
pub mod error;
pub mod keys;
pub mod oplog;
pub mod ops;
pub mod paths;
pub mod store;

pub use changeid::ChangeId;
pub use error::{Error, Result};
pub use store::{FileEntry, FileMap, FileMode, GitId, Store};
