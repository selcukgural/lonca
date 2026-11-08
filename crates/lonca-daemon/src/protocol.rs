//! Wire protocol: one JSON object per line over a Unix socket. The shapes a
//! client needs are in `lonca-client`; here is what only the daemon's
//! policy knows.

pub use lonca_client::protocol::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrepareInit {
    pub repo: String,
    pub human: String,
    pub human_key: lonca_core::ops::HumanKey,
    /// Import trunk from this Git repository (path or URL).
    #[serde(default)]
    pub import_from: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
    /// The settings to start from. `None`: the install's own, hardened on a
    /// hardened daemon.
    #[serde(default)]
    pub profile: Option<lonca_policy::config::Profile>,
    /// A hardened repository on a machine with no presence key.
    #[serde(default)]
    pub without_presence: bool,
}
