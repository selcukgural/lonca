//! The Lonca daemon: the Gatekeeper every write goes through.

pub use lonca_client::client;
pub mod gitcmd;
pub mod home;
pub mod hooked;
pub mod hooks;
mod import;
pub mod limits;
pub mod lineage;
#[cfg(not(target_os = "linux"))]
mod peer_other;
pub mod protocol;
pub mod proxy;
pub mod repo;
pub mod security;
pub mod server;
pub mod service;
pub mod sys;
pub use lonca_client::trust;

pub use client::Client;
pub use home::Home;
pub use service::{Clock, Peer, Service, Settings, system_clock};
