//! The Lonca daemon: the Gatekeeper every write goes through.

pub mod client;
pub mod gitcmd;
pub mod home;
pub mod hooks;
pub mod limits;
#[cfg(not(target_os = "linux"))]
mod peer_other;
pub mod protocol;
pub mod proxy;
pub mod repo;
pub mod server;
pub mod service;
pub mod sys;
pub mod trust;

pub use client::Client;
pub use home::Home;
pub use service::{Clock, Service, Settings, system_clock};
