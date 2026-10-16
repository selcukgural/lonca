//! The Lonca daemon: the Gatekeeper every write goes through.

pub mod client;
pub mod home;
pub mod hooks;
pub mod protocol;
pub mod repo;
pub mod server;
pub mod service;

pub use client::Client;
pub use home::Home;
pub use service::{Clock, Service, Settings, system_clock};
