//! The Lonca network proxy (observation level H2).
//!
//! The harness sandbox routes every outbound connection of sandboxed shell
//! commands here (Claude Code: `sandbox.network.httpProxyPort`). Each
//! connection is logged as an observation of the session it belongs to,
//! which taints that session; repository policy may refuse it instead.
//! Whose it is, the connecting process's parents say (`lineage`).
//! The proxy itself lives in `lonca-net`; this module is Lonca's gate.

use std::net::TcpListener;
use std::sync::Arc;

pub use lonca_net::{bind, is_private, peer_pid};

use crate::lineage::Table;

use crate::service::Service;

impl lonca_net::Gate for Service {
    fn decide(&self, request: &lonca_net::Request<'_>) -> lonca_net::Verdict {
        let line =
            peer_pid(request.peer, request.local).and_then(|pid| Some(Table::read()?.line(pid)));
        let verdict = self.proxy_connect(line.as_deref(), request.host, request.port, request.peer);
        lonca_net::Verdict {
            allow: verdict.allow,
            allow_private: verdict.allow_private,
            reason: verdict.reason,
        }
    }

    fn finished(&self, request: &lonca_net::Request<'_>, _outcome: lonca_net::Outcome) {
        self.proxy_finished(request.peer);
    }

    fn misnamed(&self, request: &lonca_net::Request<'_>, asked: Option<&str>) {
        self.proxy_misnamed(request.peer, request.host, request.port, asked);
    }

    fn carried(&self, request: &lonca_net::Request<'_>, bytes: u64) -> bool {
        self.proxy_carried(request.peer, bytes)
    }
}

pub fn serve(listener: TcpListener, svc: Arc<Service>) {
    lonca_net::serve(listener, svc);
}
