//! The Lonca network proxy (observation level H2).
//!
//! The harness sandbox routes every outbound connection of sandboxed shell
//! commands here (Claude Code: `sandbox.network.httpProxyPort`). Each
//! connection is logged as an observation of the session it belongs to,
//! which taints that session; repository policy may refuse it instead.
//! The proxy itself lives in `lonca-net`; this module is Lonca's gate.

use std::net::TcpListener;
use std::sync::Arc;

pub use lonca_net::{bind, is_private, peer_cwd};

use crate::service::Service;

impl lonca_net::Gate for Service {
    fn decide(&self, request: &lonca_net::Request<'_>) -> lonca_net::Verdict {
        let verdict = self.proxy_connect(
            peer_cwd(request.peer, request.local).as_deref(),
            request.host,
            request.port,
            request.peer,
        );
        lonca_net::Verdict {
            allow: verdict.allow,
            allow_private: verdict.allow_private,
            reason: verdict.reason,
        }
    }

    fn finished(&self, request: &lonca_net::Request<'_>, _outcome: lonca_net::Outcome) {
        self.proxy_finished(request.peer);
    }

    fn carried(&self, request: &lonca_net::Request<'_>, bytes: u64) -> bool {
        self.proxy_carried(request.peer, bytes)
    }
}

pub fn serve(listener: TcpListener, svc: Arc<Service>) {
    lonca_net::serve(listener, svc);
}
