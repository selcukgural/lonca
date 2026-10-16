//! Unix socket server: one thread per connection, one JSON line per request.

use std::io::BufReader;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

use crate::protocol::{MAX_LINE, Request, Response, read_line_limited, write_line};
use crate::service::Service;

/// Longest socket path that fits `sockaddr_un` on every supported platform.
pub const MAX_SOCKET_PATH: usize = 100;

pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    if path.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "socket path {} is longer than {MAX_SOCKET_PATH} bytes; set LONCA_SOCKET to a shorter path",
                path.display()
            ),
        ));
    }
    if path.exists() {
        // A live daemon answers; a stale socket file does not.
        if UnixStream::connect(path).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "a Lonca daemon is already running",
            ));
        }
        std::fs::remove_file(path)?;
    }
    let l = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(l)
}

pub fn serve(listener: UnixListener, svc: Arc<Service>) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let svc = svc.clone();
        std::thread::spawn(move || {
            let _ = handle_conn(stream, &svc);
        });
    }
}

fn handle_conn(stream: UnixStream, svc: &Service) -> std::io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    while let Some(line) = read_line_limited(&mut reader, MAX_LINE)? {
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => svc.handle(req),
            Err(e) => Response::err(0, "invalid", format!("bad request: {e}")),
        };
        write_line(&mut writer, &resp)?;
    }
    Ok(())
}
