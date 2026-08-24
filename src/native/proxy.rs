use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::{EgressDecision, EgressDecisionKind};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HOST_BYTES: usize = 253;
const MAX_RETAINED_DECISIONS: usize = 256;
const MAX_CONCURRENT_CONNECTIONS: usize = 128;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

pub(super) struct ProxyHandle {
    address: SocketAddr,
    decisions: Arc<Mutex<Vec<EgressDecision>>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl ProxyHandle {
    pub(super) async fn start(allowlist: Vec<(String, u16)>) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let decisions = Arc::new(Mutex::new(Vec::new()));
        let task_decisions = decisions.clone();
        let (shutdown, mut shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    _ = &mut shutdown_rx => break,
                    joined = connections.join_next(), if !connections.is_empty() => {
                        let _ = joined;
                    }
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { break };
                        if connections.len() >= MAX_CONCURRENT_CONNECTIONS {
                            let _ = stream.write_all(
                                b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                            ).await;
                            continue;
                        }
                        let allowlist = allowlist.clone();
                        let decisions = task_decisions.clone();
                        connections.spawn(async move {
                            let _ = serve(stream, &allowlist, &decisions).await;
                        });
                    }
                }
            }
            if tokio::time::timeout(SHUTDOWN_GRACE, async {
                while connections.join_next().await.is_some() {}
            })
            .await
            .is_err()
            {
                connections.abort_all();
            }
        });
        Ok(Self {
            address,
            decisions,
            shutdown: Some(shutdown),
            task,
        })
    }

    pub(super) const fn port(&self) -> u16 {
        self.address.port()
    }

    pub(super) fn proxy_url(&self) -> String {
        format!("http://{}", self.address)
    }

    pub(super) async fn finish(mut self) -> Vec<EgressDecision> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.task.await;
        self.decisions.lock().unwrap().clone()
    }
}

async fn serve(
    mut client: TcpStream,
    allowlist: &[(String, u16)],
    decisions: &Mutex<Vec<EgressDecision>>,
) -> io::Result<()> {
    let header = read_header(&mut client).await?;
    let request = parse_request(&header)?;
    let allowed = target_is_allowed(&request.host, request.port, allowlist);
    {
        let mut retained = decisions.lock().unwrap();
        if retained.len() < MAX_RETAINED_DECISIONS {
            retained.push(EgressDecision::new(
                if allowed {
                    EgressDecisionKind::Allowed
                } else {
                    EgressDecisionKind::Denied
                },
                request.host.clone(),
                request.port,
            ));
        }
    }
    if !allowed {
        client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }

    let mut upstream = TcpStream::connect((request.host.as_str(), request.port)).await?;
    if request.connect {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    } else {
        upstream.write_all(&request.forward_header).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn read_header(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    while bytes.len() < MAX_HEADER_BYTES {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy request ended before headers",
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "proxy request headers exceed limit",
    ))
}

struct ProxyRequest {
    connect: bool,
    host: String,
    port: u16,
    forward_header: Vec<u8>,
}

fn parse_request(header: &[u8]) -> io::Result<ProxyRequest> {
    let end = header
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(invalid_request)?;
    let text = std::str::from_utf8(&header[..end]).map_err(|_| invalid_request())?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(invalid_request)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or_else(invalid_request)?;
    let target = parts.next().ok_or_else(invalid_request)?;
    let version = parts.next().ok_or_else(invalid_request)?;
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Err(invalid_request());
    }

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_authority(target, 443)?;
        return Ok(ProxyRequest {
            connect: true,
            host,
            port,
            forward_header: Vec::new(),
        });
    }

    let absolute = target.strip_prefix("http://").ok_or_else(invalid_request)?;
    let (authority, path) = absolute
        .split_once('/')
        .map_or((absolute, "/"), |(authority, path)| (authority, path));
    let (host, port) = parse_authority(authority, 80)?;
    let path = if path == "/" {
        "/".to_owned()
    } else {
        format!("/{path}")
    };
    let mut forward = format!("{method} {path} {version}\r\n").into_bytes();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if !line
            .split_once(':')
            .is_some_and(|(name, _)| name.eq_ignore_ascii_case("proxy-connection"))
        {
            forward.extend_from_slice(line.as_bytes());
            forward.extend_from_slice(b"\r\n");
        }
    }
    forward.extend_from_slice(b"\r\n");
    forward.extend_from_slice(&header[end..]);
    Ok(ProxyRequest {
        connect: false,
        host,
        port,
        forward_header: forward,
    })
}

fn parse_authority(authority: &str, default_port: u16) -> io::Result<(String, u16)> {
    if authority.is_empty() || authority.contains('@') || authority.starts_with('[') {
        return Err(invalid_request());
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port = port.parse::<u16>().map_err(|_| invalid_request())?;
            (host, port)
        }
        _ => (authority, default_port),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty()
        || host.len() > MAX_HOST_BYTES
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err(invalid_request());
    }
    Ok((host, port))
}

fn target_is_allowed(host: &str, port: u16, allowlist: &[(String, u16)]) -> bool {
    allowlist
        .iter()
        .any(|(allowed_host, allowed_port)| host == allowed_host && port == *allowed_port)
}

fn invalid_request() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid proxy request")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_normalizes_dns_names_and_retains_ip_literals_for_denial_evidence() {
        assert_eq!(
            parse_authority("Example.COM.:443", 80).unwrap(),
            ("example.com".to_owned(), 443)
        );
        assert_eq!(
            parse_authority("93.184.216.34:443", 80).unwrap(),
            ("93.184.216.34".to_owned(), 443)
        );
        assert!(parse_authority("[::1]:443", 80).is_err());
    }

    #[test]
    fn connect_and_plain_http_targets_are_parsed() {
        let connect = parse_request(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n").unwrap();
        assert!(connect.connect);
        assert_eq!((connect.host.as_str(), connect.port), ("example.com", 443));

        let plain = parse_request(
            b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n",
        )
        .unwrap();
        assert!(!plain.connect);
        assert!(
            plain
                .forward_header
                .starts_with(b"GET /path?q=1 HTTP/1.1\r\n")
        );
        assert!(
            !plain
                .forward_header
                .windows(16)
                .any(|window| window.eq_ignore_ascii_case(b"proxy-connection"))
        );
    }
}
