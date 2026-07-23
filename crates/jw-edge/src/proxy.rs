use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

use crate::config::{EdgeConfig, HEADER_TIMEOUT, MAX_HEADER_BYTES, UPSTREAM_TIMEOUT};

pub async fn proxy_connection<S>(
    mut client: S,
    peer: SocketAddr,
    config: &EdgeConfig,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = read_request_head(&mut client).await?;
    let normalized = normalize_request_head(&request.head, peer.ip(), config)?;
    let mut upstream = timeout(
        UPSTREAM_TIMEOUT,
        UnixStream::connect(&config.upstream_socket),
    )
    .await
    .map_err(|_| String::from("upstream connection timed out"))?
    .map_err(|error| format!("cannot connect to agentd upstream: {error}"))?;
    upstream
        .write_all(&normalized)
        .await
        .map_err(|error| format!("cannot write normalized request: {error}"))?;
    upstream
        .write_all(&request.remainder)
        .await
        .map_err(|error| format!("cannot write buffered request body: {error}"))?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .map_err(|error| format!("edge proxy stream failed: {error}"))?;
    Ok(())
}

struct RequestHead {
    head: Vec<u8>,
    remainder: Vec<u8>,
}

async fn read_request_head<S>(stream: &mut S) -> Result<RequestHead, String>
where
    S: AsyncRead + Unpin,
{
    let future = async {
        let mut buffer = Vec::with_capacity(4 * 1_024);
        let mut chunk = [0_u8; 4 * 1_024];
        loop {
            let count = stream
                .read(&mut chunk)
                .await
                .map_err(|error| format!("cannot read request header: {error}"))?;
            if count == 0 {
                return Err(String::from("request closed before headers"));
            }
            buffer.extend_from_slice(&chunk[..count]);
            if let Some(end) = find_header_end(&buffer) {
                return Ok(RequestHead {
                    head: buffer[..end].to_vec(),
                    remainder: buffer[end..].to_vec(),
                });
            }
            if buffer.len() > MAX_HEADER_BYTES {
                return Err(String::from("request header exceeded bound"));
            }
        }
    };
    timeout(HEADER_TIMEOUT, future)
        .await
        .map_err(|_| String::from("request header timed out"))?
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

pub fn normalize_request_head(
    head: &[u8],
    peer: IpAddr,
    config: &EdgeConfig,
) -> Result<Vec<u8>, String> {
    if head.len() > MAX_HEADER_BYTES {
        return Err(String::from("request header exceeded bound"));
    }
    let text = std::str::from_utf8(head).map_err(|_| String::from("request header is invalid"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| String::from("request line is missing"))?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts
        .next()
        .ok_or_else(|| String::from("request method is missing"))?;
    let target = request_parts
        .next()
        .ok_or_else(|| String::from("request target is missing"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| String::from("request version is missing"))?;
    if request_parts.next().is_some()
        || !matches!(
            method,
            "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS"
        )
        || !target.starts_with('/')
        || target.starts_with("//")
        || version != "HTTP/1.1"
    {
        return Err(String::from("request line is rejected"));
    }

    let mut output = String::with_capacity(head.len().saturating_add(96));
    output.push_str(request_line);
    output.push_str("\r\n");
    let mut host_count = 0_u8;
    let mut origin_count = 0_u8;
    let mut content_length_count = 0_u8;
    let mut upgrade_count = 0_u8;
    let mut upgrade = false;
    let mut header_count = 0_u16;
    for line in lines {
        if line.is_empty() {
            break;
        }
        header_count = header_count.saturating_add(1);
        if header_count > 128 || line.starts_with(' ') || line.starts_with('\t') {
            return Err(String::from("request headers are rejected"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| String::from("request header is malformed"))?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(String::from("request header name is rejected"));
        }
        let value = value.trim();
        if value
            .bytes()
            .any(|byte| (byte < 0x20 && byte != b'\t') || byte == 0x7f)
        {
            return Err(String::from("request header value is rejected"));
        }
        let lower = name.to_ascii_lowercase();
        match lower.as_str() {
            "host" => {
                host_count = host_count.saturating_add(1);
                if value != config.external_authority() {
                    return Err(String::from("request host is rejected"));
                }
                output.push_str("Host: ");
                output.push_str(&config.public_host);
                output.push_str("\r\n");
            }
            "origin" => {
                origin_count = origin_count.saturating_add(1);
                if value != config.external_origin() {
                    return Err(String::from("request origin is rejected"));
                }
                output.push_str("Origin: ");
                output.push_str(&config.canonical_origin());
                output.push_str("\r\n");
            }
            "upgrade" => {
                upgrade_count = upgrade_count.saturating_add(1);
                if upgrade_count != 1 || !value.eq_ignore_ascii_case("websocket") {
                    return Err(String::from("request upgrade is rejected"));
                }
                upgrade = true;
                output.push_str(line);
                output.push_str("\r\n");
            }
            "content-length" => {
                content_length_count = content_length_count.saturating_add(1);
                if content_length_count != 1
                    || value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(String::from("request content length is rejected"));
                }
                output.push_str("Content-Length: ");
                output.push_str(value);
                output.push_str("\r\n");
            }
            "transfer-encoding" => {
                return Err(String::from("request transfer encoding is rejected"));
            }
            "connection"
            | "keep-alive"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "x-jw-client-address"
            | "forwarded"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto" => {}
            _ => {
                output.push_str(line);
                output.push_str("\r\n");
            }
        }
    }
    if host_count != 1 {
        return Err(String::from("request host is required exactly once"));
    }
    let mutation = !matches!(method, "GET" | "HEAD" | "OPTIONS");
    if mutation && origin_count != 1 {
        return Err(String::from("request origin is required exactly once"));
    }
    if !mutation && origin_count > 1 {
        return Err(String::from("request origin is duplicated"));
    }
    output.push_str("X-JW-Client-Address: ");
    output.push_str(&peer.to_string());
    output.push_str("\r\nConnection: ");
    output.push_str(if upgrade { "upgrade" } else { "close" });
    output.push_str("\r\n\r\n");
    Ok(output.into_bytes())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::path::PathBuf;

    use super::normalize_request_head;
    use crate::config::EdgeConfig;

    fn config() -> EdgeConfig {
        EdgeConfig {
            listen_address: SocketAddr::from(([0, 0, 0, 0], 9443)),
            public_host: String::from("agent.example.test"),
            certificate: PathBuf::from("/cert"),
            private_key: PathBuf::from("/key"),
            upstream_socket: PathBuf::from("/socket"),
            ready_file: PathBuf::from("/ready"),
            ready_socket: PathBuf::from("/ready.sock"),
        }
    }

    #[test]
    fn rewrites_authority_and_strips_forged_forwarding_headers() -> Result<(), String> {
        let request = b"POST /api/v1/auth/login HTTP/1.1\r\nHost: agent.example.test:9443\r\nOrigin: https://agent.example.test:9443\r\nX-JW-Client-Address: 203.0.113.5\r\nForwarded: for=203.0.113.5\r\nContent-Length: 2\r\n\r\n";
        let normalized =
            normalize_request_head(request, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), &config())?;
        let text = String::from_utf8(normalized).map_err(|error| error.to_string())?;
        assert!(text.contains("Host: agent.example.test\r\n"));
        assert!(text.contains("Origin: https://agent.example.test\r\n"));
        assert!(text.contains("X-JW-Client-Address: 192.0.2.10\r\n"));
        assert!(!text.contains("203.0.113.5"));
        assert!(text.contains("Connection: close\r\n"));
        Ok(())
    }

    #[test]
    fn rejects_wrong_host_and_missing_mutation_origin() {
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert!(
            normalize_request_head(
                b"GET / HTTP/1.1\r\nHost: wrong.example.test:9443\r\n\r\n",
                peer,
                &config(),
            )
            .is_err()
        );
        assert!(
            normalize_request_head(
                b"POST /api HTTP/1.1\r\nHost: agent.example.test:9443\r\n\r\n",
                peer,
                &config(),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_request_smuggling_and_header_overflow_shapes() {
        let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for request in [
            b"POST /api HTTP/1.1\r\nHost: agent.example.test:9443\r\nOrigin: https://agent.example.test:9443\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n"
                .as_slice(),
            b"POST /api HTTP/1.1\r\nHost: agent.example.test:9443\r\nOrigin: https://agent.example.test:9443\r\nTransfer-Encoding: chunked\r\n\r\n"
                .as_slice(),
            b"CONNECT /api HTTP/1.1\r\nHost: agent.example.test:9443\r\n\r\n".as_slice(),
        ] {
            assert!(normalize_request_head(request, peer, &config()).is_err());
        }
        let oversized = vec![b'a'; crate::config::MAX_HEADER_BYTES.saturating_add(1)];
        assert!(normalize_request_head(&oversized, peer, &config()).is_err());
    }
}
