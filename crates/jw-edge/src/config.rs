use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_LISTEN_ADDRESS: &str = "0.0.0.0:9443";
pub const DEFAULT_CERTIFICATE: &str = "/etc/jw-agent/edge/server.crt";
pub const DEFAULT_PRIVATE_KEY: &str = "/etc/jw-agent/edge/server.key";
pub const DEFAULT_UPSTREAM_SOCKET: &str = "/run/jw-agent-proxy/agentd.sock";
pub const DEFAULT_READY_FILE: &str = "/run/jw-agent-edge/ready";
pub const DEFAULT_READY_SOCKET: &str = "/run/jw-agent-edge/ready.sock";
pub const MAX_HEADER_BYTES: usize = 32 * 1_024;
pub const MAX_CONNECTIONS: usize = 128;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
pub const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EdgeConfig {
    pub listen_address: SocketAddr,
    pub public_host: String,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub upstream_socket: PathBuf,
    pub ready_file: PathBuf,
    pub ready_socket: PathBuf,
}

impl EdgeConfig {
    pub fn from_environment() -> Result<Self, String> {
        let listen_address = environment_or("JW_EDGE_LISTEN_ADDRESS", DEFAULT_LISTEN_ADDRESS)
            .parse::<SocketAddr>()
            .map_err(|_| String::from("JW_EDGE_LISTEN_ADDRESS is invalid"))?;
        if listen_address.port() < 1_024 {
            return Err(String::from(
                "JW_EDGE_LISTEN_ADDRESS must use an unprivileged port",
            ));
        }
        let public_host = std::env::var("JW_AGENT_PUBLIC_HOST")
            .map_err(|_| String::from("JW_AGENT_PUBLIC_HOST is required"))?;
        validate_public_host(&public_host)?;
        Ok(Self {
            listen_address,
            public_host,
            certificate: PathBuf::from(environment_or("JW_EDGE_CERTIFICATE", DEFAULT_CERTIFICATE)),
            private_key: PathBuf::from(environment_or("JW_EDGE_PRIVATE_KEY", DEFAULT_PRIVATE_KEY)),
            upstream_socket: PathBuf::from(environment_or(
                "JW_EDGE_UPSTREAM_SOCKET",
                DEFAULT_UPSTREAM_SOCKET,
            )),
            ready_file: PathBuf::from(environment_or("JW_EDGE_READY_FILE", DEFAULT_READY_FILE)),
            ready_socket: PathBuf::from(environment_or(
                "JW_EDGE_READY_SOCKET",
                DEFAULT_READY_SOCKET,
            )),
        })
    }

    #[must_use]
    pub fn external_authority(&self) -> String {
        format!("{}:{}", self.public_host, self.listen_address.port())
    }

    #[must_use]
    pub fn external_origin(&self) -> String {
        format!("https://{}", self.external_authority())
    }

    #[must_use]
    pub fn canonical_origin(&self) -> String {
        format!("https://{}", self.public_host)
    }
}

fn environment_or(name: &str, fallback: &str) -> String {
    match std::env::var(name) {
        Ok(value) => value,
        Err(_) => fallback.to_owned(),
    }
}

fn validate_public_host(host: &str) -> Result<(), String> {
    if host.len() > 253
        || host.trim() != host
        || host.contains(':')
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(String::from("JW_AGENT_PUBLIC_HOST is invalid"));
    }
    let labels = host.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(String::from("JW_AGENT_PUBLIC_HOST is invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_public_host;

    #[test]
    fn host_is_fqdn_without_port_or_ip() {
        assert!(validate_public_host("agent.example.com").is_ok());
        assert!(validate_public_host("agent.example.com:9443").is_err());
        assert!(validate_public_host("192.0.2.10").is_err());
        assert!(validate_public_host("localhost").is_err());
    }
}
