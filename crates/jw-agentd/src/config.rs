use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use jw_contracts::IngressChannel;

pub const DEFAULT_RECOVERY_ADDRESS: &str = "127.0.0.1:8787";
pub const DEFAULT_RECOVERY_ORIGIN: &str = "http://127.0.0.1:8787";
pub const DEFAULT_PROXY_SOCKET: &str = "/run/jw-agent-proxy/agentd.sock";
pub const DEFAULT_AUTH_SOCKET: &str = "/run/jw-agent/authd.sock";
pub const DEFAULT_OPS_SOCKET: &str = "/run/jw-agent/opsd.sock";
pub const DEFAULT_DATABASE: &str = "/var/lib/jw-agent/agentd/agentd.sqlite3";
pub const DEFAULT_WEB_ROOT: &str = "/usr/share/jw-agent/web";
pub const DEFAULT_SSH_EXECUTABLE: &str = "/usr/bin/ssh";
pub const DEFAULT_SSH_KNOWN_HOSTS: &str = "/etc/jw-agent/ssh_known_hosts";
pub const DEFAULT_ASKPASS_EXECUTABLE: &str = "/usr/lib/jw-agent/jw-agentd";
pub const DEFAULT_ASKPASS_DIRECTORY: &str = "/run/jw-agent/askpass";
pub const DEFAULT_STTY_EXECUTABLE: &str = "/usr/bin/stty";
pub const DEFAULT_SETSID_EXECUTABLE: &str = "/usr/bin/setsid";
pub const DEFAULT_OPERATION_TIMEOUT_SECONDS: u64 = 14 * 60;

#[derive(Clone, Debug)]
pub struct AgentConfig {
    pub recovery_address: SocketAddr,
    pub recovery_origin: String,
    pub public_host: Option<String>,
    pub public_addresses: Vec<IpAddr>,
    pub proxy_socket: PathBuf,
    pub auth_socket: PathBuf,
    pub ops_socket: PathBuf,
    pub database: PathBuf,
    pub web_root: PathBuf,
    pub ssh_executable: PathBuf,
    pub ssh_known_hosts: PathBuf,
    pub askpass_executable: PathBuf,
    pub askpass_directory: PathBuf,
    pub stty_executable: PathBuf,
    pub setsid_executable: PathBuf,
    pub auth_timeout: Duration,
    pub operation_timeout: Duration,
}

impl AgentConfig {
    pub fn from_environment() -> Result<Self, String> {
        let recovery_address =
            environment_or("JW_AGENT_RECOVERY_ADDRESS", DEFAULT_RECOVERY_ADDRESS)
                .parse::<SocketAddr>()
                .map_err(|_| String::from("JW_AGENT_RECOVERY_ADDRESS is invalid"))?;
        if !recovery_address.ip().is_loopback() {
            return Err(String::from(
                "recovery listener must bind a loopback address",
            ));
        }
        let recovery_origin = environment_or("JW_AGENT_RECOVERY_ORIGIN", DEFAULT_RECOVERY_ORIGIN);
        validate_origin(&recovery_origin, IngressChannel::Recovery)?;
        let public_host = std::env::var("JW_AGENT_PUBLIC_HOST")
            .ok()
            .filter(|value| !value.is_empty());
        if let Some(host) = &public_host {
            validate_public_host(host)?;
        }
        let public_addresses = public_addresses()?;
        Ok(Self {
            recovery_address,
            recovery_origin,
            public_host,
            public_addresses,
            proxy_socket: PathBuf::from(environment_or(
                "JW_AGENT_PROXY_SOCKET",
                DEFAULT_PROXY_SOCKET,
            )),
            auth_socket: PathBuf::from(environment_or("JW_AGENT_AUTH_SOCKET", DEFAULT_AUTH_SOCKET)),
            ops_socket: PathBuf::from(environment_or("JW_AGENT_OPS_SOCKET", DEFAULT_OPS_SOCKET)),
            database: PathBuf::from(environment_or("JW_AGENT_DATABASE", DEFAULT_DATABASE)),
            web_root: PathBuf::from(environment_or("JW_AGENT_WEB_ROOT", DEFAULT_WEB_ROOT)),
            ssh_executable: PathBuf::from(DEFAULT_SSH_EXECUTABLE),
            ssh_known_hosts: PathBuf::from(DEFAULT_SSH_KNOWN_HOSTS),
            askpass_executable: PathBuf::from(DEFAULT_ASKPASS_EXECUTABLE),
            askpass_directory: PathBuf::from(DEFAULT_ASKPASS_DIRECTORY),
            stty_executable: PathBuf::from(DEFAULT_STTY_EXECUTABLE),
            setsid_executable: PathBuf::from(DEFAULT_SETSID_EXECUTABLE),
            auth_timeout: Duration::from_secs(8),
            operation_timeout: operation_timeout()?,
        })
    }

    #[must_use]
    pub fn expected_origin(&self, channel: IngressChannel) -> String {
        match channel {
            IngressChannel::Public => self
                .public_host
                .as_ref()
                .map_or_else(String::new, |host| format!("https://{host}")),
            IngressChannel::Recovery => self.recovery_origin.clone(),
        }
    }

    #[must_use]
    pub fn expected_host(&self, channel: IngressChannel) -> String {
        match channel {
            IngressChannel::Public => match &self.public_host {
                Some(host) => host.clone(),
                None => String::new(),
            },
            IngressChannel::Recovery => match self.recovery_origin.strip_prefix("http://") {
                Some(authority) => authority.to_owned(),
                None => self.recovery_origin.clone(),
            },
        }
    }
}

fn public_addresses() -> Result<Vec<IpAddr>, String> {
    let raw = environment_or("JW_AGENT_PUBLIC_ADDRESSES", "");
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let mut addresses = Vec::new();
    for value in raw.split(',') {
        if value.is_empty() || value.trim() != value {
            return Err(String::from("JW_AGENT_PUBLIC_ADDRESSES is invalid"));
        }
        let address = value
            .parse::<IpAddr>()
            .map_err(|_| String::from("JW_AGENT_PUBLIC_ADDRESSES is invalid"))?;
        if address.is_loopback() || address.is_unspecified() || address.is_multicast() {
            return Err(String::from("JW_AGENT_PUBLIC_ADDRESSES is invalid"));
        }
        addresses.push(address);
    }
    addresses.sort();
    addresses.dedup();
    if addresses.len() > 8 {
        return Err(String::from(
            "JW_AGENT_PUBLIC_ADDRESSES has too many values",
        ));
    }
    Ok(addresses)
}

fn operation_timeout() -> Result<Duration, String> {
    let raw = environment_or(
        "JW_AGENT_OPERATION_TIMEOUT_SECONDS",
        &DEFAULT_OPERATION_TIMEOUT_SECONDS.to_string(),
    );
    let seconds = raw
        .parse::<u64>()
        .map_err(|_| String::from("JW_AGENT_OPERATION_TIMEOUT_SECONDS is invalid"))?;
    if !(30..=900).contains(&seconds) {
        return Err(String::from(
            "JW_AGENT_OPERATION_TIMEOUT_SECONDS must be between 30 and 900",
        ));
    }
    Ok(Duration::from_secs(seconds))
}

fn environment_or(name: &str, default: &str) -> String {
    match std::env::var(name) {
        Ok(value) => value,
        Err(_) => default.to_owned(),
    }
}

fn validate_origin(value: &str, channel: IngressChannel) -> Result<(), String> {
    let required_prefix = match channel {
        IngressChannel::Public => "https://",
        IngressChannel::Recovery => "http://",
    };
    let Some(authority) = value.strip_prefix(required_prefix) else {
        return Err(String::from("origin scheme does not match ingress"));
    };
    validate_host(authority)
}

fn validate_host(host: &str) -> Result<(), String> {
    if host.is_empty()
        || host.len() > 253
        || host.contains('/')
        || host.contains('\\')
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(String::from("host is invalid"));
    }
    Ok(())
}

fn validate_public_host(host: &str) -> Result<(), String> {
    validate_host(host)?;
    if host.parse::<IpAddr>().is_ok()
        || !host.contains('.')
        || !host.is_ascii()
        || host.bytes().any(|byte| byte.is_ascii_uppercase())
        || host.ends_with('.')
    {
        return Err(String::from("public host must be a lowercase FQDN"));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(String::from("public host must be a lowercase FQDN"));
        }
    }
    Ok(())
}

#[must_use]
pub fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
}

#[cfg(test)]
mod tests {
    use super::{validate_host, validate_public_host};

    #[test]
    fn host_rejects_path() {
        assert!(validate_host("example.com/path").is_err());
    }

    #[test]
    fn public_host_requires_fqdn_without_port_or_ip() {
        assert!(validate_public_host("server.example.com").is_ok());
        assert!(validate_public_host("127.0.0.1").is_err());
        assert!(validate_public_host("server.example.com:443").is_err());
    }
}
