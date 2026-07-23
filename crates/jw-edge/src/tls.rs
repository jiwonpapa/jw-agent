use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{self, ServerConfig};

pub fn load_acceptor(certificate: &Path, private_key: &Path) -> Result<TlsAcceptor, String> {
    let provider = rustls::crypto::ring::default_provider();
    let certificate_file = File::open(certificate)
        .map_err(|error| format!("cannot open edge certificate: {error}"))?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(certificate_file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot parse edge certificate: {error}"))?;
    if certificates.is_empty() {
        return Err(String::from("edge certificate chain is empty"));
    }
    let key_file = File::open(private_key)
        .map_err(|error| format!("cannot open edge private key: {error}"))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .map_err(|error| format!("cannot parse edge private key: {error}"))?
        .ok_or_else(|| String::from("edge private key is missing"))?;
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| format!("cannot configure edge TLS versions: {error}"))?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| format!("cannot configure edge certificate: {error}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}
