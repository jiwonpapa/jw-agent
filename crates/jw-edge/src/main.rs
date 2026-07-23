#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, io};

use jw_edge::config::{EdgeConfig, HANDSHAKE_TIMEOUT, MAX_CONNECTIONS, UPSTREAM_TIMEOUT};
use jw_edge::proxy::proxy_connection;
use jw_edge::tls::load_acceptor;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("jw-edge: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let config = Arc::new(EdgeConfig::from_environment()?);
    let acceptor = load_acceptor(&config.certificate, &config.private_key)?;
    wait_for_upstream(&config.upstream_socket).await;
    let listener = TcpListener::bind(config.listen_address)
        .await
        .map_err(|error| format!("cannot bind edge listener: {error}"))?;
    prepare_readiness_socket(&config.ready_socket)?;
    let readiness_listener = UnixListener::bind(&config.ready_socket)
        .map_err(|error| format!("cannot bind edge readiness socket: {error}"))?;
    fs::set_permissions(
        &config.ready_socket,
        <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o622),
    )
    .map_err(|error| format!("cannot protect edge readiness socket: {error}"))?;
    let _readiness =
        ReadinessGuard::create(config.ready_file.clone(), config.ready_socket.clone())?;
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer) =
                    result.map_err(|error| format!("edge accept failed: {error}"))?;
                let permit = match Arc::clone(&permits).try_acquire_owned() {
                    Ok(value) => value,
                    Err(_) => continue,
                };
                let acceptor = acceptor.clone();
                let config = Arc::clone(&config);
                tokio::spawn(async move {
                    let _permit = permit;
                    let tls = match timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(value)) => value,
                        Ok(Err(_)) | Err(_) => return,
                    };
                    let _proxy_result = proxy_connection(tls, peer, &config).await;
                });
            }
            result = readiness_listener.accept() => {
                let (mut stream, _) =
                    result.map_err(|error| format!("edge readiness accept failed: {error}"))?;
                let upstream_socket = config.upstream_socket.clone();
                tokio::spawn(async move {
                    if matches!(
                        timeout(UPSTREAM_TIMEOUT, UnixStream::connect(upstream_socket)).await,
                        Ok(Ok(_))
                    ) {
                        let _result =
                            timeout(UPSTREAM_TIMEOUT, stream.write_all(b"JW-EDGE-READY-V1\n")).await;
                    }
                });
            }
        }
    }
}

async fn wait_for_upstream(path: &Path) {
    loop {
        if matches!(
            timeout(UPSTREAM_TIMEOUT, UnixStream::connect(path)).await,
            Ok(Ok(_))
        ) {
            return;
        }
        sleep(Duration::from_millis(250)).await;
    }
}

struct ReadinessGuard {
    ready_file: PathBuf,
    ready_socket: PathBuf,
}

impl ReadinessGuard {
    fn create(ready_file: PathBuf, ready_socket: PathBuf) -> Result<Self, String> {
        let parent = ready_file
            .parent()
            .ok_or_else(|| String::from("edge readiness path has no parent"))?;
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create edge runtime directory: {error}"))?;
        fs::write(&ready_file, b"ready\n")
            .map_err(|error| format!("cannot write edge readiness: {error}"))?;
        fs::set_permissions(
            &ready_file,
            <fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .map_err(|error| format!("cannot protect edge readiness file: {error}"))?;
        Ok(Self {
            ready_file,
            ready_socket,
        })
    }
}

impl Drop for ReadinessGuard {
    fn drop(&mut self) {
        let _ready_result = fs::remove_file(&self.ready_file);
        let _socket_result = fs::remove_file(&self.ready_socket);
    }
}

fn prepare_readiness_socket(path: &PathBuf) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| String::from("edge readiness socket has no parent"))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create edge runtime directory: {error}"))?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot replace edge readiness socket: {error}")),
    }
}
