#![forbid(unsafe_code)]

use std::env;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use jw_agentd::{
    AgentConfig, ApiDoc, AppState, FileBroker, SessionStore, TerminalBroker, UdsAuthBroker,
    UdsOpsBroker, build_router,
};
use jw_contracts::IngressChannel;
use tokio::net::{TcpListener, UnixListener};
use utoipa::OpenApi;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("jw-agentd: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    if jw_agentd::askpass::requested() {
        return jw_agentd::askpass::run();
    }
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("openapi") => {
            let output = arguments
                .next()
                .map_or_else(|| PathBuf::from("api/openapi.json"), PathBuf::from);
            if arguments.next().is_some() {
                return Err(String::from("usage: jw-agentd openapi [output-path]"));
            }
            write_openapi(&output)
        }
        Some("serve") | None => {
            if arguments.next().is_some() {
                return Err(String::from("usage: jw-agentd [serve|openapi]"));
            }
            serve().await
        }
        Some(_) => Err(String::from("usage: jw-agentd [serve|openapi]")),
    }
}

fn write_openapi(output: &Path) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let document = ApiDoc::openapi();
    let encoded = serde_json::to_string_pretty(&document).map_err(|error| error.to_string())?;
    std::fs::write(output, format!("{encoded}\n")).map_err(|error| error.to_string())
}

async fn serve() -> Result<(), String> {
    let config = AgentConfig::from_environment()?;
    let store = SessionStore::open(config.database.clone(), unix_milliseconds()?)?;
    let auth = Arc::new(UdsAuthBroker::new(
        config.auth_socket.clone(),
        config.auth_timeout,
    ));
    let ops = Arc::new(UdsOpsBroker::new(
        config.ops_socket.clone(),
        config.operation_timeout,
    ));
    let terminal = TerminalBroker::default();
    let files = FileBroker::default();

    let recovery_listener = TcpListener::bind(config.recovery_address)
        .await
        .map_err(|error| format!("cannot bind recovery listener: {error}"))?;
    let recovery_app = build_router(
        AppState::new(
            config.clone(),
            IngressChannel::Recovery,
            store.clone(),
            auth.clone(),
            ops.clone(),
        )
        .with_terminal_broker(terminal.clone())
        .with_file_broker(files.clone()),
    );

    if config.public_host.is_some() {
        prepare_socket(&config.proxy_socket)?;
        let public_listener = UnixListener::bind(&config.proxy_socket)
            .map_err(|error| format!("cannot bind public proxy socket: {error}"))?;
        std::fs::set_permissions(&config.proxy_socket, std::fs::Permissions::from_mode(0o660))
            .map_err(|error| format!("cannot set public proxy socket permissions: {error}"))?;
        let public_app = build_router(
            AppState::new(config, IngressChannel::Public, store, auth, ops)
                .with_terminal_broker(terminal)
                .with_file_broker(files),
        );
        let recovery = axum::serve(recovery_listener, recovery_app);
        let public = axum::serve(public_listener, public_app);
        tokio::try_join!(recovery, public)
            .map(|_| ())
            .map_err(|error| format!("listener failed: {error}"))
    } else {
        axum::serve(recovery_listener, recovery_app)
            .await
            .map_err(|error| format!("recovery listener failed: {error}"))
    }
}

fn prepare_socket(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Err(String::from("public proxy socket has no parent directory"));
    };
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            std::fs::remove_file(path).map_err(|error| error.to_string())
        }
        Ok(_) => Err(String::from(
            "refusing to replace non-socket public proxy path",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn unix_milliseconds() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| String::from("system clock is before Unix epoch"))?;
    i64::try_from(duration.as_millis()).map_err(|_| String::from("system clock overflow"))
}
