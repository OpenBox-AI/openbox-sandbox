#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use openbox_sandbox::{
    CallerFingerprint, DurableStore, OpenShellConfig, OpenShellRuntime, SandboxRuntime,
    SandboxServiceBoundary, SandboxTlsServer, SrtConfig, SrtRuntime, TlsServerConfig,
    compile_srt_policy,
};
use sha2::{Digest as _, Sha256};
use tokio_util::sync::CancellationToken;

mod config;

use config::{ProcessConfig, ProviderKind};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openbox-sandbox failed: {error}");
            std::process::ExitCode::from(1)
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run() -> Result<(), ProcessError> {
    let mode = parse_mode(std::env::args_os().skip(1))?;
    if let Mode::CompileSrtPolicy {
        policy_document,
        output,
        workspace_root,
    } = &mode
    {
        let digest = compile_srt_policy(policy_document, output, workspace_root)
            .map_err(|_| ProcessError::Configuration)?;
        println!("{digest}");
        return Ok(());
    }
    let config_path = std::env::var_os("OPENBOX_SANDBOX_CONFIG")
        .map(PathBuf::from)
        .ok_or(ProcessError::Configuration)?;
    let config: ProcessConfig =
        config::load(&config_path).map_err(|_| ProcessError::Configuration)?;
    verify_running_binary(config.asset_bundle.adapter_build_sha256().as_str())?;

    let callers = config
        .authorized_callers
        .iter()
        .map(|caller| {
            Ok((
                CallerFingerprint::parse(caller.certificate_sha256.clone())
                    .map_err(|_| ProcessError::Configuration)?,
                caller.role.into(),
            ))
        })
        .collect::<Result<HashMap<_, _>, ProcessError>>()?;
    if callers.len() != config.authorized_callers.len() {
        return Err(ProcessError::Configuration);
    }

    let runtime: Arc<dyn SandboxRuntime> = match config.provider {
        ProviderKind::OpenShell => {
            let runtime_config = OpenShellConfig::new(
                config
                    .runtime_endpoint
                    .clone()
                    .ok_or(ProcessError::Configuration)?,
                config
                    .runtime_mtls_directory
                    .clone()
                    .ok_or(ProcessError::Configuration)?,
            )
            .map_err(|_| ProcessError::Runtime)?
            .with_connect_timeout(Duration::from_millis(
                config
                    .runtime_connect_timeout_ms
                    .ok_or(ProcessError::Configuration)?,
            ))
            .map_err(|_| ProcessError::Runtime)?
            .with_poll_interval(Duration::from_millis(
                config
                    .runtime_poll_interval_ms
                    .ok_or(ProcessError::Configuration)?,
            ))
            .map_err(|_| ProcessError::Runtime)?
            .with_degraded_landlock(config.allow_degraded_landlock);
            if mode == Mode::CheckConfig {
                return Ok(());
            }
            Arc::new(
                OpenShellRuntime::connect(runtime_config)
                    .await
                    .map_err(|_| ProcessError::Runtime)?,
            )
        }
        ProviderKind::Srt => {
            let srt = SrtConfig::new(
                config
                    .srt_profile_path
                    .clone()
                    .ok_or(ProcessError::Configuration)?,
                config
                    .srt_profile_sha256
                    .clone()
                    .ok_or(ProcessError::Configuration)?,
                config
                    .srt_workspace_root
                    .clone()
                    .ok_or(ProcessError::Configuration)?,
                config.asset_bundle.policy().clone(),
            )
            .map_err(|_| ProcessError::Runtime)?;
            if mode == Mode::CheckConfig {
                return Ok(());
            }
            Arc::new(SrtRuntime::new(srt).map_err(|_| ProcessError::Runtime)?)
        }
    };
    let store =
        DurableStore::initialize(config.state_directory).map_err(|_| ProcessError::DurableState)?;
    let boundary = Arc::new(SandboxServiceBoundary::new(
        runtime,
        config.asset_bundle,
        store,
    ));
    boundary
        .reconcile_startup(
            Duration::from_millis(config.reconcile_delete_deadline_ms),
            Duration::from_millis(config.reconcile_wait_deadline_ms),
        )
        .await
        .map_err(|_| ProcessError::Reconciliation)?;

    let tls = TlsServerConfig::new(
        config.bind_address,
        config.server_certificate_path,
        config.server_private_key_path,
        config.client_ca_path,
        callers,
        config.maximum_connections,
        Duration::from_millis(config.drain_timeout_ms),
    )
    .map_err(|_| ProcessError::Configuration)?;
    let server = SandboxTlsServer::bind(tls, boundary)
        .await
        .map_err(|_| ProcessError::Transport)?;
    let shutdown = CancellationToken::new();
    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        signal_shutdown.cancel();
    });
    server
        .run(shutdown)
        .await
        .map_err(|_| ProcessError::Transport)
}

fn parse_mode(arguments: impl IntoIterator<Item = OsString>) -> Result<Mode, ProcessError> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    match arguments.as_slice() {
        [] => Ok(Mode::Run),
        [argument] if argument == "--check-config" => Ok(Mode::CheckConfig),
        [flag, policy_document, output, workspace_root] if flag == "--compile-srt-policy" => {
            Ok(Mode::CompileSrtPolicy {
                policy_document: PathBuf::from(policy_document),
                output: PathBuf::from(output),
                workspace_root: PathBuf::from(workspace_root),
            })
        }
        _ => Err(ProcessError::Usage),
    }
}

fn verify_running_binary(expected: &str) -> Result<(), ProcessError> {
    let executable = std::env::current_exe().map_err(|_| ProcessError::Configuration)?;
    let bytes = fs::read(executable).map_err(|_| ProcessError::Configuration)?;
    let actual = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in actual {
        use core::fmt::Write as _;
        write!(encoded, "{byte:02x}").map_err(|_| ProcessError::Configuration)?;
    }
    if encoded != expected {
        eprintln!("ERROR: binary hash mismatch: expected {expected} but actual is {encoded}");
        return Err(ProcessError::Configuration);
    }
    Ok(())
}

#[cfg(unix)]
async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};

    let Ok(mut terminate) = signal(SignalKind::terminate()) else {
        let _ = tokio::signal::ctrl_c().await;
        return;
    };
    tokio::select! {
        result = tokio::signal::ctrl_c() => { let _ = result; }
        value = terminate.recv() => { let _ = value; }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Mode {
    Run,
    CheckConfig,
    CompileSrtPolicy {
        policy_document: PathBuf,
        output: PathBuf,
        workspace_root: PathBuf,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessError {
    Usage,
    Configuration,
    Runtime,
    DurableState,
    Reconciliation,
    Transport,
}

impl core::fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Usage => "unsupported command line",
            Self::Configuration => "configuration rejected",
            Self::Runtime => "sandbox runtime unavailable",
            Self::DurableState => "durable state unavailable",
            Self::Reconciliation => "startup reconciliation incomplete",
            Self::Transport => "local authenticated transport unavailable",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_line_accepts_only_run_and_config_check_modes() {
        assert_eq!(parse_mode([]).unwrap(), Mode::Run);
        assert_eq!(
            parse_mode([OsString::from("--check-config")]).unwrap(),
            Mode::CheckConfig
        );
        assert_eq!(
            parse_mode([
                OsString::from("--compile-srt-policy"),
                OsString::from("/policy.yaml"),
                OsString::from("/profile.sb"),
                OsString::from("/workspaces"),
            ])
            .unwrap(),
            Mode::CompileSrtPolicy {
                policy_document: PathBuf::from("/policy.yaml"),
                output: PathBuf::from("/profile.sb"),
                workspace_root: PathBuf::from("/workspaces"),
            }
        );
        assert_eq!(
            parse_mode([OsString::from("--help")]).unwrap_err(),
            ProcessError::Usage
        );
        assert_eq!(
            parse_mode([
                OsString::from("--check-config"),
                OsString::from("unexpected")
            ])
            .unwrap_err(),
            ProcessError::Usage
        );
    }
}
