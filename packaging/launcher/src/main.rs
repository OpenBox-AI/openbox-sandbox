//! `obs` operator/developer launcher.
//!
//! This standalone launcher locates an operator-installed `OpenShell`
//! gateway, verifies its launcher release pin, and can start that external
//! gateway. It is distinct from the root `openbox-sandbox` binary, which is the
//! production-intent mTLS sandbox service. `OpenShell` remains an external
//! runtime dependency; the launcher does not embed it.
//!
//! Architecture:
//!   client → mTLS → openbox-sandbox service → OpenShell gateway → driver/runtime
//!
//! `--verify-runtime` only checks local artifact/version compatibility. It does
//! not connect to a gateway or prove sandbox execution. From a source checkout,
//! `obs verify` drives the live mTLS create→ready→exec→delete proof.
//!
//! OpenShell supports four drivers; the operator's gateway selects one:
//!   - podman: rootless container runtime (preferred container path).
//!   - docker: container runtime with a root daemon.
//!   - kubernetes: delegates sandboxes to a cluster.
//!   - vm: libkrun microVM (KVM on Linux, Hypervisor.framework on macOS).
//!
//! Platform behavior:
//!   - Linux: any driver; container path uses Landlock (strict) or best_effort.
//!   - macOS: the microVM driver is the real target; container drivers are degraded and need consent.
//!   - Windows: unsupported directly; run inside WSL2.

use std::path::Path;
use std::process::{Command, ExitCode};

mod bundle;
mod deps;
mod provision;
mod publish;
mod pin;
mod scripts;
mod update;

/// One OpenShell compute driver the launcher can detect.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Runtime {
    Podman,
    Docker,
    Kubernetes,
    MicroVm,
}

impl Runtime {
    const ALL: [Runtime; 4] = [
        Runtime::Podman,
        Runtime::Docker,
        Runtime::Kubernetes,
        Runtime::MicroVm,
    ];

    fn key(self) -> &'static str {
        match self {
            Runtime::Podman => "podman",
            Runtime::Docker => "docker",
            Runtime::Kubernetes => "kubernetes",
            Runtime::MicroVm => "vm",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Runtime::Podman => "Podman (rootless container)",
            Runtime::Docker => "Docker (container, root daemon)",
            Runtime::Kubernetes => "Kubernetes (cluster)",
            Runtime::MicroVm => "libkrun microVM (hardware-isolated)",
        }
    }

    fn from_key(value: &str) -> Option<Runtime> {
        Runtime::ALL
            .into_iter()
            .find(|runtime| runtime.key() == value)
    }

    fn available(self) -> bool {
        match self {
            Runtime::Podman => command_ok("podman", &["--version"]),
            Runtime::Docker => command_ok("docker", &["--version"]),
            Runtime::Kubernetes => command_ok("kubectl", &["version", "--client"]),
            Runtime::MicroVm => hypervisor_available(),
        }
    }
}

/// Filesystem-isolation posture the run will request.
#[derive(Clone, Copy)]
enum Posture {
    ContainerStrict,
    ContainerDegraded,
    MicroVm,
    Cluster,
}

#[derive(Debug, PartialEq, Eq)]
enum CommandLine {
    Help,
    Provision {
        clean_rerun: bool,
        keep_pki: bool,
        overrides: Vec<(String, String)>,
    },
    Uninstall {
        keep_pki: bool,
    },
    Verify,
    Status,
    VerifyRuntime {
        skip_hash: bool,
    },
    Publish {
        release_dir: String,
        tag: String,
    },
    Update {
        release: Option<String>,
    },
    Launch,
}

/// Value-taking `--flag` → env mapping for provision options. Every knob the
/// provision script accepts via OPENBOX_* env has a CLI spelling.
const PROVISION_FLAG_ENV: &[(&str, &str)] = &[
    ("--state-root", "OPENBOX_STATE_ROOT"),
    ("--config-root", "OPENBOX_CONFIG_ROOT"),
    ("--project-root", "OPENBOX_PROJECT_ROOT"),
    ("--bundle-dir", "OPENSHELL_BUNDLE_DIR"),
    ("--sandbox-bin", "OPENBOX_SANDBOX_BIN"),
    ("--sandbox-port", "OPENBOX_SANDBOX_PORT"),
    ("--gateway-port", "OPENSHELL_SERVER_PORT"),
    ("--gateway-name", "OPENSHELL_GATEWAY_NAME"),
    ("--log-level", "OPENSHELL_LOG_LEVEL"),
    ("--policy-file", "OPENBOX_POLICY_FILE"),
    ("--policy-id", "OPENBOX_POLICY_ID"),
    ("--policy-version", "OPENBOX_POLICY_VERSION"),
    ("--compat-id", "OPENBOX_COMPAT_ID"),
    ("--sandbox-image", "OPENBOX_SANDBOX_IMAGE"),
    ("--dev-tar", "OPENBOX_SANDBOX_DEV_TAR"),
    ("--dev-image", "OPENBOX_DEV_IMAGE_NAME"),
    ("--vm-driver-state-dir", "OPENSHELL_VM_DRIVER_STATE_DIR"),
    ("--tls-dir", "OPENSHELL_LOCAL_TLS_DIR"),
    ("--runtime-mtls-dir", "OPENBOX_RUNTIME_MTLS_DIR"),
    ("--openshell-meta-dir", "OPENBOX_OPENSHELL_META_DIR"),
    ("--caller-subj", "OPENBOX_CALLER_SUBJ"),
    ("--cert-days", "OPENBOX_CERT_DAYS"),
    ("--rsa-bits", "OPENBOX_RSA_BITS"),
    ("--jwt-ttl-secs", "OPENBOX_JWT_TTL_SECS"),
    ("--gateway-ready-polls", "OPENBOX_GATEWAY_READY_POLLS"),
    ("--gateway-ready-interval", "OPENBOX_GATEWAY_READY_INTERVAL"),
    ("--service-ready-polls", "OPENBOX_SERVICE_READY_POLLS"),
    ("--service-ready-interval", "OPENBOX_SERVICE_READY_INTERVAL"),
    ("--warm-poll-count", "OPENBOX_WARM_POLL_COUNT"),
    ("--warm-poll-interval", "OPENBOX_WARM_POLL_INTERVAL"),
    ("--runtime-connect-timeout-ms", "OPENBOX_RUNTIME_CONNECT_TIMEOUT_MS"),
    ("--runtime-poll-interval-ms", "OPENBOX_RUNTIME_POLL_INTERVAL_MS"),
    ("--reconcile-delete-deadline-ms", "OPENBOX_RECONCILE_DELETE_DEADLINE_MS"),
    ("--reconcile-wait-deadline-ms", "OPENBOX_RECONCILE_WAIT_DEADLINE_MS"),
    ("--max-connections", "OPENBOX_MAX_CONNECTIONS"),
    ("--drain-timeout-ms", "OPENBOX_DRAIN_TIMEOUT_MS"),
    ("--allow-degraded-landlock", "OPENBOX_ALLOW_DEGRADED_LANDLOCK"),
    ("--container-runtime", "CONTAINER_RUNTIME"),
    ("--bin-override", "OPENSHELL_BIN_OVERRIDE"),
];

/// Boolean `--flag` → env=value pairs for provision options.
const PROVISION_FLAG_BOOLS: &[(&str, &str, &str)] = &[
    ("--no-start", "NO_START", "1"),
    ("--skip-warm-cache", "OPENBOX_WARM_CACHE", "0"),
    ("--force-warm-cache", "OPENBOX_WARM_CACHE", "1"),
];

fn parse_provision_flags(
    args: &[String],
) -> Result<(Vec<(String, String)>, bool, bool), String> {
    let mut overrides: Vec<(String, String)> = Vec::new();
    let mut clean_rerun = false;
    let mut keep_pki = false;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--clean-rerun" {
            clean_rerun = true;
            i += 1;
            continue;
        }
        if arg == "--keep-pki" {
            keep_pki = true;
            i += 1;
            continue;
        }
        if let Some((_, env_key, value)) = PROVISION_FLAG_BOOLS
            .iter()
            .find(|(flag, _, _)| *flag == arg)
        {
            overrides.push(((*env_key).to_owned(), (*value).to_owned()));
            i += 1;
            continue;
        }
        let mut matched = false;
        for (flag, env_key) in PROVISION_FLAG_ENV {
            if arg == *flag {
                // --flag value
                if i + 1 >= args.len() {
                    return Err(format!("{arg} requires a value"));
                }
                overrides.push(((*env_key).to_owned(), args[i + 1].clone()));
                i += 2;
                matched = true;
                break;
            }
            // --flag=value
            if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
                if value.is_empty() {
                    return Err(format!("{flag}= requires a value"));
                }
                overrides.push(((*env_key).to_owned(), value.to_owned()));
                i += 1;
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(format!(
                "unknown provision option '{arg}' (see `obs provision --help`-listed flags)"
            ));
        }
    }
    if keep_pki && !clean_rerun {
        return Err("--keep-pki requires `obs provision --clean-rerun`".to_owned());
    }
    Ok((overrides, clean_rerun, keep_pki))
}

fn parse_command(args: &[String]) -> Result<CommandLine, String> {
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        return Ok(CommandLine::Help);
    }
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(CommandLine::Launch);
    };
    match command {
        "provision" => {
            let (overrides, clean_rerun, keep_pki) = parse_provision_flags(&args[1..])?;
            Ok(CommandLine::Provision {
                clean_rerun,
                keep_pki,
                overrides,
            })
        }
        "uninstall" => {
            ensure_options(&args[1..], &["--keep-pki"])?;
            Ok(CommandLine::Uninstall {
                keep_pki: args[1..].iter().any(|arg| arg == "--keep-pki"),
            })
        }
        "verify" => {
            ensure_options(&args[1..], &[])?;
            Ok(CommandLine::Verify)
        }
        "status" => {
            ensure_options(&args[1..], &[])?;
            Ok(CommandLine::Status)
        }
        "update" => {
            let mut release = None;
            for arg in &args[1..] {
                if let Some(value) = arg.strip_prefix("--release=") {
                    release = Some(value.to_owned());
                } else if arg == "--release" {
                    let Some(value) = args.get(2).cloned() else {
                        return Err("--release requires a value".to_owned());
                    };
                    release = Some(value);
                } else if arg.starts_with('-') {
                    return Err(format!("unknown update option '{arg}'"));
                } else if release.is_none() {
                    release = Some(arg.clone());
                }
            }
            Ok(CommandLine::Update { release })
        }
        "publish" => {
            if args.len() < 2 {
                return Err("usage: obs publish <release-dir> [tag]".to_owned());
            }
            let release_dir = args[1].clone();
            let tag = args.get(2).cloned().unwrap_or_default();
            Ok(CommandLine::Publish { release_dir, tag })
        }
        value if !value.starts_with('-') => Err(format!("unknown subcommand: {value}")),
        _ => {
            validate_launch_options(args)?;
            if args.iter().any(|arg| arg == "--verify-runtime") {
                let verify_count = args
                    .iter()
                    .filter(|arg| arg.as_str() == "--verify-runtime")
                    .count();
                if verify_count != 1
                    || args
                        .iter()
                        .any(|arg| !matches!(arg.as_str(), "--verify-runtime" | "--skip-hash"))
                {
                    return Err("--verify-runtime may be combined only with --skip-hash".to_owned());
                }
                Ok(CommandLine::VerifyRuntime {
                    skip_hash: args.iter().any(|arg| arg == "--skip-hash"),
                })
            } else {
                Ok(CommandLine::Launch)
            }
        }
    }
}

fn ensure_options(args: &[String], allowed: &[&str]) -> Result<(), String> {
    if let Some(arg) = args.iter().find(|arg| !allowed.contains(&arg.as_str())) {
        return Err(format!("unsupported option: {arg}"));
    }
    Ok(())
}

fn validate_launch_options(args: &[String]) -> Result<(), String> {
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        match arg.as_str() {
            "--allow-degraded" | "--dry-run" | "--skip-hash" | "--verify-runtime" => {}
            "--driver" => {
                index += 1;
                if args.get(index).is_none_or(|value| value.starts_with('-')) {
                    return Err("--driver requires a value".to_owned());
                }
            }
            value if value.starts_with("--driver=") && value.len() > "--driver=".len() => {}
            _ => return Err(format!("unsupported option: {arg}")),
        }
        index += 1;
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_command(&args) {
        Ok(CommandLine::Help) => {
            print_help();
            return ExitCode::SUCCESS;
        }
        Ok(CommandLine::Provision {
            clean_rerun,
            keep_pki,
            overrides,
        }) => return provision::run_provision(clean_rerun, keep_pki, overrides),
        Ok(CommandLine::Uninstall { keep_pki }) => return provision::run_uninstall(keep_pki),
        Ok(CommandLine::Verify) => return provision::run_verify(),
        Ok(CommandLine::Status) => return provision::run_status(),
        Ok(CommandLine::VerifyRuntime { skip_hash }) => return verify_runtime(skip_hash),
        Ok(CommandLine::Publish { release_dir, tag }) => return publish::run(&release_dir, &tag),
        Ok(CommandLine::Update { release }) => return update::run(release.as_deref()),
        Ok(CommandLine::Launch) => {}
        Err(message) => {
            err(&message);
            info("run `obs --help` for usage");
            return ExitCode::FAILURE;
        }
    }

    let allow_degraded = args.iter().any(|arg| arg == "--allow-degraded");
    let dry_run = args.iter().any(|arg| arg == "--dry-run");
    let requested_key = flag_value(&args, "--driver");

    banner();
    let (os, arch) = platform();
    info(&format!("{os}/{arch}"));

    if os == "windows" {
        err("Windows is not supported directly; use WSL2.");
        return ExitCode::FAILURE;
    }

    let requested = match requested_key.as_deref().map(Runtime::from_key) {
        None => None,
        Some(Some(runtime)) => Some(runtime),
        Some(None) => {
            err("unknown --driver (use podman|docker|kubernetes|vm)");
            return ExitCode::FAILURE;
        }
    };

    let available: Vec<Runtime> = Runtime::ALL
        .into_iter()
        .filter(|runtime| runtime.available())
        .collect();
    info(&format!("runtimes: {}", runtime_summary(&available)));
    if available.is_empty() {
        err("no supported driver present");
        info("install one of: Podman, Docker, kubectl + cluster, or hypervisor");
        return ExitCode::FAILURE;
    }

    let chosen = match requested {
        Some(runtime) if available.contains(&runtime) => runtime,
        Some(runtime) => {
            err(&format!("--driver {} is not available", runtime.key()));
            return ExitCode::FAILURE;
        }
        None => *priority(os)
            .iter()
            .find(|runtime| available.contains(runtime))
            .expect("a runtime is available"),
    };
    info(&format!("driver: {}", chosen.label()));

    let posture = match assess(chosen, os, allow_degraded) {
        Some(posture) => posture,
        None => return ExitCode::FAILURE,
    };

    let artifacts = match bundle::resolve() {
        Ok(artifacts) => artifacts,
        Err(missing) => {
            err(&format!("artifact not found: {missing}"));
            info("OpenShell must be installed by the environment owner.");
            info("run packaging/launcher/scripts/fetch-openshell-deps.sh to fetch");
            info("the pinned release, or install via Homebrew (brew install openshell).");
            return ExitCode::FAILURE;
        }
    };
    report_artifacts(&artifacts);

    let skip_hash = args.iter().any(|a| a == "--skip-hash")
        || std::env::var("OPENBOX_SANDBOX_SKIP_ARTIFACT_HASH").as_deref() == Ok("1");
    if let Err(err_msg) = pin::verify(&artifacts, !skip_hash) {
        err(&format!("{}: {}", err_msg.artifact, err_msg.reason));
        info("OpenShell is pinned to a tested version; a mismatch can break the");
        info("sandbox-name / hook contracts. Install the matching release, or set");
        info("OPENBOX_SANDBOX_REQUIRED_OPENSHELL_VERSION to the installed version.");
        if err_msg.reason.starts_with("version") {
            info("run packaging/launcher/scripts/fetch-openshell-deps.sh to fetch");
            info("the pinned release.");
        }
        return ExitCode::FAILURE;
    }
    info(&format!(
        "pin: openshell {} verified",
        pin::REQUIRED_VERSION
    ));

    if dry_run {
        plan(os, arch, chosen, posture, &artifacts);
        return ExitCode::SUCCESS;
    }
    launch(chosen, posture, &artifacts)
}

/// Verify local launcher artifacts and their exact release version.
///
/// This does not connect to the gateway, inspect mTLS, or execute a sandbox.
/// Use `obs verify` from a provisioned source checkout for that live proof.
fn verify_runtime(skip_hash: bool) -> ExitCode {
    banner();
    let (os, arch) = platform();
    info(&format!("{os}/{arch}"));

    let artifacts = match bundle::resolve() {
        Ok(artifacts) => artifacts,
        Err(missing) => {
            err(&format!("local artifact not found ({missing})"));
            info("install the external OpenShell artifacts or set OPENBOX_BUNDLE_DIR");
            return ExitCode::FAILURE;
        }
    };
    report_artifacts(&artifacts);
    let skip_hash =
        skip_hash || std::env::var("OPENBOX_SANDBOX_SKIP_ARTIFACT_HASH").as_deref() == Ok("1");
    if let Err(error) = pin::verify(&artifacts, !skip_hash) {
        err(&format!("{}: {}", error.artifact, error.reason));
        return ExitCode::FAILURE;
    }
    ok(&format!(
        "launcher artifact/version pin {} matches",
        pin::REQUIRED_VERSION
    ));
    if artifacts.driver_vm.is_some() {
        info("vm driver: present");
    } else {
        info("vm driver: not found (needed only for microVM runs)");
    }
    println!();
    warn("artifact compatibility only: no gateway connection or sandbox was attempted");
    info("`obs verify` is the live mTLS create→ready→exec→delete proof");
    ExitCode::SUCCESS
}

/// Per-platform auto-selection order. On macOS the microVM is preferred because
/// the container drivers can only run degraded inside a VM there.
fn priority(os: &str) -> [Runtime; 4] {
    if os == "macos" {
        [
            Runtime::MicroVm,
            Runtime::Podman,
            Runtime::Docker,
            Runtime::Kubernetes,
        ]
    } else {
        [
            Runtime::Podman,
            Runtime::Docker,
            Runtime::MicroVm,
            Runtime::Kubernetes,
        ]
    }
}

fn assess(chosen: Runtime, os: &str, allow_degraded: bool) -> Option<Posture> {
    match chosen {
        Runtime::MicroVm => {
            info("isolation: microVM (hardware boundary)");
            if os == "macos" {
                info("Runs on Apple Hypervisor.framework with its own guest kernel;");
                info("no container runtime required. This is the supported macOS path.");
            }
            Some(Posture::MicroVm)
        }
        Runtime::Kubernetes => {
            info("isolation: delegated to the cluster");
            Some(Posture::Cluster)
        }
        Runtime::Podman | Runtime::Docker => match os {
            "linux" => {
                if landlock_available() {
                    info("isolation: strict (landlock)");
                    Some(Posture::ContainerStrict)
                } else {
                    warn("Landlock not available on this kernel.");
                    info("Continuing best_effort: namespaces/cgroups/seccomp still apply.");
                    info("isolation: degraded (best_effort)");
                    Some(Posture::ContainerDegraded)
                }
            }
            "macos" => {
                warn("Container driver on macOS is degraded and NOT recommended.");
                info("It runs inside the runtime's Linux VM where Landlock is absent.");
                info("Prefer --driver vm (libkrun microVM) for real isolation on macOS.");
                if !command_ok(chosen.key(), &["info"]) {
                    err(&format!(
                        "{}: no reachable connection (is the VM started?)",
                        chosen.key()
                    ));
                    return None;
                }
                if !allow_degraded {
                    err("refusing degraded run without consent");
                    info("re-run with --allow-degraded, or use --driver vm.");
                    return None;
                }
                info("isolation: degraded (best_effort, via runtime VM)");
                Some(Posture::ContainerDegraded)
            }
            _ => {
                err("unsupported operating system");
                None
            }
        },
    }
}

/// Report the resolved artifact paths so the operator can see exactly what the
/// launcher will run.
fn report_artifacts(artifacts: &bundle::Artifacts) {
    info(&format!("gateway: {}", artifacts.gateway.display()));
    info(&format!("cli:     {}", artifacts.cli.display()));
    info(&format!("policy:  {}", artifacts.policy(false).display()));
}

/// Print the concrete plan without starting anything (`--dry-run`).
fn plan(os: &str, arch: &str, chosen: Runtime, posture: Posture, artifacts: &bundle::Artifacts) {
    println!();
    let (degraded, policy) = posture_config(posture);
    step(&format!("PLAN — bootstrap for {os}/{arch}"));
    info(&format!("1. driver: OPENSHELL_DRIVERS={}", chosen.key()));
    info(&format!("2. gateway: {}", artifacts.gateway.display()));
    info(&format!(
        "3. service config allow_degraded_landlock = {degraded}"
    ));
    info(&format!(
        "4. policy: {}",
        artifacts.policy(policy).display()
    ));
    info("5. generate local mTLS identities on first run");
    info("6. start the OpenShell gateway; then start the openbox-sandbox service");
}

/// Map a posture to (allow_degraded_landlock, use_dev_policy).
fn posture_config(posture: Posture) -> (bool, bool) {
    match posture {
        Posture::ContainerStrict => (false, false),
        Posture::ContainerDegraded => (true, true),
        Posture::MicroVm => (true, true),
        Posture::Cluster => (false, false),
    }
}

/// Start the OpenShell gateway with the selected driver and wait on it.
fn launch(chosen: Runtime, posture: Posture, artifacts: &bundle::Artifacts) -> ExitCode {
    let (degraded, dev_policy) = posture_config(posture);
    println!();
    step("START openbox-sandbox");
    info(&format!(
        "driver={} degraded_landlock={degraded}",
        chosen.key()
    ));
    info(&format!(
        "policy={}",
        artifacts.policy(dev_policy).display()
    ));
    info(&format!("gateway={}", artifacts.gateway.display()));

    let mut command = Command::new(&artifacts.gateway);
    command
        .env("OPENSHELL_DRIVERS", chosen.key())
        .arg("--drivers")
        .arg(chosen.key());
    match command.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => {
            err(&format!(
                "gateway exited with status {}",
                status.code().unwrap_or(-1)
            ));
            ExitCode::FAILURE
        }
        Err(error) => {
            err(&format!("gateway failed to start: {error}"));
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn platform() -> (&'static str, &'static str) {
    let os = if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    };
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "unknown"
    };
    (os, arch)
}

fn hypervisor_available() -> bool {
    if cfg!(target_os = "linux") {
        Path::new("/dev/kvm").exists()
    } else if cfg!(target_os = "macos") {
        Command::new("sysctl")
            .args(["-n", "kern.hv_support"])
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "1")
            .unwrap_or(false)
    } else {
        false
    }
}

fn landlock_available() -> bool {
    std::fs::read_to_string("/sys/kernel/security/lsm")
        .map(|modules| modules.split(',').any(|module| module.trim() == "landlock"))
        .unwrap_or(false)
}

fn command_ok(bin: &str, args: &[&str]) -> bool {
    Command::new(bin)
        .args(args)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    let prefix = format!("{name}=");
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == name {
            return iter.next().cloned();
        }
        if let Some(value) = arg.strip_prefix(&prefix) {
            return Some(value.to_owned());
        }
    }
    None
}

fn runtime_summary(available: &[Runtime]) -> String {
    if available.is_empty() {
        return "none".to_owned();
    }
    available
        .iter()
        .map(|runtime| runtime.key())
        .collect::<Vec<_>>()
        .join(", ")
}

fn print_help() {
    println!(
        r#"obs — OpenBox operator/developer launcher

USAGE:
  obs provision [OPTIONS]      Teardown stale state, then provision dogfood.
  obs uninstall [--keep-pki]   Teardown and delete wizard-owned state.
  obs verify                   Prove mTLS create→ready→exec→delete live.
  obs status                   Report stack readiness.
  obs publish <dir> [tag]      Publish a release dir to GitHub Releases.
  obs update [TAG]            Download the platform assets for TAG (default:
                              latest release) into the current dir, verify
                              SHA256SUMS, and replace obs.
  obs [OPTIONS]                Start the external OpenShell gateway.

MODULES:
  openbox-sandbox   Production-intent mTLS sandbox service (root crate).
  obs               Operator/developer launcher (this binary).
  OpenShell         External gateway/driver runtime; never embedded.

DOGFOOD LOOP (source checkout only):
  cargo build --release --bin openbox-sandbox
  cargo build --release --manifest-path packaging/launcher/Cargo.toml
  OPENSHELL_BIN_OVERRIDE=/path/to/f1690849/build obs provision
  obs verify && obs uninstall

PROVISION OPTIONS (defaults in parentheses; every OPENBOX_* env knob has a --flag):
  --clean-rerun          Also remove wizard-owned state before provisioning.
  --keep-pki             Preserve PKI (with --clean-rerun or uninstall).
  --state-root PATH      (~/.local/state/openbox-sandbox)
  --config-root PATH     (~/.config/openbox-sandbox)
  --sandbox-port N       (17443)
  --gateway-port N       (17670)
  --gateway-name NAME    (openshell)
  --log-level LEVEL      (info)
  --policy-file PATH     (auto: launcher dir / cwd / repo defaults)
  --policy-id ID         (auto from policy file name)
  --policy-version N     (1)
  --compat-id ID         (darwin-dev-1)
  --dev-tar PATH         (auto per platform next to obs)
  --dev-image NAME       (openbox-sandboxes-dev)
  --sandbox-image REF    (NVIDIA base image digest)
  --bundle-dir PATH      (auto: launcher bundle dir)
  --bin-override PATH    (bundle bin override)
  --container-runtime RT (docker)
  --cert-days N          (825)
  --rsa-bits N           (2048)
  --jwt-ttl-secs N       (3600)
  --gateway-ready-polls N (60)
  --gateway-ready-interval S (0.5)
  --service-ready-polls N (40)
  --service-ready-interval S (0.25)
  --warm-poll-count N    (240)
  --warm-poll-interval S (5)
  --runtime-connect-timeout-ms N (10000)
  --runtime-poll-interval-ms N  (500)
  --reconcile-delete-deadline-ms N (60000)
  --reconcile-wait-deadline-ms N  (60000)
  --max-connections N    (64)
  --drain-timeout-ms N   (30000)
  --allow-degraded-landlock BOOL (true)
  --vm-driver-state-dir PATH (auto per user+gateway)
  --tls-dir PATH         (~/.local/state/openshell/tls)
  --runtime-mtls-dir PATH (~/.config/openbox-sandbox/runtime-mtls)
  --openshell-meta-dir PATH (~/.config/openshell)
  --caller-subj SUBJ     (/CN=openbox-sandbox-runtime-caller)
  --no-start             Set NO_START=1 (write configs, start nothing)
  --skip-warm-cache      Set OPENBOX_WARM_CACHE=0
  --force-warm-cache     Set OPENBOX_WARM_CACHE=1

LAUNCHER OPTIONS:
  --driver <name>      Force a driver (podman|docker|kubernetes|vm).
  --allow-degraded     Accept reduced isolation (container w/o Landlock).
  --dry-run            Resolve artifacts and print the plan; start nothing.
  --verify-runtime     Verify local artifact/version compatibility only.
                       It does not connect or prove sandbox execution.
  --skip-hash          Skip operator-supplied hashes (dev only); may be
                       combined with --verify-runtime.
  -h, --help           Show this help.

`obs provision` requires OpenShell 0.0.88 (locked release)
or the root protocol marker f1690849."#
    );
}

// ── Output helpers ──────────────────────────────────────────────────────

pub(crate) fn banner() {
    println!("obs\n");
}

pub(crate) fn step(msg: &str) {
    eprintln!("▸ {msg}");
}

pub(crate) fn ok(msg: &str) {
    eprintln!("  ✓ {msg}");
}

pub(crate) fn info(msg: &str) {
    eprintln!("  • {msg}");
}

pub(crate) fn warn(msg: &str) {
    eprintln!("  ⚠ {msg}");
}

pub(crate) fn err(msg: &str) {
    eprintln!("  ✗ {msg}");
}

#[cfg(test)]
mod tests {
    use super::{parse_command, CommandLine};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn subcommand_name_used_as_driver_value_does_not_dispatch() {
        let parsed = parse_command(&args(&["--driver", "provision"]));
        assert_eq!(parsed, Ok(CommandLine::Launch));
    }

    #[test]
    fn provision_options_are_validated() {
        assert_eq!(
            parse_command(&args(&["provision", "--clean-rerun", "--keep-pki"])),
            Ok(CommandLine::Provision {
                clean_rerun: true,
                keep_pki: true,
            })
        );
        assert_eq!(
            parse_command(&args(&["provision", "--keep-pki"])),
            Err("--keep-pki requires `obs provision --clean-rerun`".to_owned())
        );
    }

    #[test]
    fn driver_requires_a_value() {
        assert_eq!(
            parse_command(&args(&["--driver"])),
            Err("--driver requires a value".to_owned())
        );
        assert_eq!(
            parse_command(&args(&["--driver="])),
            Err("unsupported option: --driver=".to_owned())
        );
    }

    #[test]
    fn verify_runtime_accepts_only_skip_hash() {
        assert_eq!(
            parse_command(&args(&["--verify-runtime"])),
            Ok(CommandLine::VerifyRuntime { skip_hash: false })
        );
        assert_eq!(
            parse_command(&args(&["--verify-runtime", "--skip-hash"])),
            Ok(CommandLine::VerifyRuntime { skip_hash: true })
        );
        assert_eq!(
            parse_command(&args(&["--skip-hash", "--verify-runtime"])),
            Ok(CommandLine::VerifyRuntime { skip_hash: true })
        );
        assert_eq!(
            parse_command(&args(&["--verify-runtime", "--dry-run"])),
            Err("--verify-runtime may be combined only with --skip-hash".to_owned())
        );
    }
}
