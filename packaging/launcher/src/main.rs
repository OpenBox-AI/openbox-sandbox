//! openbox-sandbox launcher.
//!
//! A thin launcher that locates, pins, and runs externally-provided OpenBox and
//! OpenShell artifacts. It is NOT a self-contained binary: the operator must
//! install or fetch the pinned OpenShell release (via `brew install openshell`
//! or `scripts/fetch-openshell-deps.sh`) before running the launcher.
//!
//! OpenShell supports four drivers; the launcher detects what is present:
//!   - podman: rootless container runtime (preferred container path).
//!   - docker: container runtime with a root daemon.
//!   - kubernetes: delegates sandboxes to a cluster.
//!   - vm: libkrun microVM (KVM on Linux, Hypervisor.framework on macOS); self-contained, needs only a hypervisor.
//!
//! Platform behavior:
//!   - Linux: any driver; container path uses Landlock (strict) or best_effort.
//!   - macOS: the microVM driver is the real target; container drivers are degraded and need consent.
//!   - Windows: unsupported directly; run inside WSL2.
//!
//! Detection, driver selection, posture, artifact resolution, and gateway
//! launch are implemented. Artifacts are resolved from `$OPENBOX_BUNDLE_DIR`, a
//! platform install prefix, `PATH`, or the in-repo build (see bundle.rs).

use std::path::Path;
use std::process::{Command, ExitCode};

mod bundle;
mod pin;

/// One OpenShell compute driver the launcher can select.
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
            Runtime::MicroVm => "libkrun microVM (hardware-isolated, self-contained)",
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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        print_help();
        return ExitCode::SUCCESS;
    }
    let allow_degraded = args.iter().any(|arg| arg == "--allow-degraded");
    let dry_run = args.iter().any(|arg| arg == "--dry-run");
    let requested_key = flag_value(&args, "--driver");

    banner();
    let (os, arch) = platform();
    field("platform", &format!("{os}/{arch}"));

    if os == "windows" {
        windows_guidance();
        return ExitCode::FAILURE;
    }

    let requested = match requested_key.as_deref().map(Runtime::from_key) {
        None => None,
        Some(Some(runtime)) => Some(runtime),
        Some(None) => {
            fail(
                "driver",
                "unknown --driver (use podman|docker|kubernetes|vm)",
            );
            return ExitCode::FAILURE;
        }
    };

    let available: Vec<Runtime> = Runtime::ALL
        .into_iter()
        .filter(|runtime| runtime.available())
        .collect();
    field("runtimes", &runtime_summary(&available));
    if available.is_empty() {
        fail("runtime", "no supported driver is present");
        note("install one of: Podman, Docker, kubectl + a cluster, or a hypervisor");
        note("(KVM on Linux / Hypervisor.framework on macOS) for the microVM driver.");
        return ExitCode::FAILURE;
    }

    let chosen = match requested {
        Some(runtime) if available.contains(&runtime) => runtime,
        Some(runtime) => {
            fail(
                "driver",
                &format!("requested '{}' is not available", runtime.key()),
            );
            return ExitCode::FAILURE;
        }
        None => *priority(os)
            .iter()
            .find(|runtime| available.contains(runtime))
            .expect("a runtime is available"),
    };
    field("driver", chosen.label());

    let posture = match assess(chosen, os, allow_degraded) {
        Some(posture) => posture,
        None => return ExitCode::FAILURE,
    };

    let artifacts = match bundle::resolve() {
        Ok(artifacts) => artifacts,
        Err(missing) => {
            fail(
                "artifacts",
                &format!("required artifact not found: {missing}"),
            );
            note("set OPENBOX_BUNDLE_DIR to a directory holding the OpenShell gateway,");
            note("CLI, and policies, or install OpenShell (brew install openshell).");
            return ExitCode::FAILURE;
        }
    };
    report_artifacts(&artifacts);

    // Dependency pin: refuse to run against an OpenShell whose version/hash
    // does not match the pinned manifest. Version always checked; sha256 only
    // in strict mode (on by default). Override the required version with
    // OPENBOX_SANDBOX_REQUIRED_OPENSHELL_VERSION; skip the hash check with
    // --skip-hash / OPENBOX_SANDBOX_SKIP_ARTIFACT_HASH=1 (e.g. local builds).
    let skip_hash = args.iter().any(|a| a == "--skip-hash")
        || std::env::var("OPENBOX_SANDBOX_SKIP_ARTIFACT_HASH").as_deref() == Ok("1");
    if let Err(err) = pin::verify(&artifacts, !skip_hash) {
        fail("pin", &format!("{} rejected: {}", err.artifact, err.reason));
        note("OpenShell is pinned to a tested version; a mismatch can break the");
        note("sandbox-name / hook contracts. Pin the matching release, or set");
        note("OPENBOX_SANDBOX_REQUIRED_OPENSHELL_VERSION to the installed version.");
        if err.reason.starts_with("version") {
            note("or run packaging/launcher/scripts/fetch-openshell-deps.sh to fetch");
            note("the pinned release.");
        }
        return ExitCode::FAILURE;
    }
    field(
        "pin",
        &format!("openshell {} verified", pin::REQUIRED_VERSION),
    );

    if dry_run {
        plan(os, arch, chosen, posture, &artifacts);
        return ExitCode::SUCCESS;
    }
    launch(chosen, posture, &artifacts)
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
            field("isolation", "microVM (hardware boundary)");
            if os == "macos" {
                note("Runs on Apple Hypervisor.framework with its own guest kernel;");
                note("no container runtime required. This is the supported macOS path.");
            }
            Some(Posture::MicroVm)
        }
        Runtime::Kubernetes => {
            field("isolation", "delegated to the cluster");
            Some(Posture::Cluster)
        }
        Runtime::Podman | Runtime::Docker => match os {
            "linux" => {
                if landlock_available() {
                    field("isolation", "strict (landlock hard_requirement)");
                    Some(Posture::ContainerStrict)
                } else {
                    warn("Landlock is not available on this kernel.");
                    note("Continuing best_effort: namespaces/cgroups/seccomp still apply.");
                    field("isolation", "degraded (best_effort)");
                    Some(Posture::ContainerDegraded)
                }
            }
            "macos" => {
                warn("A container driver on macOS is degraded and NOT recommended.");
                note("It runs inside the runtime's Linux VM where Landlock is absent.");
                note("Prefer --driver vm (libkrun microVM) for real isolation on macOS.");
                if !command_ok(chosen.key(), &["info"]) {
                    fail(chosen.key(), "no reachable connection (is the VM started?)");
                    return None;
                }
                if !allow_degraded {
                    fail("isolation", "refusing degraded run without consent");
                    note("re-run with --allow-degraded, or use --driver vm.");
                    return None;
                }
                field("isolation", "degraded (best_effort, via runtime VM)");
                Some(Posture::ContainerDegraded)
            }
            _ => {
                fail("platform", "unsupported operating system");
                None
            }
        },
    }
}

/// Report the resolved artifact paths so the operator can see exactly what the
/// launcher will run.
fn report_artifacts(artifacts: &bundle::Artifacts) {
    field("gateway", &artifacts.gateway.display().to_string());
    field("cli", &artifacts.cli.display().to_string());
    field("policy", &artifacts.policy(false).display().to_string());
    field("policy(dev)", &artifacts.policy(true).display().to_string());
}

/// Print the concrete plan without starting anything (`--dry-run`).
fn plan(os: &str, arch: &str, chosen: Runtime, posture: Posture, artifacts: &bundle::Artifacts) {
    println!();
    field(
        "PLAN",
        &format!("bootstrap openbox-sandbox for {os}/{arch}"),
    );
    let (degraded, policy) = posture_config(posture);
    note(&format!("1. driver: OPENSHELL_DRIVERS={}", chosen.key()));
    note(&format!("2. gateway: {}", artifacts.gateway.display()));
    note(&format!(
        "3. service config allow_degraded_landlock = {degraded}"
    ));
    note(&format!(
        "4. policy: {}",
        artifacts.policy(policy).display()
    ));
    note("5. generate local mTLS identities on first run");
    note("6. start the OpenShell gateway; then start the openbox-sandbox service");
}

/// Map a posture to (allow_degraded_landlock, use_dev_policy).
fn posture_config(posture: Posture) -> (bool, bool) {
    match posture {
        Posture::ContainerStrict => (false, false),
        Posture::ContainerDegraded => (true, true),
        // The microVM guest kernel has no Landlock, so the floor runs the
        // best_effort tier; the cluster path defers to admission policy.
        Posture::MicroVm => (true, true),
        Posture::Cluster => (false, false),
    }
}

/// Start the OpenShell gateway with the selected driver and wait on it. This is
/// the real bootstrap: it execs the resolved gateway binary in the foreground so
/// the launcher's exit status tracks the gateway's.
fn launch(chosen: Runtime, posture: Posture, artifacts: &bundle::Artifacts) -> ExitCode {
    let (degraded, dev_policy) = posture_config(posture);
    println!();
    field("START", "openbox-sandbox");
    note(&format!(
        "driver={} degraded_landlock={degraded}",
        chosen.key()
    ));
    note(&format!(
        "policy={}",
        artifacts.policy(dev_policy).display()
    ));
    note(&format!("gateway={}", artifacts.gateway.display()));

    let mut command = Command::new(&artifacts.gateway);
    command
        .env("OPENSHELL_DRIVERS", chosen.key())
        .arg("--drivers")
        .arg(chosen.key());
    // The gateway inherits stdio and runs in the foreground; the launcher exits
    // with the gateway's status. Ctrl-C stops both.
    match command.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => {
            fail(
                "gateway",
                &format!("exited with status {}", status.code().unwrap_or(-1)),
            );
            ExitCode::FAILURE
        }
        Err(error) => {
            fail("gateway", &format!("failed to start: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn platform() -> (&'static str, &'static str) {
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

fn windows_guidance() {
    warn("Windows is not a supported direct target.");
    note("Run inside WSL2 (a Linux VM). Install a WSL distro, then run the Linux build there:");
    note("  wsl -d <distro> -- ./openbox-sandbox");
}

fn print_help() {
    println!(
        "openbox-sandbox launcher\n\n\
         USAGE:\n  openbox-sandbox [--driver podman|docker|kubernetes|vm] [--allow-degraded]\n\n\
         Locates, verifies, and runs the pinned OpenShell gateway and driver.\n\
         Artifacts are resolved from $OPENBOX_BUNDLE_DIR, install prefixes,\n\
         PATH, or the in-repo build output (see bundle.rs). A version pin\n\
         guard refuses to run against an unpinned OpenShell.\n\n\
         OPTIONS:\n\
         \x20 --driver <name>    Force a driver instead of auto-selecting.\n\
         \x20 --allow-degraded   Accept reduced isolation (container driver without Landlock).\n\
         \x20 --dry-run          Resolve artifacts and print the plan; start nothing.\n\
         \x20 --skip-hash         Skip the pinned-artifact sha256 check (local builds).\n\
         \x20 -h, --help         Show this help.\n"
    );
}

fn banner() {
    println!("openbox-sandbox launcher");
}

fn field(key: &str, value: &str) {
    println!("  {key:<16} {value}");
}

fn warn(message: &str) {
    println!("  WARN            {message}");
}

fn fail(key: &str, message: &str) {
    println!("  ERROR  {key:<9} {message}");
}

fn note(message: &str) {
    println!("        {message}");
}
