//! Seamless local demo lifecycle — `obs demo up|run|down`.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::{dogfood, err, info, ok, step, warn};

const REGISTRY_FINGERPRINT: &str =
    "fed07f6a1c5780db7cfc276f1350eaae4df2d7c870424b9e3da8b11aec9c02b8";
const POLICY_FILE: &str = "policy-temporal-activity-worker-dev.yaml";
const TEMPORAL_VERSION: &str = "1.8.2";

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DemoCommand {
    Up {
        clean: bool,
        demo_root: Option<String>,
    },
    Run {
        scenario: ScenarioSelection,
    },
    Down {
        stack: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ScenarioSelection {
    G1,
    G2,
    G3,
    G4,
    All,
}

impl ScenarioSelection {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "g1" => Ok(Self::G1),
            "g2" => Ok(Self::G2),
            "g3" => Ok(Self::G3),
            "g4" => Ok(Self::G4),
            "all" => Ok(Self::All),
            _ => Err(format!(
                "unsupported demo scenario: {value} (use g1|g2|g3|g4|all)"
            )),
        }
    }

    fn scenarios(self) -> Vec<Scenario> {
        match self {
            Self::G1 => vec![Scenario::G1],
            Self::G2 => vec![Scenario::G2],
            Self::G3 => vec![Scenario::G3],
            Self::G4 => vec![Scenario::G4],
            Self::All => vec![Scenario::G1, Scenario::G2, Scenario::G3, Scenario::G4],
        }
    }
}

#[derive(Clone, Copy)]
enum Scenario {
    G1,
    G2,
    G3,
    G4,
}

impl Scenario {
    fn name(self) -> &'static str {
        match self {
            Self::G1 => "g1",
            Self::G2 => "g2",
            Self::G3 => "g3",
            Self::G4 => "g4",
        }
    }
}

pub(crate) fn parse(args: &[String]) -> Result<DemoCommand, String> {
    let Some(subcommand) = args.first().map(String::as_str) else {
        return Err("usage: obs demo <up|run|down> [OPTIONS]".to_owned());
    };
    match subcommand {
        "up" => {
            let mut clean = false;
            let mut demo_root = None;
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "--clean" => clean = true,
                    "--demo-root" => {
                        index += 1;
                        let value = args
                            .get(index)
                            .filter(|value| !value.starts_with('-'))
                            .ok_or_else(|| "--demo-root requires a path".to_owned())?;
                        demo_root = Some(value.clone());
                    }
                    value if value.starts_with("--demo-root=") => {
                        let value = value.trim_start_matches("--demo-root=");
                        if value.is_empty() {
                            return Err("--demo-root requires a path".to_owned());
                        }
                        demo_root = Some(value.to_owned());
                    }
                    value => return Err(format!("unsupported option for `obs demo up`: {value}")),
                }
                index += 1;
            }
            Ok(DemoCommand::Up { clean, demo_root })
        }
        "run" => {
            let mut scenario = ScenarioSelection::All;
            let mut index = 1;
            while index < args.len() {
                match args[index].as_str() {
                    "--scenario" => {
                        index += 1;
                        let value = args
                            .get(index)
                            .filter(|value| !value.starts_with('-'))
                            .ok_or_else(|| "--scenario requires g1|g2|g3|g4|all".to_owned())?;
                        scenario = ScenarioSelection::parse(value)?;
                    }
                    value if value.starts_with("--scenario=") => {
                        scenario =
                            ScenarioSelection::parse(value.trim_start_matches("--scenario="))?;
                    }
                    value => {
                        return Err(format!("unsupported option for `obs demo run`: {value}"));
                    }
                }
                index += 1;
            }
            Ok(DemoCommand::Run { scenario })
        }
        "down" => {
            let mut stack = false;
            for arg in &args[1..] {
                match arg.as_str() {
                    "--stack" => stack = true,
                    value => {
                        return Err(format!("unsupported option for `obs demo down`: {value}"));
                    }
                }
            }
            Ok(DemoCommand::Down { stack })
        }
        value => Err(format!("unknown `obs demo` subcommand: {value}")),
    }
}

pub(crate) fn run(command: DemoCommand) -> ExitCode {
    match command {
        DemoCommand::Up { clean, demo_root } => run_up(clean, demo_root),
        DemoCommand::Run { scenario } => run_scenarios(scenario),
        DemoCommand::Down { stack } => run_down(stack),
    }
}

fn run_up(clean: bool, demo_root: Option<String>) -> ExitCode {
    step("DEMO UP");
    let paths = match LocalPaths::resolve() {
        Ok(paths) => paths,
        Err(reason) => return failure(&reason),
    };

    let reprovisioned = clean || !stack_is_up(&paths);
    if reprovisioned {
        info(if clean {
            "clean demo requested — reprovisioning with --clean-rerun"
        } else {
            "stack is not ready — provisioning"
        });
        if dogfood::run_provision(clean, false) != ExitCode::SUCCESS {
            return failure("stack provisioning failed");
        }
    } else {
        ok("gateway and sandbox service already up");
    }

    let repo = match resolve_demo_repo(demo_root.as_deref(), &paths.home) {
        Ok(repo) => repo,
        Err(reason) => return failure(&reason),
    };
    let temporal = match ensure_temporal_cli(&paths) {
        Ok(path) => path,
        Err(reason) => return failure(&reason),
    };
    let agent_env = match read_agent_env(&paths.config_root.join("agent.env")) {
        Ok(values) => values,
        Err(reason) => return failure(&reason),
    };
    if let Err(reason) = ensure_adapter(&paths, &repo, &agent_env, reprovisioned) {
        return failure(&reason);
    }
    let spec = match write_demo_spec(&paths, &repo, &temporal, &agent_env) {
        Ok(spec) => spec,
        Err(reason) => return failure(&reason),
    };
    print_up_status(&paths, &repo, &temporal, &spec, &agent_env);
    ExitCode::SUCCESS
}

fn run_scenarios(selection: ScenarioSelection) -> ExitCode {
    step("DEMO RUN");
    let paths = match LocalPaths::resolve() {
        Ok(paths) => paths,
        Err(reason) => return failure(&reason),
    };
    let spec_path = paths.config_root.join("demo.json");
    let spec = match read_json(&spec_path) {
        Ok(spec) => spec,
        Err(reason) => return failure(&format!("cannot read {}: {reason}", spec_path.display())),
    };
    if spec.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return failure("demo.json has an unsupported schema_version (expected 1)");
    }
    let repo = match spec_path_value(&spec, &["demo", "repo"]) {
        Ok(path) => path,
        Err(reason) => return failure(&reason),
    };
    if let Err(reason) = validate_demo_repo(&repo) {
        return failure(&reason);
    }
    let evidence_dir = match spec_path_value(&spec, &["demo", "evidence_dir"]) {
        Ok(path) => path,
        Err(reason) => return failure(&reason),
    };
    if let Err(error) = fs::create_dir_all(&evidence_dir) {
        return failure(&format!(
            "cannot create evidence directory {}: {error}",
            evidence_dir.display()
        ));
    }
    let temporal = spec
        .pointer("/demo/temporal_cli")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(find_temporal_on_path);

    let mut results = Vec::new();
    let mut any_failed = false;
    for scenario in selection.scenarios() {
        if matches!(scenario, Scenario::G3) && llm_key(&spec).is_none() {
            println!("SKIP g3 (no LLM key)");
            results.push(ScenarioResult::skipped("g3"));
            continue;
        }
        let result = run_one_scenario(
            scenario,
            &spec,
            &spec_path,
            &repo,
            &evidence_dir,
            temporal.as_deref(),
            &paths,
        );
        any_failed |= !result.passed;
        results.push(result);
    }
    print_results(&results);
    if any_failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn run_one_scenario(
    scenario: Scenario,
    spec: &Value,
    spec_path: &Path,
    repo: &Path,
    evidence_dir: &Path,
    temporal: Option<&Path>,
    paths: &LocalPaths,
) -> ScenarioResult {
    let name = scenario.name();
    let evidence = evidence_dir.join(format!("evidence-{name}.json"));
    let _ = fs::remove_file(&evidence);
    let timestamp = unix_timestamp();
    let log_path = evidence_dir.join(format!("run-{name}-{timestamp}.log"));
    info(&format!("{name}: log -> {}", log_path.display()));

    let mut temporal_server = None;
    if matches!(scenario, Scenario::G4) {
        let Some(cli) = temporal else {
            err("g4: temporal CLI is not configured or on PATH");
            return ScenarioResult::failed(name, &evidence);
        };
        match start_temporal_dev(cli, paths) {
            Ok(child) => temporal_server = Some(child),
            Err(reason) => {
                err(&format!("g4: {reason}"));
                return ScenarioResult::failed(name, &evidence);
            }
        }
    }

    let mut command = Command::new("uv");
    command
        .current_dir(repo)
        .args([
            "run",
            "--package",
            "temporal-constrain-poc",
            "python",
            "-m",
            "temporal_constrain_poc.run_poc",
            "--spec",
        ])
        .arg(spec_path)
        .arg("--evidence")
        .arg(&evidence)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match scenario {
        Scenario::G1 | Scenario::G3 => {}
        Scenario::G2 => {
            command.args(["--record-count", "50000"]);
        }
        Scenario::G4 => {
            command.args(["--external-temporal-target", "localhost:7233"]);
        }
    }
    if let Some(cli) = temporal {
        prepend_path(&mut command, cli.parent().unwrap_or_else(|| Path::new(".")));
    }
    if matches!(scenario, Scenario::G3) {
        if let Some(key) = llm_key(spec) {
            command.env("OPENAI_API_KEY", key);
        }
        command.env(
            "OPENBOX_DEMO_LLM_MODEL",
            spec.pointer("/llm/model")
                .and_then(Value::as_str)
                .unwrap_or("gpt-4o"),
        );
    }

    let status = tee_command(&mut command, &log_path);
    drop(temporal_server);
    let child_passed = match status {
        Ok(status) => status.success(),
        Err(reason) => {
            err(&format!("{name}: {reason}"));
            false
        }
    };
    let evidence_json = read_json(&evidence).ok();
    let evidence_passed = evidence_json
        .as_ref()
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        == Some("passed");
    if child_passed && !evidence_passed {
        err(&format!(
            "{name}: evidence is missing, invalid, or does not report status=passed"
        ));
    }
    let verdict = evidence_json
        .as_ref()
        .and_then(|value| value.pointer("/mock_core/pre_workflow_decision/verdict"))
        .and_then(Value::as_str)
        .unwrap_or("-")
        .to_owned();
    let disposition = evidence_json
        .as_ref()
        .and_then(|value| value.pointer("/execution/disposition"))
        .and_then(Value::as_str)
        .map(short_disposition)
        .unwrap_or("-")
        .to_owned();
    ScenarioResult {
        name,
        verdict,
        disposition,
        passed: child_passed && evidence_passed,
        skipped: false,
    }
}

fn run_down(stack: bool) -> ExitCode {
    step("DEMO DOWN");
    let paths = match LocalPaths::resolve() {
        Ok(paths) => paths,
        Err(reason) => return failure(&reason),
    };
    let mut failed = false;
    if let Err(reason) = stop_owned_process(
        &paths.demo_dir.join("adapter.pid"),
        "adapter",
        "openbox_sandbox.runtime_client.agent_server",
    ) {
        err(&reason);
        failed = true;
    }
    let _ = fs::remove_file(paths.demo_dir.join("adapter.sock"));
    if let Err(reason) = stop_owned_process(
        &paths.demo_dir.join("temporal-dev.pid"),
        "Temporal dev server",
        "temporal server start-dev",
    ) {
        err(&reason);
        failed = true;
    }
    if stack && dogfood::run_teardown() != ExitCode::SUCCESS {
        failed = true;
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ok(if stack {
            "demo and provisioned stack are down"
        } else {
            "demo processes are down"
        });
        ExitCode::SUCCESS
    }
}

pub(crate) fn print_status() {
    let Ok(paths) = LocalPaths::resolve() else {
        warn("demo status unavailable: HOME is not set");
        return;
    };
    let adapter_pid = read_pid(&paths.demo_dir.join("adapter.pid"));
    let adapter_socket = paths.demo_dir.join("adapter.sock");
    if adapter_pid.is_some_and(process_alive) && adapter_socket.exists() {
        ok(&format!(
            "demo adapter: up pid={} socket={}",
            adapter_pid.unwrap_or_default(),
            adapter_socket.display()
        ));
    } else {
        warn(&format!(
            "demo adapter: down socket={}",
            adapter_socket.display()
        ));
    }
    let core = paths.state_root.join("demo-core-identity");
    let core_complete = ["poc-ca.crt", "core.crt", "core.key"]
        .iter()
        .all(|name| core.join(name).is_file());
    status_presence("demo Core identity", &core, core_complete);

    let registry = paths.state_root.join("demo-registry");
    let policy = registry.join(POLICY_FILE);
    if policy.is_file() {
        match file_sha256(&policy) {
            Ok(sha) => ok(&format!(
                "demo registry: {} sha256={sha}",
                registry.display()
            )),
            Err(reason) => warn(&format!("demo registry: present, hash failed: {reason}")),
        }
    } else {
        warn(&format!("demo registry: missing -> {}", registry.display()));
    }

    let spec = read_json(&paths.config_root.join("demo.json")).ok();
    let model = spec
        .as_ref()
        .and_then(|value| value.pointer("/llm/model"))
        .and_then(Value::as_str)
        .unwrap_or("gpt-4o");
    let key = spec
        .as_ref()
        .and_then(|value| value.pointer("/llm/api_key_file"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .unwrap_or_else(|| paths.home.join(".config/openbox/openai.key"));
    info(&format!(
        "LLM: key={} model={model}",
        if key.is_file() { "present" } else { "missing" }
    ));
    let temporal = spec
        .as_ref()
        .and_then(|value| value.pointer("/demo/temporal_cli"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .filter(|path| path.is_file())
        .or_else(find_temporal_on_path);
    match temporal {
        Some(path) => ok(&format!("temporal CLI: {}", path.display())),
        None => warn("temporal CLI: not found"),
    }
}

struct LocalPaths {
    home: PathBuf,
    state_root: PathBuf,
    config_root: PathBuf,
    demo_dir: PathBuf,
}

impl LocalPaths {
    fn resolve() -> Result<Self, String> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| "HOME is not set".to_owned())?;
        let state_root = std::env::var_os("OPENBOX_STATE_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/state/openbox-sandbox"));
        let config_root = std::env::var_os("OPENBOX_CONFIG_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config/openbox-sandbox"));
        let state_root = absolute_path(&state_root)?;
        let config_root = absolute_path(&config_root)?;
        let demo_dir = state_root.join("demo");
        Ok(Self {
            home,
            state_root,
            config_root,
            demo_dir,
        })
    }
}

fn stack_is_up(paths: &LocalPaths) -> bool {
    let pid = read_pid(&paths.state_root.join("sandbox-service.pid"));
    let port = read_service_port(&paths.config_root.join("service.json")).unwrap_or(17443);
    pid.is_some_and(process_alive) && tcp_open(port)
}

fn resolve_demo_repo(option: Option<&str>, home: &Path) -> Result<PathBuf, String> {
    let source = std::env::var_os("OPENBOX_DEMO_REPO")
        .map(PathBuf::from)
        .or_else(|| option.map(PathBuf::from))
        .unwrap_or_else(|| home.join("openbox-demo/poc"));
    let path = absolute_path(&source)?;
    validate_demo_repo(&path)?;
    fs::canonicalize(&path)
        .map_err(|error| format!("cannot resolve demo repo {}: {error}", path.display()))
}

fn validate_demo_repo(path: &Path) -> Result<(), String> {
    let pyproject = path.join("pyproject.toml");
    let valid = fs::read_to_string(&pyproject)
        .map(|body| body.contains("temporal-constrain-poc"))
        .unwrap_or(false);
    if valid {
        Ok(())
    } else {
        Err(format!(
            "demo repo is not a pinned temporal-constrain-poc checkout: {}\n  accepted sources (in precedence order): OPENBOX_DEMO_REPO, `obs demo up --demo-root PATH`, or ~/openbox-demo/poc\n  the selected directory must contain pyproject.toml with temporal-constrain-poc",
            path.display()
        ))
    }
}

fn ensure_temporal_cli(paths: &LocalPaths) -> Result<PathBuf, String> {
    if let Some(explicit) = std::env::var_os("TEMPORAL_CLI_PATH") {
        let path = absolute_path(&PathBuf::from(explicit))?;
        verify_temporal(&path)?;
        return canonical_or_absolute(&path);
    }
    if let Some(path) = find_temporal_on_path() {
        verify_temporal(&path)?;
        return canonical_or_absolute(&path);
    }

    let asset = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "temporal_cli_1.8.2_linux_amd64.tar.gz",
        ("macos", "aarch64") => "temporal_cli_1.8.2_darwin_arm64.tar.gz",
        (os, arch) => {
            return Err(format!(
                "no Temporal CLI release asset configured for {os}/{arch}; set TEMPORAL_CLI_PATH"
            ));
        }
    };
    let bin_dir = paths.home.join(".local/bin");
    fs::create_dir_all(&bin_dir)
        .map_err(|error| format!("cannot create {}: {error}", bin_dir.display()))?;
    let temp = paths
        .demo_dir
        .join(format!("temporal-download-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp)
        .map_err(|error| format!("cannot create {}: {error}", temp.display()))?;
    let archive = temp.join(asset);
    let url =
        format!("https://github.com/temporalio/cli/releases/download/v{TEMPORAL_VERSION}/{asset}");
    info(&format!(
        "downloading Temporal CLI {TEMPORAL_VERSION} from {url}"
    ));
    command_success(
        Command::new("curl")
            .args([
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--output",
            ])
            .arg(&archive)
            .arg(&url),
        "Temporal CLI download",
    )?;
    command_success(
        Command::new("tar")
            .arg("-xzf")
            .arg(&archive)
            .arg("-C")
            .arg(&temp),
        "Temporal CLI extraction",
    )?;
    let extracted = temp.join("temporal");
    if !extracted.is_file() {
        return Err(format!(
            "Temporal CLI archive did not contain {}",
            extracted.display()
        ));
    }
    let destination = bin_dir.join("temporal");
    fs::copy(&extracted, &destination)
        .map_err(|error| format!("cannot install {}: {error}", destination.display()))?;
    set_mode(&destination, 0o755)?;
    let _ = fs::remove_dir_all(&temp);
    verify_temporal(&destination)?;
    canonical_or_absolute(&destination)
}

fn verify_temporal(path: &Path) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("Temporal CLI is not a file: {}", path.display()));
    }
    let output = Command::new(path)
        .arg("--version")
        .output()
        .map_err(|error| format!("cannot run {} --version: {error}", path.display()))?;
    let version = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() || version.trim().is_empty() {
        return Err(format!(
            "{} --version did not print a version",
            path.display()
        ));
    }
    ok(&format!(
        "temporal CLI: {} ({})",
        path.display(),
        version.trim()
    ));
    Ok(())
}

fn ensure_adapter(
    paths: &LocalPaths,
    repo: &Path,
    agent_env: &HashMap<String, String>,
    force_restart: bool,
) -> Result<(), String> {
    fs::create_dir_all(&paths.demo_dir)
        .map_err(|error| format!("cannot create {}: {error}", paths.demo_dir.display()))?;
    set_mode(&paths.demo_dir, 0o700)?;
    let pid_file = paths.demo_dir.join("adapter.pid");
    let socket = paths.demo_dir.join("adapter.sock");
    if !force_restart && read_pid(&pid_file).is_some_and(process_alive) && socket.exists() {
        ok("adapter already up");
        return Ok(());
    }
    if force_restart && read_pid(&pid_file).is_some_and(process_alive) {
        info("restarting adapter to load freshly provisioned TLS credentials");
    }
    stop_owned_process(
        &pid_file,
        "adapter",
        "openbox_sandbox.runtime_client.agent_server",
    )?;
    let _ = fs::remove_file(&socket);

    let service_config = env_path(agent_env, "OPENBOX_SANDBOX_CONFIG_PATH")?;
    let ca = env_path(agent_env, "OPENBOX_SANDBOX_CA")?;
    let certificate = env_path(agent_env, "OPENBOX_SANDBOX_CERT")?;
    let private_key = env_path(agent_env, "OPENBOX_SANDBOX_KEY")?;
    let log_path = paths.demo_dir.join("adapter.log");
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("cannot open {}: {error}", log_path.display()))?;
    let stderr = stdout
        .try_clone()
        .map_err(|error| format!("cannot clone adapter log: {error}"))?;
    let mut child = Command::new("uv")
        .current_dir(repo)
        .args([
            "run",
            "--package",
            "temporal-constrain-poc",
            "python",
            "-m",
            "openbox_sandbox.runtime_client.agent_server",
            "serve",
            "--service-config",
        ])
        .arg(service_config)
        .arg("--socket")
        .arg(&socket)
        .arg("--registry-fingerprint")
        .arg(REGISTRY_FINGERPRINT)
        .arg("--ca")
        .arg(ca)
        .arg("--certificate")
        .arg(certificate)
        .arg("--private-key")
        .arg(private_key)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("cannot start adapter with uv: {error}"))?;
    fs::write(&pid_file, format!("{}\n", child.id()))
        .map_err(|error| format!("cannot write {}: {error}", pid_file.display()))?;
    set_mode(&pid_file, 0o600)?;
    for _ in 0..80 {
        if socket.exists() {
            ok(&format!(
                "adapter up (pid={}, socket={})",
                child.id(),
                socket.display()
            ));
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("cannot check adapter: {error}"))?
        {
            let _ = fs::remove_file(&pid_file);
            return Err(format!(
                "adapter exited with {status}; log tail:\n{}",
                tail(&log_path, 30)
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&pid_file);
    Err(format!(
        "adapter did not create its socket within 20s; log tail:\n{}",
        tail(&log_path, 30)
    ))
}

fn write_demo_spec(
    paths: &LocalPaths,
    repo: &Path,
    temporal: &Path,
    agent_env: &HashMap<String, String>,
) -> Result<Value, String> {
    let evidence_dir = paths.demo_dir.clone();
    fs::create_dir_all(&evidence_dir)
        .map_err(|error| format!("cannot create {}: {error}", evidence_dir.display()))?;
    set_mode(&evidence_dir, 0o700)?;
    let service_config = env_path(agent_env, "OPENBOX_SANDBOX_CONFIG_PATH")?;
    let service_ca = env_path(agent_env, "OPENBOX_SANDBOX_CA")?;
    let registry = paths.state_root.join("demo-registry");
    let policy = registry.join(POLICY_FILE);
    if !policy.is_file() {
        return Err(format!(
            "demo policy registry is incomplete at {}; run `obs provision`",
            policy.display()
        ));
    }
    let policy_sha = file_sha256(&policy)?;
    let core = paths.state_root.join("demo-core-identity");
    for name in ["poc-ca.crt", "core.crt", "core.key"] {
        if !core.join(name).is_file() {
            return Err(format!(
                "demo Core identity is incomplete at {}; run `obs provision`",
                core.display()
            ));
        }
    }
    let model = std::env::var("OPENBOX_DEMO_LLM_MODEL").unwrap_or_else(|_| "gpt-4o".to_owned());
    let key = paths.home.join(".config/openbox/openai.key");
    let mut llm = serde_json::Map::new();
    if key.is_file() {
        llm.insert("api_key_file".to_owned(), json!(absolute_path(&key)?));
    }
    llm.insert("model".to_owned(), json!(model));
    let spec = json!({
        "schema_version": 1,
        "service": {
            "config": canonical_or_absolute(&service_config)?,
            "ca": canonical_or_absolute(&service_ca)?,
        },
        "adapter": {
            "socket": paths.demo_dir.join("adapter.sock"),
            "pid_file": paths.demo_dir.join("adapter.pid"),
        },
        "core_identity": {
            "ca": canonical_or_absolute(&core.join("poc-ca.crt"))?,
            "certificate": canonical_or_absolute(&core.join("core.crt"))?,
            "private_key": canonical_or_absolute(&core.join("core.key"))?,
        },
        "policy_registry": {
            "directory": canonical_or_absolute(&registry)?,
            "policy_file": POLICY_FILE,
            "policy_sha256": policy_sha,
            "fingerprint": REGISTRY_FINGERPRINT,
        },
        "llm": Value::Object(llm),
        "demo": {
            "repo": canonical_or_absolute(repo)?,
            "evidence_dir": canonical_or_absolute(&evidence_dir)?,
            "console_otel": true,
            "temporal_cli": canonical_or_absolute(temporal)?,
        },
    });
    let path = paths.config_root.join("demo.json");
    fs::create_dir_all(&paths.config_root)
        .map_err(|error| format!("cannot create {}: {error}", paths.config_root.display()))?;
    let temp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(&spec).map_err(|error| error.to_string())?;
    fs::write(&temp, [body.as_slice(), b"\n"].concat())
        .map_err(|error| format!("cannot write {}: {error}", temp.display()))?;
    set_mode(&temp, 0o600)?;
    fs::rename(&temp, &path)
        .map_err(|error| format!("cannot finalize {}: {error}", path.display()))?;
    ok(&format!("demo run-spec written: {}", path.display()));
    Ok(spec)
}

fn print_up_status(
    paths: &LocalPaths,
    repo: &Path,
    temporal: &Path,
    spec: &Value,
    agent_env: &HashMap<String, String>,
) {
    println!("\nDemo ready");
    println!(
        "  gateway       {}",
        agent_env
            .get("OPENBOX_GATEWAY_ENDPOINT")
            .map(String::as_str)
            .unwrap_or("unknown")
    );
    println!(
        "  service       {}",
        agent_env
            .get("OPENBOX_SANDBOX_ENDPOINT")
            .map(String::as_str)
            .unwrap_or("unknown")
    );
    println!(
        "  adapter       {}",
        paths.demo_dir.join("adapter.sock").display()
    );
    println!(
        "  registry      {}",
        paths.state_root.join("demo-registry").display()
    );
    println!("  temporal CLI  {}", temporal.display());
    println!("  demo repo     {}", repo.display());
    println!(
        "  LLM            key={} model={}",
        if spec.pointer("/llm/api_key_file").is_some() {
            "present"
        } else {
            "missing (g3 will skip)"
        },
        spec.pointer("/llm/model")
            .and_then(Value::as_str)
            .unwrap_or("gpt-4o")
    );
}

struct TemporalDev {
    child: Child,
    pid_file: PathBuf,
}

impl Drop for TemporalDev {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.pid_file);
    }
}

fn start_temporal_dev(cli: &Path, paths: &LocalPaths) -> Result<TemporalDev, String> {
    let pid_file = paths.demo_dir.join("temporal-dev.pid");
    stop_owned_process(
        &pid_file,
        "Temporal dev server",
        "temporal server start-dev",
    )?;
    if tcp_open(7233) {
        return Err("port 7233 is already occupied; refusing to use an unowned server".to_owned());
    }
    let log_path = paths.demo_dir.join("temporal-dev.log");
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|error| format!("cannot open {}: {error}", log_path.display()))?;
    let stderr = stdout
        .try_clone()
        .map_err(|error| format!("cannot clone Temporal log: {error}"))?;
    let mut child = Command::new(cli)
        .args(["server", "start-dev", "--port", "7233"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("cannot start Temporal dev server: {error}"))?;
    fs::write(&pid_file, format!("{}\n", child.id()))
        .map_err(|error| format!("cannot write {}: {error}", pid_file.display()))?;
    set_mode(&pid_file, 0o600)?;
    for _ in 0..120 {
        if tcp_open(7233) {
            ok(&format!("Temporal dev server up (pid={})", child.id()));
            return Ok(TemporalDev { child, pid_file });
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("cannot check Temporal dev server: {error}"))?
        {
            let _ = fs::remove_file(&pid_file);
            return Err(format!(
                "Temporal dev server exited with {status}; log tail:\n{}",
                tail(&log_path, 30)
            ));
        }
        thread::sleep(Duration::from_millis(250));
    }
    let _ = child.kill();
    let _ = child.wait();
    let _ = fs::remove_file(&pid_file);
    Err(format!(
        "Temporal dev server did not listen on 7233; log tail:\n{}",
        tail(&log_path, 30)
    ))
}

struct ScenarioResult {
    name: &'static str,
    verdict: String,
    disposition: String,
    passed: bool,
    skipped: bool,
}

impl ScenarioResult {
    fn failed(name: &'static str, _evidence: &Path) -> Self {
        Self {
            name,
            verdict: "-".to_owned(),
            disposition: "-".to_owned(),
            passed: false,
            skipped: false,
        }
    }

    fn skipped(name: &'static str) -> Self {
        Self {
            name,
            verdict: "-".to_owned(),
            disposition: "-".to_owned(),
            passed: true,
            skipped: true,
        }
    }
}

fn print_results(results: &[ScenarioResult]) {
    println!("\nscenario  verdict    disposition  result");
    println!("--------  ---------  -----------  ------");
    for result in results {
        println!(
            "{:<8}  {:<9}  {:<11}  {}",
            result.name,
            result.verdict,
            result.disposition,
            if result.skipped {
                "SKIP"
            } else if result.passed {
                "PASS"
            } else {
                "FAIL"
            }
        );
    }
}

fn tee_command(command: &mut Command, log_path: &Path) -> Result<std::process::ExitStatus, String> {
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start POC runner: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "runner stdout unavailable".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "runner stderr unavailable".to_owned())?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|error| format!("cannot open {}: {error}", log_path.display()))?;
    let log = Arc::new(Mutex::new(log));
    let stdout_log = Arc::clone(&log);
    let stdout_thread = thread::spawn(move || tee_stream(stdout, false, stdout_log));
    let stderr_thread = thread::spawn(move || tee_stream(stderr, true, log));
    let status = child
        .wait()
        .map_err(|error| format!("cannot wait for POC runner: {error}"))?;
    stdout_thread
        .join()
        .map_err(|_| "stdout tee thread panicked".to_owned())?
        .map_err(|error| format!("stdout tee failed: {error}"))?;
    stderr_thread
        .join()
        .map_err(|_| "stderr tee thread panicked".to_owned())?
        .map_err(|error| format!("stderr tee failed: {error}"))?;
    Ok(status)
}

fn tee_stream<R: Read>(reader: R, stderr: bool, log: Arc<Mutex<File>>) -> io::Result<()> {
    let mut reader = BufReader::new(reader);
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        if reader.read_until(b'\n', &mut buffer)? == 0 {
            break;
        }
        if stderr {
            io::stderr().write_all(&buffer)?;
            io::stderr().flush()?;
        } else {
            io::stdout().write_all(&buffer)?;
            io::stdout().flush()?;
        }
        let mut file = log
            .lock()
            .map_err(|_| io::Error::other("log mutex poisoned"))?;
        file.write_all(&buffer)?;
        file.flush()?;
    }
    Ok(())
}

fn llm_key(spec: &Value) -> Option<String> {
    let path = spec
        .pointer("/llm/api_key_file")
        .and_then(Value::as_str)
        .map(PathBuf::from)?;
    let value = fs::read_to_string(path).ok()?;
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

fn spec_path_value(spec: &Value, keys: &[&str]) -> Result<PathBuf, String> {
    let pointer = format!("/{}", keys.join("/"));
    spec.pointer(&pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("demo.json is missing {pointer}"))
}

fn short_disposition(value: &str) -> &str {
    match value {
        "executed_in_sandbox" | "sandbox" => "sandbox",
        "executed_on_host" | "host" => "host",
        other => other,
    }
}

fn prepend_path(command: &mut Command, directory: &Path) {
    let mut paths = vec![directory.to_path_buf()];
    if let Some(current) = std::env::var_os("PATH") {
        paths.extend(std::env::split_paths(&current));
    }
    if let Ok(joined) = std::env::join_paths(paths) {
        command.env("PATH", joined);
    }
}

fn stop_owned_process(pid_file: &Path, label: &str, marker: &str) -> Result<(), String> {
    let Some(pid) = read_pid(pid_file) else {
        let _ = fs::remove_file(pid_file);
        return Ok(());
    };
    if !process_alive(pid) {
        let _ = fs::remove_file(pid_file);
        return Ok(());
    }
    let command_line = process_command(pid).unwrap_or_default();
    if !command_line.contains(marker) {
        return Err(format!(
            "{label} pid {pid} does not contain ownership marker '{marker}'; refusing to signal it"
        ));
    }
    info(&format!("stopping {label} pid={pid}"));
    let _ = Command::new("kill").arg(pid.to_string()).status();
    for _ in 0..40 {
        if !process_alive(pid) {
            let _ = fs::remove_file(pid_file);
            return Ok(());
        }
        thread::sleep(Duration::from_millis(125));
    }
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    let _ = fs::remove_file(pid_file);
    Ok(())
}

fn process_command(pid: i32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-ww", "-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn process_alive(pid: i32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn read_pid(path: &Path) -> Option<i32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn read_agent_env(path: &Path) -> Result<HashMap<String, String>, String> {
    let body = fs::read_to_string(path).map_err(|error| {
        format!(
            "cannot read {}: {error}; run `obs provision`",
            path.display()
        )
    })?;
    let mut values = HashMap::new();
    for (index, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("{} line {} is not KEY=VALUE", path.display(), index + 1))?;
        values.insert(key.to_owned(), value.to_owned());
    }
    Ok(values)
}

fn env_path(values: &HashMap<String, String>, key: &str) -> Result<PathBuf, String> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| format!("agent.env is missing {key}"))
}

fn read_service_port(path: &Path) -> Option<u16> {
    let value = read_json(path).ok()?;
    value
        .get("bind_address")?
        .as_str()?
        .rsplit_once(':')?
        .1
        .parse()
        .ok()
}

fn tcp_open(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddr::from(([127, 0, 0, 1], port)),
        Duration::from_millis(250),
    )
    .is_ok()
}

fn find_temporal_on_path() -> Option<PathBuf> {
    find_on_path("temporal")
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| canonical_or_absolute(&candidate).ok())
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let mut command = if cfg!(target_os = "macos") {
        let mut command = Command::new("shasum");
        command.args(["-a", "256"]);
        command
    } else {
        Command::new("sha256sum")
    };
    let output = command
        .arg(path)
        .output()
        .map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!("cannot hash {}: command failed", path.display()));
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .filter(|value| value.len() == 64)
        .map(str::to_owned)
        .ok_or_else(|| format!("cannot parse sha256 for {}", path.display()))
}

fn command_success(command: &mut Command, label: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("{label} failed to start: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{label} exited with {status}"))
    }
}

fn read_json(path: &Path) -> Result<Value, String> {
    let body = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&body).map_err(|error| error.to_string())
}

fn absolute_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|error| format!("cannot resolve {}: {error}", path.display()))
    }
}

fn canonical_or_absolute(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path).or_else(|_| absolute_path(path))
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("cannot chmod {}: {error}", path.display()))?;
    }
    let _ = mode;
    Ok(())
}

fn tail(path: &Path, lines: usize) -> String {
    let Ok(body) = fs::read_to_string(path) else {
        return "(log unavailable)".to_owned();
    };
    let all: Vec<_> = body.lines().collect();
    all[all.len().saturating_sub(lines)..].join("\n")
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn status_presence(label: &str, path: &Path, present: bool) {
    if present {
        ok(&format!("{label}: {}", path.display()));
    } else {
        warn(&format!("{label}: missing -> {}", path.display()));
    }
}

fn failure(message: &str) -> ExitCode {
    err(message);
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::{parse, DemoCommand, ScenarioSelection};

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_demo_commands() {
        assert_eq!(
            parse(&args(&["up", "--clean", "--demo-root", "/demo"])),
            Ok(DemoCommand::Up {
                clean: true,
                demo_root: Some("/demo".to_owned())
            })
        );
        assert_eq!(
            parse(&args(&["run", "--scenario=g3"])),
            Ok(DemoCommand::Run {
                scenario: ScenarioSelection::G3
            })
        );
        assert_eq!(
            parse(&args(&["down", "--stack"])),
            Ok(DemoCommand::Down { stack: true })
        );
    }

    #[test]
    fn demo_run_defaults_to_all() {
        assert_eq!(
            parse(&args(&["run"])),
            Ok(DemoCommand::Run {
                scenario: ScenarioSelection::All
            })
        );
    }

    #[test]
    fn rejects_invalid_scenario() {
        assert!(parse(&args(&["run", "--scenario", "g5"])).is_err());
    }
}
