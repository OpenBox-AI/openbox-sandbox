//! Local dogfood lifecycle — `obs provision`, `obs uninstall`, `obs verify`,
//! `obs status`.
//!
//! These source-checkout commands delegate to
//! `packaging/launcher/scripts/provision-local-sandbox.sh` and to the in-crate
//! `live_service_create_exec_delete` integration test:
//!
//! - `obs provision` = teardown, then provision.
//! - `obs uninstall` = teardown, delete wizard-owned state, and exit.
//! - `obs verify` = prove create→ready→exec→delete over mTLS through the root
//!   service and the external `OpenShell` microVM runtime.
//! - `obs status` = report ports, PID files, and generated artifacts.
//!
//! `obs provision` always tears down stale processes first. A clean-state run
//! is explicit with `obs provision --clean-rerun`.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use crate::{err, info, ok, step, warn};

/// Resolve the source repository used by dogfood-only commands.
fn repo_root() -> PathBuf {
    if let Some(root) = std::env::var_os("OPENBOX_SOURCE_ROOT").map(PathBuf::from) {
        return root;
    }
    if let Ok(current) = std::env::current_dir() {
        for candidate in current.ancestors() {
            if candidate.join("Cargo.toml").is_file()
                && candidate
                    .join("packaging/launcher/scripts/provision-local-sandbox.sh")
                    .is_file()
            {
                return candidate.to_path_buf();
            }
        }
    }
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn wizard_script() -> Result<PathBuf, String> {
    crate::scripts::resolve("provision-local-sandbox.sh")
}

/// Auto-acquire the OpenShell bundle when a hosted bundle URL is configured
/// and the target bundle is missing. Reuses the embedded fetch logic so a
/// fresh machine needs only `obs provision` (setup stays the explicit
/// acquire+verify path for operators who want it).
fn auto_fetch_bundle() -> Result<(), ExitCode> {
    let url = std::env::var("OPENBOX_OPENSHELL_BUNDLE_URL").unwrap_or_default();
    if url.is_empty() {
        return Ok(());
    }
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let bundle_dir = std::env::var("OPENSHELL_BUNDLE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| cwd.join("openbox-sandbox-bundle"));
    if bundle_dir.join("bin/openshell-gateway").is_file() {
        // The wizard's default bundle path differs (project-root based); pin
        // the resolved bundle regardless of whether a fetch happened.
        unsafe { std::env::set_var("OPENSHELL_BUNDLE_DIR", &bundle_dir) };
        return Ok(());
    }
    let script = match crate::scripts::resolve("fetch-openshell-deps.sh") {
        Ok(s) => s,
        Err(reason) => {
            err(&format!("fetch-openshell-deps.sh unavailable: {reason}"));
            return Err(ExitCode::FAILURE);
        }
    };
    info("bundle missing — fetching via OPENBOX_OPENSHELL_BUNDLE_URL");
    let status = Command::new("bash")
        .arg(&script)
        .env("OUT", &bundle_dir)
        .current_dir(&cwd)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();
    match status {
        Ok(s) if s.success() => {
            // The wizard must consume exactly this bundle.
            unsafe { std::env::set_var("OPENSHELL_BUNDLE_DIR", &bundle_dir) };
            Ok(())
        }
        Ok(_) => {
            err("bundle fetch failed (see output above)");
            Err(ExitCode::FAILURE)
        }
        Err(e) => {
            err(&format!("bundle fetch failed: {e}"));
            Err(ExitCode::FAILURE)
        }
    }
}

/// `obs provision` — teardown and provision, optionally cleaning state first.
pub fn run_provision(clean_rerun: bool, keep_pki: bool) -> ExitCode {
    if let Err(code) = auto_fetch_bundle() {
        return code;
    }
    let script = match wizard_script() {
        Ok(s) => s,
        Err(reason) => {
            err(&format!("provision-local-sandbox.sh unavailable: {reason}"));
            return ExitCode::FAILURE;
        }
    };
    banner_phase("PROVISION");
    info("teardown stale runs -> codesign -> gateway -> mTLS -> service -> agent.env");
    let mut args = Vec::new();
    if clean_rerun {
        args.push("--clean-rerun");
    }
    if keep_pki {
        args.push("--keep-pki");
    }
    exec_bash(&script, &args)
}

/// `obs uninstall` — stop everything the wizard started and wipe its state.
pub fn run_uninstall(keep_pki: bool) -> ExitCode {
    let script = match wizard_script() {
        Ok(s) => s,
        Err(reason) => {
            err(&format!("provision-local-sandbox.sh unavailable: {reason}"));
            return ExitCode::FAILURE;
        }
    };
    banner_phase("UNINSTALL");
    info("teardown -> delete state root / config root / gateway metadata / PKI");
    let args = if keep_pki {
        vec!["--uninstall", "--keep-pki"]
    } else {
        vec!["--uninstall"]
    };
    exec_bash(&script, &args)
}

/// Stop only the provisioned gateway/service processes, preserving all state.
pub(crate) fn run_teardown() -> ExitCode {
    let script = match wizard_script() {
        Ok(s) => s,
        Err(reason) => {
            err(&format!("provision-local-sandbox.sh unavailable: {reason}"));
            return ExitCode::FAILURE;
        }
    };
    banner_phase("STACK TEARDOWN");
    let mut command = Command::new("bash");
    command
        .arg(&script)
        .env("OPENBOX_TEARDOWN_ONLY", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // The downloaded standalone launcher may not live beside the provisioned
    // service binary. Recover its exact path from agent.env so the wizard's
    // fail-closed PID ownership check still recognizes the process it started.
    if let Ok(body) = std::fs::read_to_string(agent_env_path()) {
        if let Ok(values) = parse_agent_env(&body) {
            if let Some(binary) = env_value(&values, "OPENBOX_SANDBOX_BINARY") {
                command.env("OPENBOX_SANDBOX_BIN", binary);
            }
        }
    }
    let status = command.status();
    match status {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(s) => {
            err(&format!("provision script exit {}", s.code().unwrap_or(-1)));
            ExitCode::FAILURE
        }
        Err(error) => {
            err(&format!("could not run bash script: {error}"));
            ExitCode::FAILURE
        }
    }
}

/// `obs verify` — drive a real create→exec→delete against the live stack.
pub fn run_verify() -> ExitCode {
    banner_phase("VERIFY");
    let agent_env = agent_env_path();
    if !agent_env.is_file() {
        err(&format!(
            "agent.env not found at {} — run `obs provision` first",
            agent_env.display()
        ));
        return ExitCode::FAILURE;
    }
    info(&format!("loading env from {}", agent_env.display()));
    // Toolchain-free deployments (hosted-bin flow) ship a prebuilt test
    // harness; run it directly instead of invoking cargo. Set
    // OPENBOX_VERIFY_BIN=/path/to/harness to select it.
    if let Ok(bin) = std::env::var("OPENBOX_VERIFY_BIN") {
        if !bin.is_empty() {
            let mut cmd = Command::new(&bin);
            cmd.stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
            if let Err(error) = apply_agent_env(&mut cmd, &agent_env) {
                err(&format!("cannot load agent environment: {error}"));
                return ExitCode::FAILURE;
            }
            info(&format!("running prebuilt verify harness: {bin}"));
            return match cmd.status() {
                Ok(s) if s.success() => {
                    ok("live dogfood lifecycle SUCCEEDED");
                    ExitCode::SUCCESS
                }
                Ok(s) => {
                    err(&format!("verify failed (exit {})", s.code().unwrap_or(-1)));
                    info("see the harness output above; the service retains durable cleanup ownership");
                    ExitCode::FAILURE
                }
                Err(error) => {
                    err(&format!("could not run verify harness: {error}"));
                    ExitCode::FAILURE
                }
            };
        }
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(repo_root())
        .args([
            "test",
            "--lib",
            "live_service_create_exec_delete",
            "--",
            "--nocapture",
            "--test-threads=1",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Err(error) = apply_agent_env(&mut cmd, &agent_env) {
        err(&format!("cannot load agent environment: {error}"));
        return ExitCode::FAILURE;
    }
    info("running `cargo test --lib live_service_create_exec_delete`");
    match cmd.status() {
        Ok(s) if s.success() => {
            ok("live dogfood lifecycle SUCCEEDED");
            ExitCode::SUCCESS
        }
        Ok(s) => {
            err(&format!("verify failed (exit {})", s.code().unwrap_or(-1)));
            info("see the test output above; the service retains durable cleanup ownership");
            ExitCode::FAILURE
        }
        Err(error) => {
            err(&format!("could not run cargo: {error}"));
            info("set OPENBOX_VERIFY_BIN to the prebuilt verify harness (toolchain-free flow)");
            ExitCode::FAILURE
        }
    }
}

/// `obs status` — quick run-state report.
pub fn run_status() -> ExitCode {
    banner_phase("STATUS");
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let state_root = std::env::var_os("OPENBOX_STATE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/state/openbox-sandbox"));
    let config_root = std::env::var_os("OPENBOX_CONFIG_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config/openbox-sandbox"));
    let gateway_pid_file = state_root.join("gateway/gateway.pid");
    let sandbox_pid_file = state_root.join("sandbox-service.pid");
    let agent_env = config_root.join("agent.env");
    let service_config = config_root.join("service.json");
    let gateway_log = state_root.join("gateway/gateway.log");
    let sandbox_log = state_root.join("sandbox-service.log");

    // The wizard records the actual ports (OPENSHELL_SERVER_PORT and
    // OPENBOX_SANDBOX_PORT overrides are honored); read them back instead of
    // assuming the defaults.
    let gateway_port = read_gateway_port(&home).unwrap_or(17670);
    let sandbox_port = read_sandbox_port(&service_config).unwrap_or(17443);

    port_phase(gateway_port, "gateway");
    port_phase(sandbox_port, "sandbox service");
    pid_phase(&gateway_pid_file, "gateway");
    pid_phase(&sandbox_pid_file, "sandbox service");
    artifact_phase(&agent_env, "agent.env");
    artifact_phase(&service_config, "service.json");
    info(&format!("config root: {}", config_root.display()));
    info(&format!("state root:  {}", state_root.display()));
    info(&format!("gateway log: {}", gateway_log.display()));
    info(&format!("sandbox log: {}", sandbox_log.display()));
    let all_up = port_open(gateway_port) && port_open(sandbox_port);
    if all_up {
        ok("stack ready — run `obs verify` to exercise the lifecycle");
    } else {
        warn("stack not fully up — run `obs provision`");
    }
    ExitCode::SUCCESS
}

/// Read the gateway port from the wizard-written metadata (active gateway).
/// Dependency-free: the launcher has no JSON crate, and the metadata format
/// is wizard-owned (`"gateway_port": <n>`), so a bounded string scan suffices.
fn read_gateway_port(home: &Path) -> Option<u16> {
    let name = std::fs::read_to_string(home.join(".config/openshell/active_gateway"))
        .ok()?
        .trim()
        .to_string();
    let meta = home
        .join(".config/openshell/gateways")
        .join(if name.is_empty() { "openshell" } else { &name })
        .join("metadata.json");
    let body = std::fs::read_to_string(meta).ok()?;
    let key = "\"gateway_port\"";
    let start = body.find(key)? + key.len();
    let rest = &body[start..];
    let digits: String = rest
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u16>().ok()
}

/// Read the sandbox service port from the generated service.json
/// (`"bind_address": "127.0.0.1:<port>"`).
fn read_sandbox_port(service_config: &Path) -> Option<u16> {
    let body = std::fs::read_to_string(service_config).ok()?;
    let key = "\"bind_address\"";
    let start = body.find(key)? + key.len();
    let rest = &body[start..];
    let quoted = rest.trim_start().strip_prefix(':')?.trim_start();
    let value = quoted.strip_prefix('"')?;
    let end = value.find('"')?;
    value[..end].rsplit_once(':')?.1.parse::<u16>().ok()
}

fn banner_phase(name: &str) {
    step(name);
}

fn port_open(port: u16) -> bool {
    Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn port_phase(port: u16, label: &str) {
    if port_open(port) {
        ok(&format!("{label}: listening on {port}"));
    } else {
        warn(&format!("{label}: not listening on {port}"));
    }
}

fn pid_phase(pid_file: &Path, label: &str) {
    match std::fs::read_to_string(pid_file)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
    {
        Some(pid) => {
            let alive = libc_kill_alive(pid);
            if alive {
                ok(&format!("{label}: pid={pid} alive"));
            } else {
                warn(&format!("{label}: stale pid file (pid={pid} not alive)"));
            }
        }
        None => warn(&format!("{label}: no pid file at {}", pid_file.display())),
    }
}

fn artifact_phase(path: &Path, label: &str) {
    if path.is_file() {
        ok(&format!("{label}: {}", path.display()));
    } else {
        warn(&format!("{label}: missing -> {}", path.display()));
    }
}

fn agent_env_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    std::env::var_os("OPENBOX_CONFIG_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config/openbox-sandbox"))
        .join("agent.env")
}

fn apply_agent_env(cmd: &mut Command, env_path: &Path) -> Result<(), String> {
    // Parse the generated env file ourselves so verification needs no shell.
    let body = std::fs::read_to_string(env_path).map_err(|error| error.to_string())?;
    let values = parse_agent_env(&body)?;
    verify_service_binary(&values)?;
    for (key, value) in values {
        cmd.env(key, value);
    }
    Ok(())
}

fn verify_service_binary(values: &[(&str, &str)]) -> Result<(), String> {
    let binary = env_value(values, "OPENBOX_SANDBOX_BINARY")
        .ok_or_else(|| "OPENBOX_SANDBOX_BINARY is missing".to_owned())?;
    let expected = env_value(values, "OPENBOX_SANDBOX_ADAPTER_SHA")
        .ok_or_else(|| "OPENBOX_SANDBOX_ADAPTER_SHA is missing".to_owned())?;
    let actual = file_sha256(Path::new(binary))?;
    if actual.eq_ignore_ascii_case(expected) {
        info(&format!("service binary identity verified: {binary}"));
        Ok(())
    } else {
        Err(format!(
            "service binary hash mismatch for {binary}: expected {expected}, found {actual}"
        ))
    }
}

fn env_value<'a>(values: &'a [(&str, &str)], key: &str) -> Option<&'a str> {
    values
        .iter()
        .find_map(|(candidate, value)| (*candidate == key).then_some(*value))
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let (program, prefix): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("shasum", &["-a", "256"])
    } else {
        ("sha256sum", &[])
    };
    let output = Command::new(program)
        .args(prefix)
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("cannot hash service binary {}: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "cannot hash service binary {}: {program} exited {}",
            path.display(),
            output.status
        ));
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .filter(|digest| !digest.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("cannot parse service binary hash for {}", path.display()))
}

fn parse_agent_env(body: &str) -> Result<Vec<(&str, &str)>, String> {
    let mut values = Vec::new();
    let mut has_endpoint = false;
    for (line_number, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {} is not KEY=VALUE", line_number + 1))?;
        if key.is_empty() || value.is_empty() {
            return Err(format!(
                "line {} has an empty key or value",
                line_number + 1
            ));
        }
        if values.iter().any(|(existing, _)| *existing == key) {
            return Err(format!("line {} duplicates {key}", line_number + 1));
        }
        has_endpoint |= key == "OPENBOX_SANDBOX_ENDPOINT";
        values.push((key, value));
    }
    if !has_endpoint {
        return Err(
            "OPENBOX_SANDBOX_ENDPOINT is missing; refusing a skippable live test".to_owned(),
        );
    }
    Ok(values)
}

fn exec_bash(script: &Path, args: &[&str]) -> ExitCode {
    let status = Command::new("bash")
        .arg(script.to_str().unwrap_or(""))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();
    match status {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(s) => {
            err(&format!("provision script exit {}", s.code().unwrap_or(-1)));
            ExitCode::FAILURE
        }
        Err(error) => {
            err(&format!("could not run bash script: {error}"));
            ExitCode::FAILURE
        }
    }
}

/// Best-effort `kill(pid, 0)` liveness check via `kill -0` (no libc FFI).
fn libc_kill_alive(pid: i32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{parse_agent_env, verify_service_binary};

    #[test]
    fn agent_env_requires_endpoint_so_live_verify_cannot_skip() {
        assert!(parse_agent_env("OPENBOX_SANDBOX_CA=/tmp/ca.crt\n").is_err());
        assert_eq!(
            parse_agent_env("OPENBOX_SANDBOX_ENDPOINT=127.0.0.1:17443\n"),
            Ok(vec![("OPENBOX_SANDBOX_ENDPOINT", "127.0.0.1:17443")])
        );
    }

    #[test]
    fn malformed_agent_env_fails_closed() {
        assert!(parse_agent_env("not-an-assignment\n").is_err());
        assert!(parse_agent_env("OPENBOX_SANDBOX_ENDPOINT=\n").is_err());
        assert!(parse_agent_env(
            "OPENBOX_SANDBOX_ENDPOINT=127.0.0.1:1\n\
                 OPENBOX_SANDBOX_ENDPOINT=127.0.0.1:2\n"
        )
        .is_err());
    }

    #[test]
    fn service_binary_hash_must_match_before_live_verify() {
        let path = std::env::temp_dir().join(format!(
            "openbox-dogfood-adapter-test-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"adapter").expect("write adapter fixture");
        let path_text = path.to_string_lossy();
        let matching = [
            ("OPENBOX_SANDBOX_BINARY", path_text.as_ref()),
            (
                "OPENBOX_SANDBOX_ADAPTER_SHA",
                "ae1eae1d76e5b7c865c4122ce366a08025842566d2d96c75cc13e6353a73db0d",
            ),
        ];
        assert_eq!(verify_service_binary(&matching), Ok(()));

        let mismatch = [
            ("OPENBOX_SANDBOX_BINARY", path_text.as_ref()),
            (
                "OPENBOX_SANDBOX_ADAPTER_SHA",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ];
        let error = verify_service_binary(&mismatch).expect_err("mismatch must fail");
        assert!(error.contains(path_text.as_ref()));
        assert!(error.contains("service binary hash mismatch"));
        std::fs::remove_file(path).expect("remove adapter fixture");
    }
}
