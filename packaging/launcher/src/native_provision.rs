//! Native-provider provisioning implemented without an external shell script.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::{info, ok};

// Foreground Ctrl-C: the terminal sends SIGINT to the whole foreground
// process group, so the launcher and the service receive it together. The
// launcher must survive the signal long enough to report the service's exit.
// Rust programs die on SIGINT by default, so install a catcher via FFI. No
// signal crate is allowed here; libc's `signal` and `kill` are enough.
// SIGINT is 2 on macOS and Linux.
#[cfg(unix)]
mod fg_signal {
    use std::sync::atomic::{AtomicI32, Ordering};
    static CHILD_PID: AtomicI32 = AtomicI32::new(0);
    extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
        fn kill(pid: i32, sig: i32) -> i32;
    }
    extern "C" fn on_sigint(_: i32) {
        let pid = CHILD_PID.load(Ordering::SeqCst);
        if pid > 0 {
            // Forward the interrupt to the service so a Ctrl-C that only
            // reached the launcher still drains the service.
            unsafe { kill(pid, 2) };
        }
    }
    pub fn install(pid: i32) {
        CHILD_PID.store(pid, Ordering::SeqCst);
        unsafe { signal(2, on_sigint as *const () as usize) };
    }
}
#[cfg(not(unix))]
mod fg_signal {
    pub fn install(_pid: i32) {}
}

const CLIENT_EXT: &str = "basicConstraints=critical,CA:FALSE\n\
keyUsage=critical,digitalSignature\n\
extendedKeyUsage=clientAuth\n";
const SERVER_CNF: &str = "[req]\n\
distinguished_name=dn\n\
req_extensions=v3_req\n\
prompt=no\n\
[dn]\n\
CN=localhost\n\
[v3_req]\n\
keyUsage=critical,digitalSignature,keyEncipherment\n\
extendedKeyUsage=serverAuth\n\
subjectAltName=@alt\n\
[alt]\n\
DNS.1=localhost\n\
IP.1=127.0.0.1\n";

#[derive(Clone, Copy)]
pub struct Options {
    pub uninstall: bool,
    pub clean_rerun: bool,
    // The shell implementation accepted this argument but did not use it.
    pub _keep_pki: bool,
}

struct Settings {
    state_root: PathBuf,
    config_root: PathBuf,
    sandbox_port: String,
    service_config: PathBuf,
    service_log: PathBuf,
    service_pid_file: PathBuf,
    tls_dir: PathBuf,
    sandbox_state_dir: PathBuf,
    workspace_root: PathBuf,
    native_profile: PathBuf,
    agent_env: PathBuf,
    no_start: String,
    systemd: String,
    detach: String,
    ready_polls: i64,
    ready_interval: String,
    reconcile_delete_deadline_ms: String,
    reconcile_wait_deadline_ms: String,
    maximum_connections: String,
    drain_timeout_ms: String,
    cert_days: String,
    rsa_bits: String,
    caller_subject: String,
    policy_version: String,
    compatibility_id: String,
    sandbox_bin: PathBuf,
    policy_file: PathBuf,
    policy_id: String,
}

pub fn run(options: Options) -> Result<(), String> {
    set_private_umask();
    let mut settings = Settings::from_environment()?;

    info("native teardown");
    stop_service(&settings)?;
    if port_listening(&settings.sandbox_port) {
        return Err(format!(
            "sandbox service port {} remains occupied",
            settings.sandbox_port
        ));
    }
    ok("teardown complete");

    if options.uninstall || options.clean_rerun {
        remove_tree(&settings.state_root)?;
        remove_tree(&settings.config_root)?;
        remove_tree(&settings.workspace_root)?;
        ok("state cleaned");
    }
    if options.uninstall || env_or("OPENBOX_TEARDOWN_ONLY", "0") == "1" {
        ok("native teardown/uninstall complete");
        return Ok(());
    }

    require_executable(
        &settings.sandbox_bin,
        &format!(
            "openbox-sandbox service not found at {}",
            settings.sandbox_bin.display()
        ),
    )?;
    if !settings.policy_file.is_file() {
        return Err(format!(
            "channel policy not found at {}",
            settings.policy_file.display()
        ));
    }
    #[cfg(target_os = "macos")]
    require_executable(
        Path::new("/usr/bin/sandbox-exec"),
        "/usr/bin/sandbox-exec is required for the native provider on macOS (it ships with macOS; contact Apple support if missing)",
    )?;
    #[cfg(target_os = "linux")]
    if !command_exists("bwrap") {
        return Err(
            "bubblewrap is required for the native provider (install package: bubblewrap)".into(),
        );
    }
    if !command_exists("openssl") {
        return Err("openssl is required".into());
    }

    for directory in [
        settings.state_root.join("native"),
        settings.workspace_root.clone(),
        settings.sandbox_state_dir.clone(),
        settings.config_root.clone(),
        settings.tls_dir.clone(),
    ] {
        create_private_dir(&directory)?;
    }
    settings.workspace_root = physical_path(&settings.workspace_root)?;

    info("compiling deployment-pinned native policy");
    let output = Command::new(&settings.sandbox_bin)
        .args([OsStr::new("--compile-native-policy")])
        .arg(&settings.policy_file)
        .arg(&settings.native_profile)
        .arg(&settings.workspace_root)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|error| format!("native policy compilation failed: {error}"))?;
    if !output.status.success() {
        return Err("native policy compilation failed".into());
    }
    chmod(&settings.native_profile, 0o600)?;
    let profile_sha = String::from_utf8_lossy(&output.stdout)
        .trim_end_matches('\n')
        .to_owned();
    if sha256_file(&settings.native_profile)? != profile_sha {
        return Err("compiled native profile hash mismatch".into());
    }
    ok(&format!("profile pinned: {profile_sha}"));

    create_pki(&settings)?;

    let ca_cert = settings.tls_dir.join("ca.crt");
    let client_cert = settings.tls_dir.join("client.crt");
    let caller_der = openssl_output([
        OsStr::new("x509"),
        OsStr::new("-in"),
        client_cert.as_os_str(),
        OsStr::new("-outform"),
        OsStr::new("DER"),
    ])?;
    let caller_fingerprint = sha256_bytes(&caller_der)?;
    let adapter_sha = sha256_file(&settings.sandbox_bin)?;
    let policy_sha = sha256_file(&settings.policy_file)?;

    let service_json = format!(
        r#"{{
  "bind_address": "127.0.0.1:{}",
  "server_certificate_path": "{}/server.crt",
  "server_private_key_path": "{}/server.key",
  "client_ca_path": "{}",
  "authorized_callers": [{{"certificate_sha256":"{}","role":"runtime"}}],
  "state_directory": "{}",
  "provider": "native",
  "provider_capability": "enforced-locally",
  "native_profile_path": "{}",
  "native_profile_sha256": "{}",
  "native_workspace_root": "{}",
  "asset_bundle": {{
    "runtime_contract_version": 1,
    "adapter_build_sha256": "{}",
    "template": "native://native",
    "policy": {{"id":"{}","version":{},"sha256":"{}"}},
    "compatibility_id": "{}"
  }},
  "reconcile_delete_deadline_ms": {},
  "reconcile_wait_deadline_ms": {},
  "maximum_connections": {},
  "drain_timeout_ms": {}
}}
"#,
        settings.sandbox_port,
        settings.tls_dir.display(),
        settings.tls_dir.display(),
        ca_cert.display(),
        caller_fingerprint,
        settings.sandbox_state_dir.display(),
        settings.native_profile.display(),
        profile_sha,
        settings.workspace_root.display(),
        adapter_sha,
        settings.policy_id,
        settings.policy_version,
        policy_sha,
        settings.compatibility_id,
        settings.reconcile_delete_deadline_ms,
        settings.reconcile_wait_deadline_ms,
        settings.maximum_connections,
        settings.drain_timeout_ms,
    );
    write_private(&settings.service_config, service_json.as_bytes())?;

    let check = Command::new(&settings.sandbox_bin)
        .arg("--check-config")
        .env("OPENBOX_SANDBOX_CONFIG", &settings.service_config)
        .stdout(Stdio::null())
        .status()
        .map_err(|error| format!("service rejected native config: {error}"))?;
    if !check.success() {
        return Err("service rejected native config".into());
    }
    ok("service config validated (provider=native, capability=enforced-locally)");

    let mut foreground = None;
    if settings.no_start != "1" {
        foreground = start_service(&settings)?;
    }

    let agent_env = format!(
        "# OpenBox SDK agent environment. Provider-neutral boundary values.\n\
OPENBOX_SANDBOX_ENDPOINT=127.0.0.1:{}\n\
OPENBOX_SANDBOX_SERVER_NAME=localhost\n\
OPENBOX_SANDBOX_CA={}\n\
OPENBOX_SANDBOX_CERT={}/client.crt\n\
OPENBOX_SANDBOX_KEY={}/client.key\n\
OPENBOX_SANDBOX_BINARY={}\n\
OPENBOX_SANDBOX_ADAPTER_SHA={}\n\
OPENBOX_SANDBOX_TEMPLATE=native://native\n\
OPENBOX_SANDBOX_POLICY_FILE={}\n\
OPENBOX_SANDBOX_POLICY_ID={}\n\
OPENBOX_SANDBOX_POLICY_VERSION={}\n\
OPENBOX_SANDBOX_POLICY_SHA256={}\n\
OPENBOX_SANDBOX_COMPAT_ID={}\n\
OPENBOX_SANDBOX_CONFIG_PATH={}\n\
OPENBOX_PROVIDER=native\n",
        settings.sandbox_port,
        ca_cert.display(),
        settings.tls_dir.display(),
        settings.tls_dir.display(),
        settings.sandbox_bin.display(),
        adapter_sha,
        settings.policy_file.display(),
        settings.policy_id,
        settings.policy_version,
        policy_sha,
        settings.compatibility_id,
        settings.service_config.display(),
    );
    write_private(&settings.agent_env, agent_env.as_bytes())?;

    if settings.no_start != "1" {
        smoke_test(&settings)?;
        ok("native sandbox smoke ready");
    }
    ok("native provision complete");
    info(&format!("service: 127.0.0.1:{}", settings.sandbox_port));
    info(&format!("agent env: {}", settings.agent_env.display()));

    if let Some(mut child) = foreground {
        // A foreground service is silent until it handles a request, so the
        // terminal looks like it hung. Say plainly that this is the running
        // state, and prove it by re-checking the port rather than asserting it.
        let live = port_listening(&settings.sandbox_port);
        crate::step("RUNNING");
        if live {
            ok(&format!(
                "accepting mTLS connections on 127.0.0.1:{} (pid {})",
                settings.sandbox_port,
                child.id()
            ));
        } else {
            crate::warn(&format!(
                "port 127.0.0.1:{} is not accepting connections",
                settings.sandbox_port
            ));
        }
        info("this terminal is now the service; it stays here until you stop it");
        info("press Ctrl-C to stop and drain work in flight");
        info("run the agent from another shell, or re-run with --detach");
        info("service output appears below as requests arrive");
        // Ctrl-C reaches the child through the process group. The service
        // drains and exits on SIGINT. Without a catcher, the terminal's
        // SIGINT kills the launcher before `wait` returns and before the
        // final message prints. Install a catcher, forward the signal to
        // the service, and only then wait.
        fg_signal::install(child.id() as i32);
        let status = child
            .wait()
            .map_err(|error| format!("cannot wait for the sandbox service: {error}"))?;
        let _ = fs::remove_file(&settings.service_pid_file);
        if !status.success() && status.code().is_some() {
            return Err(format!("sandbox service exited with {status}"));
        }
        ok("sandbox service stopped");
    }
    Ok(())
}

impl Settings {
    fn from_environment() -> Result<Self, String> {
        let home = std::env::var_os("HOME");
        let state_root = nonempty_env_path("OPENBOX_STATE_ROOT")
            .or_else(|| {
                home.as_ref()
                    .map(|path| home_join(path, ".local/state/openbox-sandbox"))
            })
            .ok_or_else(|| "HOME is unset and OPENBOX_STATE_ROOT was not provided".to_owned())?;
        let config_root = nonempty_env_path("OPENBOX_CONFIG_ROOT")
            .or_else(|| {
                home.as_ref()
                    .map(|path| home_join(path, ".config/openbox-sandbox"))
            })
            .ok_or_else(|| "HOME is unset and OPENBOX_CONFIG_ROOT was not provided".to_owned())?;
        create_private_dir(&state_root)?;
        create_private_dir(&config_root)?;
        let state_root = physical_path(&state_root)?;
        let config_root = physical_path(&config_root)?;
        let cwd = std::env::current_dir().map_err(|error| format!("cannot read cwd: {error}"))?;
        let project_root =
            nonempty_env_path("OPENBOX_PROJECT_ROOT").unwrap_or_else(default_project_root);
        let sandbox_bin = select_sandbox_binary(&cwd, &project_root);
        let (policy_file, policy_id) = select_policy(&cwd, &project_root);
        let workspace_root = nonempty_env_path("OPENBOX_NATIVE_WORKSPACE_ROOT")
            .unwrap_or_else(|| state_root.join("workspaces"));
        let profile_extension = if cfg!(target_os = "macos") {
            "sb"
        } else {
            "json"
        };
        let ready_polls_text = env_or("OPENBOX_SERVICE_READY_POLLS", "40");
        let ready_polls = ready_polls_text
            .parse::<i64>()
            .map_err(|_| format!("invalid OPENBOX_SERVICE_READY_POLLS: {ready_polls_text}"))?;

        Ok(Self {
            service_config: config_root.join("service.json"),
            service_log: state_root.join("sandbox-service.log"),
            service_pid_file: state_root.join("sandbox-service.pid"),
            tls_dir: config_root.join("tls"),
            sandbox_state_dir: state_root.join("cleanup"),
            native_profile: state_root
                .join("native")
                .join(format!("policy.{profile_extension}")),
            agent_env: config_root.join("agent.env"),
            state_root,
            config_root,
            sandbox_port: env_or("OPENBOX_SANDBOX_PORT", "17443"),
            workspace_root,
            no_start: env_or("NO_START", "0"),
            systemd: env_or("OPENBOX_SYSTEMD", "0"),
            detach: env_or("OPENBOX_DETACH", "0"),
            ready_polls,
            ready_interval: env_or("OPENBOX_SERVICE_READY_INTERVAL", "0.25"),
            reconcile_delete_deadline_ms: env_or("OPENBOX_RECONCILE_DELETE_DEADLINE_MS", "60000"),
            reconcile_wait_deadline_ms: env_or("OPENBOX_RECONCILE_WAIT_DEADLINE_MS", "60000"),
            maximum_connections: env_or("OPENBOX_MAX_CONNECTIONS", "64"),
            drain_timeout_ms: env_or("OPENBOX_DRAIN_TIMEOUT_MS", "30000"),
            cert_days: env_or("OPENBOX_CERT_DAYS", "825"),
            rsa_bits: env_or("OPENBOX_RSA_BITS", "2048"),
            caller_subject: env_or("OPENBOX_CALLER_SUBJ", "/CN=openbox-sandbox-runtime-caller"),
            policy_version: env_or("OPENBOX_POLICY_VERSION", "1"),
            compatibility_id: env_or("OPENBOX_COMPAT_ID", "native-v1"),
            sandbox_bin,
            policy_file,
            policy_id,
        })
    }
}

fn select_sandbox_binary(cwd: &Path, project_root: &Path) -> PathBuf {
    if let Some(path) = nonempty_env_path("OPENBOX_SANDBOX_BIN") {
        return path;
    }
    let local_name = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        Some("openbox-sandbox-darwin-arm64")
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        Some("openbox-sandbox-linux-x86_64")
    } else {
        None
    };
    if let Some(name) = local_name {
        let candidate = cwd.join(name);
        if is_executable(&candidate) {
            return candidate;
        }
    }
    project_root.join("target/release/openbox-sandbox")
}

fn policy_defaults(release_line: &str) -> (&'static str, &'static str) {
    if release_line == "dev" {
        ("policy-allow-network-dev.yaml", "openbox-allow-network-dev")
    } else {
        ("policy-deny-network-dev.yaml", "openbox-deny-network-dev")
    }
}

fn select_policy(cwd: &Path, project_root: &Path) -> (PathBuf, String) {
    let release_line = env_or("OPENBOX_RELEASE_LINE", "base");
    let (template, default_id) = policy_defaults(&release_line);
    let policy_file = nonempty_env_path("OPENBOX_POLICY_FILE").unwrap_or_else(|| {
        let local = cwd.join(template);
        if local.is_file() {
            local
        } else {
            project_root.join("deploy/policies").join(template)
        }
    });
    let explicit_id = std::env::var("OPENBOX_POLICY_ID")
        .ok()
        .filter(|value| !value.is_empty());
    let policy_id = select_policy_id(&policy_file, default_id, explicit_id);
    (policy_file, policy_id)
}

fn select_policy_id(policy_file: &Path, default_id: &str, explicit_id: Option<String>) -> String {
    explicit_id.unwrap_or_else(|| {
        if policy_file
            .file_name()
            .is_some_and(|name| name.to_string_lossy().contains("allow"))
        {
            "openbox-allow-network-dev".to_owned()
        } else {
            default_id.to_owned()
        }
    })
}

fn stop_service(settings: &Settings) -> Result<(), String> {
    // A previous run may have handed the service to systemd. Stop the unit
    // first, whether or not this run asked for --systemd, so teardown does not
    // leave a supervised service holding the port.
    if let Some(unit_path) = systemd_unit_path() {
        if unit_path.is_file() {
            systemctl_user(&["disable", "--now", "openbox-sandbox.service"]);
            let _ = fs::remove_file(&unit_path);
            systemctl_user(&["daemon-reload"]);
        }
    }
    if !settings.service_pid_file.is_file() {
        return Ok(());
    }
    let body = fs::read_to_string(&settings.service_pid_file).unwrap_or_default();
    let pid = parse_pid_file(&body)?;
    if process_alive(pid) {
        let output = Command::new("ps")
            .args(["-ww", "-p", &pid.to_string(), "-o", "command="])
            .output()
            .ok();
        let command = output
            .filter(|value| value.status.success())
            .map(|value| {
                String::from_utf8_lossy(&value.stdout)
                    .trim_end_matches('\n')
                    .to_owned()
            })
            .unwrap_or_default();
        let first_word = command.split(' ').next().unwrap_or_default();
        let binary_name = settings
            .sandbox_bin
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default();
        if !first_word.ends_with(binary_name) {
            return Err("service PID identity mismatch; refusing to signal".into());
        }
        let _ = Command::new("kill").arg(pid.to_string()).status();
        for _ in 0..20 {
            if !process_alive(pid) {
                break;
            }
            sleep_external(&settings.ready_interval)?;
        }
        if process_alive(pid) {
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
        }
    }
    // Tolerate a PID file that has already gone: teardown races with a
    // service that exited on its own, and failing here aborts a provision
    // over a file that is absent precisely because the work is done.
    remove_file_if_present(&settings.service_pid_file)
}

fn parse_pid_file(body: &str) -> Result<u32, String> {
    let value = body.trim_end_matches('\n');
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("malformed service PID file".into());
    }
    value
        .parse::<u32>()
        .map_err(|_| "malformed service PID file".into())
}

/// True when this process is root, which decides the systemd scope.
fn running_as_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "0")
        .unwrap_or(false)
}

/// Path of the systemd unit this launcher owns.
///
/// Root installs a system unit, so the service survives logout and starts at
/// boot. An ordinary user installs a user unit, which keeps provisioning free
/// of sudo but stops with the last session unless lingering is enabled.
fn systemd_unit_path() -> Option<PathBuf> {
    if running_as_root() {
        return Some(PathBuf::from("/etc/systemd/system/openbox-sandbox.service"));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config/systemd/user/openbox-sandbox.service"))
}

/// Run systemctl in the scope that matches the unit this launcher owns.
fn systemctl_user(args: &[&str]) -> bool {
    let mut command = Command::new("systemctl");
    if !running_as_root() {
        command.arg("--user");
    }
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Supervise the service with a systemd user unit.
///
/// Opt-in through `--systemd`. The default remains a background process this
/// launcher owns, because a user unit needs a working per-user systemd manager
/// and, without lingering enabled, stops when the last session ends.
///
/// This fails closed rather than falling back: an operator who asked for
/// supervision should not silently get an unsupervised process.
fn start_service_systemd(settings: &Settings) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("--systemd requires Linux; macOS has no systemd".into());
    }
    let unit_path = systemd_unit_path().ok_or("HOME is required to write a systemd user unit")?;
    if !systemctl_user(&["--version"]) {
        return Err("no usable systemd manager; re-run without --systemd".into());
    }
    let parent = unit_path
        .parent()
        .ok_or("cannot resolve the systemd user directory")?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;

    let unit = format!(
        "[Unit]\nDescription=OpenBox Sandbox service\nAfter=network-online.target\n\n[Service]\nType=simple\nEnvironment=OPENBOX_SANDBOX_CONFIG={config}\nExecStart={binary}\nRestart=on-failure\nRestartSec=5s\n\n[Install]\nWantedBy={target}\n",
        config = settings.service_config.display(),
        binary = settings.sandbox_bin.display(),
        target = if running_as_root() {
            "multi-user.target"
        } else {
            "default.target"
        },
    );
    fs::write(&unit_path, unit)
        .map_err(|error| format!("cannot write {}: {error}", unit_path.display()))?;
    chmod(&unit_path, 0o600)?;

    if !systemctl_user(&["daemon-reload"]) {
        return Err("systemctl --user daemon-reload failed".into());
    }
    if !systemctl_user(&["enable", "--now", "openbox-sandbox.service"]) {
        return Err("systemctl --user enable --now openbox-sandbox.service failed".into());
    }

    let mut ready = false;
    for _ in 0..settings.ready_polls.max(0) {
        if port_listening(&settings.sandbox_port) {
            ready = true;
            break;
        }
        sleep_external(&settings.ready_interval)?;
    }
    if !ready {
        print_log_tail(&settings.service_log, 30);
        return Err("sandbox service failed to start under systemd".into());
    }
    // systemd owns the process, so no PID file is written: teardown asks
    // systemctl to stop the unit instead of signalling a recorded PID.
    ok(&format!(
        "service up (provider=native, supervised by systemd {})",
        if running_as_root() {
            "system"
        } else {
            "--user"
        }
    ));
    info(&format!("unit: {}", unit_path.display()));
    Ok(())
}

/// Start the service and keep the handle so provisioning can wait on it.
///
/// The default is a foreground child: it dies with the terminal, and Ctrl-C
/// reaches it through the process group, where the service already drains and
/// shuts down cleanly. Detaching is opt-in because an orphaned background
/// service holding the port is the failure this avoids.
fn start_service(settings: &Settings) -> Result<Option<Child>, String> {
    if settings.systemd == "1" {
        start_service_systemd(settings)?;
        return Ok(None);
    }
    let log = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&settings.service_log)
        .map_err(|error| format!("cannot open {}: {error}", settings.service_log.display()))?;
    chmod(&settings.service_log, 0o600)?;
    let stderr = log
        .try_clone()
        .map_err(|error| format!("cannot clone service log: {error}"))?;
    let detached = settings.detach == "1";
    let mut command = Command::new(&settings.sandbox_bin);
    command
        .env("OPENBOX_SANDBOX_CONFIG", &settings.service_config)
        .stdin(Stdio::null());
    if detached {
        // Logs go to the file because no terminal will be attached.
        command.stdout(Stdio::from(log)).stderr(Stdio::from(stderr));
        // Leave the shell's process group. This is what `nohup` bought: a
        // terminal that closes sends SIGHUP to its own group, and a detached
        // service must outlive that.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
    } else {
        // Foreground: the operator watches the service directly, and Ctrl-C
        // reaches it through the process group.
        command.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    }
    let child = command
        .spawn()
        .map_err(|error| format!("cannot start sandbox service: {error}"))?;
    write_private(
        &settings.service_pid_file,
        format!("{}\n", child.id()).as_bytes(),
    )?;

    let mut ready = false;
    for _ in 0..settings.ready_polls.max(0) {
        if port_listening(&settings.sandbox_port) {
            ready = true;
            break;
        }
        sleep_external(&settings.ready_interval)?;
    }
    if !ready {
        print_log_tail(&settings.service_log, 30);
        return Err("sandbox service failed to start".into());
    }
    ok(&format!("service up (provider=native pid={})", child.id()));
    if detached {
        return Ok(None);
    }
    Ok(Some(child))
}

fn create_pki(settings: &Settings) -> Result<(), String> {
    let ca_key = settings.tls_dir.join("ca.key");
    let ca_cert = settings.tls_dir.join("ca.crt");
    run_openssl([
        OsStr::new("req"),
        OsStr::new("-x509"),
        OsStr::new("-newkey"),
        OsStr::new(&format!("rsa:{}", settings.rsa_bits)),
        OsStr::new("-nodes"),
        OsStr::new("-sha256"),
        OsStr::new("-days"),
        OsStr::new(&settings.cert_days),
        OsStr::new("-subj"),
        OsStr::new("/CN=OpenBox Native Local CA"),
        OsStr::new("-keyout"),
        ca_key.as_os_str(),
        OsStr::new("-out"),
        ca_cert.as_os_str(),
        OsStr::new("-addext"),
        OsStr::new("basicConstraints=critical,CA:TRUE"),
        OsStr::new("-addext"),
        OsStr::new("keyUsage=critical,keyCertSign,cRLSign"),
    ])?;

    let client_key = settings.tls_dir.join("client.key");
    let client_csr = settings.tls_dir.join("client.csr");
    let client_ext = settings.tls_dir.join("client.ext");
    run_openssl([
        OsStr::new("genrsa"),
        OsStr::new("-out"),
        client_key.as_os_str(),
        OsStr::new(&settings.rsa_bits),
    ])?;
    run_openssl([
        OsStr::new("req"),
        OsStr::new("-new"),
        OsStr::new("-key"),
        client_key.as_os_str(),
        OsStr::new("-subj"),
        OsStr::new(&settings.caller_subject),
        OsStr::new("-out"),
        client_csr.as_os_str(),
    ])?;
    write_private(&client_ext, CLIENT_EXT.as_bytes())?;
    run_openssl([
        OsStr::new("x509"),
        OsStr::new("-req"),
        OsStr::new("-sha256"),
        OsStr::new("-days"),
        OsStr::new(&settings.cert_days),
        OsStr::new("-in"),
        client_csr.as_os_str(),
        OsStr::new("-CA"),
        ca_cert.as_os_str(),
        OsStr::new("-CAkey"),
        ca_key.as_os_str(),
        OsStr::new("-CAcreateserial"),
        OsStr::new("-extfile"),
        client_ext.as_os_str(),
        OsStr::new("-out"),
        settings.tls_dir.join("client.crt").as_os_str(),
    ])?;

    let server_key = settings.tls_dir.join("server.key");
    let server_cnf = settings.tls_dir.join("server.cnf");
    let server_csr = settings.tls_dir.join("server.csr");
    run_openssl([
        OsStr::new("genrsa"),
        OsStr::new("-out"),
        server_key.as_os_str(),
        OsStr::new(&settings.rsa_bits),
    ])?;
    write_private(&server_cnf, SERVER_CNF.as_bytes())?;
    run_openssl([
        OsStr::new("req"),
        OsStr::new("-new"),
        OsStr::new("-key"),
        server_key.as_os_str(),
        OsStr::new("-config"),
        server_cnf.as_os_str(),
        OsStr::new("-out"),
        server_csr.as_os_str(),
    ])?;
    run_openssl([
        OsStr::new("x509"),
        OsStr::new("-req"),
        OsStr::new("-sha256"),
        OsStr::new("-days"),
        OsStr::new(&settings.cert_days),
        OsStr::new("-in"),
        server_csr.as_os_str(),
        OsStr::new("-CA"),
        ca_cert.as_os_str(),
        OsStr::new("-CAkey"),
        ca_key.as_os_str(),
        OsStr::new("-CAcreateserial"),
        OsStr::new("-extfile"),
        server_cnf.as_os_str(),
        OsStr::new("-extensions"),
        OsStr::new("v3_req"),
        OsStr::new("-out"),
        settings.tls_dir.join("server.crt").as_os_str(),
    ])?;

    for key in [&ca_key, &client_key, &server_key] {
        chmod(key, 0o600)?;
    }
    for cert in [
        &ca_cert,
        &settings.tls_dir.join("client.crt"),
        &settings.tls_dir.join("server.crt"),
    ] {
        chmod(cert, 0o644)?;
    }
    for temporary in [client_csr, client_ext, server_csr, server_cnf] {
        remove_file_if_present(&temporary)?;
    }
    Ok(())
}

fn smoke_test(settings: &Settings) -> Result<(), String> {
    info("native runner smoke: /bin/true");
    #[cfg(target_os = "macos")]
    {
        let workspace = settings.workspace_root.to_string_lossy();
        let status = Command::new("/usr/bin/sandbox-exec")
            .current_dir(&settings.workspace_root)
            .args(["-D", &format!("WORKSPACE_ROOT={workspace}")])
            .args(["-D", &format!("WORKSPACE={workspace}")])
            .args(["-D", "PROXY_ENDPOINT=localhost:1", "-f"])
            .arg(&settings.native_profile)
            .args(["--", "/usr/bin/true"])
            .status()
            .map_err(|error| format!("native Seatbelt smoke failed: {error}"))?;
        if !status.success() {
            return Err("native Seatbelt smoke failed".into());
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut command = Command::new("bwrap");
        command.args([
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--unshare-net",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
        ]);
        for path in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc"] {
            if Path::new(path).exists() {
                command.args(["--ro-bind", path, path]);
            }
        }
        let status = command
            .arg("--bind")
            .arg(&settings.workspace_root)
            .args(["/sandbox", "--chdir", "/sandbox", "--", "/bin/true"])
            .status()
            .map_err(|error| format!("native bwrap smoke failed: {error}"))?;
        if !status.success() {
            return Err("native bwrap smoke failed".into());
        }
    }
    Ok(())
}

fn openssl_output<I, S>(args: I) -> Result<Vec<u8>, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("openssl")
        .args(args)
        .output()
        .map_err(|error| format!("cannot run openssl: {error}"))?;
    if !output.status.success() {
        return Err(format!("openssl exited {}", output.status));
    }
    Ok(output.stdout)
}

fn run_openssl<I, S>(args: I) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let status = Command::new("openssl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot run openssl: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("openssl exited {status}"))
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let output = openssl_output([OsStr::new("dgst"), OsStr::new("-sha256"), path.as_os_str()])?;
    parse_openssl_digest(&output)
}

fn sha256_bytes(bytes: &[u8]) -> Result<String, String> {
    let mut child = Command::new("openssl")
        .args(["dgst", "-sha256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot run openssl: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "cannot open openssl stdin".to_owned())?
        .write_all(bytes)
        .map_err(|error| format!("cannot write openssl stdin: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("cannot wait for openssl: {error}"))?;
    if !output.status.success() {
        return Err(format!("openssl exited {}", output.status));
    }
    parse_openssl_digest(&output.stdout)
}

fn parse_openssl_digest(output: &[u8]) -> Result<String, String> {
    let digest = String::from_utf8_lossy(output)
        .split_whitespace()
        .next_back()
        .unwrap_or_default()
        .to_owned();
    if digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(digest)
    } else {
        Err("cannot parse openssl SHA-256 output".into())
    }
}

fn physical_path(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve physical path {}: {error}", path.display()))
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("cannot create directory {}: {error}", path.display()))?;
    chmod(path, 0o700)
}

fn write_private(path: &Path, body: &[u8]) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    file.write_all(body)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    chmod(path, 0o600)
}

fn chmod(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("cannot chmod {}: {error}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

fn remove_tree(path: &Path) -> Result<(), String> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot remove {}: {error}", path.display())),
    }
}

fn remove_file_if_present(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("cannot remove {}: {error}", path.display())),
    }
}

fn require_executable(path: &Path, message: &str) -> Result<(), String> {
    if is_executable(path) {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn command_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path).any(|directory| is_executable(&directory.join(name)))
        })
        .unwrap_or(false)
}

fn process_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn port_listening(port: &str) -> bool {
    if command_exists("lsof") {
        return Command::new("lsof")
            .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
    }
    port.parse::<u16>().is_ok_and(|port| {
        TcpStream::connect_timeout(
            &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
            Duration::from_millis(250),
        )
        .is_ok()
    })
}

fn sleep_external(interval: &str) -> Result<(), String> {
    let status = Command::new("sleep")
        .arg(interval)
        .status()
        .map_err(|error| format!("cannot run sleep: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("sleep rejected interval {interval}"))
    }
}

fn print_log_tail(path: &Path, count: usize) {
    let mut body = String::new();
    if File::open(path)
        .and_then(|mut file| file.read_to_string(&mut body))
        .is_ok()
    {
        let lines: Vec<_> = body.lines().collect();
        for line in &lines[lines.len().saturating_sub(count)..] {
            eprintln!("{line}");
        }
    }
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn nonempty_env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn home_join(home: &OsStr, suffix: &str) -> PathBuf {
    if home.is_empty() {
        Path::new("/").join(suffix)
    } else {
        Path::new(home).join(suffix)
    }
}

/// The source checkout this launcher is running inside, if any.
///
/// Resolved at runtime by walking up from the working directory. It used to
/// fall back to `env!("CARGO_MANIFEST_DIR")`, which baked the build machine's
/// absolute path into every published binary: a leak of the builder's home
/// directory, and a path that does not exist for anyone else.
fn default_project_root() -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut candidate: Option<&Path> = Some(cwd.as_path());
    while let Some(directory) = candidate {
        if directory.join("packaging/launcher/Cargo.toml").is_file() {
            return directory.to_path_buf();
        }
        candidate = directory.parent();
    }
    cwd
}

#[cfg(unix)]
fn set_private_umask() {
    unsafe extern "C" {
        fn umask(mask: u32) -> u32;
    }
    // The provisioner is a single-threaded CLI path, matching `umask 077` in
    // the former process-scoped shell implementation.
    unsafe {
        umask(0o077);
    }
}

#[cfg(not(unix))]
fn set_private_umask() {}

#[cfg(test)]
mod tests {
    use super::{parse_pid_file, physical_path, policy_defaults, select_policy_id};
    use std::fs;

    #[test]
    fn release_line_selects_policy_template_and_id() {
        assert_eq!(
            policy_defaults("dev"),
            ("policy-allow-network-dev.yaml", "openbox-allow-network-dev")
        );
        assert_eq!(
            policy_defaults("base"),
            ("policy-deny-network-dev.yaml", "openbox-deny-network-dev")
        );
        assert_eq!(policy_defaults("anything-else"), policy_defaults("base"));
        assert_eq!(
            select_policy_id(
                std::path::Path::new("custom-allow-policy.yaml"),
                "openbox-deny-network-dev",
                None,
            ),
            "openbox-allow-network-dev"
        );
        assert_eq!(
            select_policy_id(
                std::path::Path::new("custom-allow-policy.yaml"),
                "openbox-deny-network-dev",
                Some("operator-policy".to_owned()),
            ),
            "operator-policy"
        );
        assert_eq!(
            select_policy_id(
                std::path::Path::new("custom-deny-policy.yaml"),
                "openbox-deny-network-dev",
                None,
            ),
            "openbox-deny-network-dev"
        );
    }

    #[test]
    fn physical_path_resolves_symlink_components() {
        let root =
            std::env::temp_dir().join(format!("obs-native-physical-path-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("real/child")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
        #[cfg(unix)]
        assert_eq!(
            physical_path(&root.join("link/child")).unwrap(),
            fs::canonicalize(root.join("real/child")).unwrap()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn pid_file_parser_accepts_only_positive_decimal_pid() {
        assert_eq!(parse_pid_file("123\n"), Ok(123));
        assert_eq!(parse_pid_file("123\n\n"), Ok(123));
        for malformed in ["", "0", "01", "-1", " 12", "12 ", "12x", "12\r\n"] {
            assert_eq!(
                parse_pid_file(malformed),
                Err("malformed service PID file".to_owned())
            );
        }
    }
}
