//! OpenShell-provider provisioning implemented without an external shell script.

use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::{err, info, ok, warn};

const OPENSHELL_SOURCE_PIN: &str = "f169084923503a02a94425857b938de2841cab0c";
const SOURCE_MARKER: &str = "f1690849";
const LOCKED_VERSION: &str = "0.0.88";
const DEFAULT_IMAGE: &str = "ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e";
const CLIENT_EXT: &str = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n";
const CA_EXT: &str = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign,digitalSignature\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n";
const SERVER_CNF: &str = "[req]\ndistinguished_name = dn\nreq_extensions = v3_req\nprompt = no\n[dn]\nCN = localhost\n[v3_req]\nkeyUsage = critical, digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = localhost\nIP.1 = 127.0.0.1\n";
const ENTITLEMENTS: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n    <key>com.apple.security.hypervisor</key>\n    <true/>\n</dict>\n</plist>\n";

#[derive(Clone, Copy)]
pub struct Options {
    pub uninstall: bool,
    pub clean_rerun: bool,
    pub keep_pki: bool,
}

struct Settings {
    home: PathBuf,
    launcher_dir: PathBuf,
    release_line: String,
    sums_file: Option<PathBuf>,
    sandbox_bin: PathBuf,
    policy_file: PathBuf,
    policy_id: String,
    policy_version: String,
    compatibility_id: String,
    sandbox_image: String,
    explicit_sandbox_image: bool,
    dev_tar: Option<PathBuf>,
    dev_image_name: String,
    oci_layout: Option<PathBuf>,
    zot_bin: Option<PathBuf>,
    zot_port: String,
    vm_cache_tar: String,
    use_vm_cache: String,
    _vm_cache_hit_timeout: String,
    purge_cache: bool,
    locked_version: String,
    gateway_bin: PathBuf,
    cli_bin: PathBuf,
    driver_bin: PathBuf,
    state_root: PathBuf,
    config_root: PathBuf,
    gateway_port: String,
    gateway_name: String,
    sandbox_port: String,
    log_level: String,
    no_start: String,
    teardown_only: String,
    cert_days: String,
    rsa_bits: String,
    jwt_ttl_secs: String,
    gateway_ready_polls: i64,
    gateway_ready_interval: String,
    service_ready_polls: i64,
    service_ready_interval: String,
    warm_poll_count: i64,
    warm_poll_interval: String,
    warm_create_timeout: u64,
    warm_get_timeout: u64,
    warm_delete_timeout: u64,
    runtime_connect_timeout_ms: String,
    runtime_poll_interval_ms: String,
    reconcile_delete_deadline_ms: String,
    reconcile_wait_deadline_ms: String,
    maximum_connections: String,
    gateway_log_level: String,
    krun_log_level: String,
    driver_rust_log: Option<OsString>,
    drain_timeout_ms: String,
    allow_degraded_landlock: String,
    caller_subject: String,
    runtime_mtls_dir: PathBuf,
    openshell_meta_dir: PathBuf,
    vm_driver_state_dir: PathBuf,
    tls_dir: PathBuf,
    gateway_state_dir: PathBuf,
    gateway_meta_dir: PathBuf,
    gateway_mtls_dir: PathBuf,
    sandbox_tls_dir: PathBuf,
    sandbox_state_dir: PathBuf,
    service_config: PathBuf,
    service_log: PathBuf,
    gateway_pid_file: PathBuf,
    gateway_log: PathBuf,
    gateway_config: PathBuf,
    sandbox_pid_file: PathBuf,
    agent_env: PathBuf,
}

struct Started {
    gateway: bool,
    service: bool,
    zot_pid: Option<u32>,
}

pub fn run(options: Options) -> Result<(), String> {
    set_private_umask();
    validate_options(options)?;
    let mut settings = Settings::from_environment()?;
    let mut started = Started {
        gateway: false,
        service: false,
        zot_pid: None,
    };
    let result = run_inner(&mut settings, options, &mut started);
    if result.is_err() && (started.gateway || started.service || started.zot_pid.is_some()) {
        warn("provision failed; tearing down launcher-owned processes started this run");
        if started.service {
            let _ = stop_pid_file(
                &settings.sandbox_pid_file,
                "sandbox service",
                settings
                    .sandbox_bin
                    .file_name()
                    .and_then(OsStr::to_str)
                    .unwrap_or_default(),
                "",
                IdentityMode::BinaryName,
                &settings.service_ready_interval,
            );
        }
        if started.gateway {
            let _ = stop_pid_file(
                &settings.gateway_pid_file,
                "gateway",
                &settings.gateway_bin.to_string_lossy(),
                &settings.gateway_config.to_string_lossy(),
                IdentityMode::GatewayConfig,
                &settings.service_ready_interval,
            );
        }
        let _ = stop_scoped_vm_drivers(&settings.vm_driver_state_dir);
        if let Some(pid) = started.zot_pid {
            let _ = signal(pid, None);
            let _ = remove_file_if_present(&settings.state_root.join("zot/zot.pid"));
        }
    }
    result
}

fn validate_options(options: Options) -> Result<(), String> {
    if options.keep_pki && !options.uninstall && !options.clean_rerun {
        return Err("--keep-pki requires --uninstall or --clean-rerun".to_owned());
    }
    let purge = env_or("OPENBOX_PURGE_CACHE", "0") == "1";
    if purge && !options.uninstall && !options.clean_rerun {
        return Err("--purge-cache requires --uninstall or --clean-rerun".to_owned());
    }
    Ok(())
}

fn run_inner(
    settings: &mut Settings,
    options: Options,
    started: &mut Started,
) -> Result<(), String> {
    debug_assert!(OPENSHELL_SOURCE_PIN.starts_with(SOURCE_MARKER));
    info(&format!(
        "release line: {} (the launcher passes the binary's channel; --dev/--base override)",
        settings.release_line
    ));
    info(&format!("state:  {}", settings.state_root.display()));
    info(&format!("config: {}", settings.config_root.display()));

    if !options.uninstall && settings.teardown_only != "1" {
        verify_provision_assets(settings)?;
        require_compatible_binary(
            &settings.gateway_bin,
            "openshell-gateway",
            &settings.locked_version,
        )?;
        require_compatible_binary(&settings.cli_bin, "openshell", &settings.locked_version)?;
        require_compatible_binary(
            &settings.driver_bin,
            "openshell-driver-vm",
            &settings.locked_version,
        )?;
        require_executable(
            &settings.sandbox_bin,
            &format!(
                "openbox-sandbox service not found at {} (set OPENBOX_SANDBOX_BIN to the downloaded release binary)",
                settings.sandbox_bin.display()
            ),
        )?;
        if !settings.policy_file.is_file() {
            return Err(format!(
                "policy file not found at {}",
                settings.policy_file.display()
            ));
        }
        prepare_dev_image(settings)?;
    }

    info("teardown (always)");
    stop_zot(settings)?;
    stop_pid_file(
        &settings.sandbox_pid_file,
        "sandbox service",
        settings
            .sandbox_bin
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default(),
        "",
        IdentityMode::BinaryName,
        &settings.service_ready_interval,
    )?;
    sweep_matching_listeners(
        &settings.sandbox_port,
        settings
            .sandbox_bin
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default(),
    );
    stop_pid_file(
        &settings.gateway_pid_file,
        "gateway",
        &settings.gateway_bin.to_string_lossy(),
        &settings.gateway_config.to_string_lossy(),
        IdentityMode::GatewayConfig,
        &settings.service_ready_interval,
    )?;
    assert_port_free(&settings.sandbox_port, "sandbox service")?;
    assert_port_free(&settings.gateway_port, "gateway")?;
    stop_scoped_vm_drivers(&settings.vm_driver_state_dir)?;
    ok("teardown complete");

    if settings.teardown_only == "1" {
        ok("stack teardown complete");
        return Ok(());
    }
    if options.uninstall || options.clean_rerun {
        state_clean(settings, options)?;
    }
    if options.uninstall {
        ok("uninstall complete — host equivalent to 'before provision'");
        return Ok(());
    }

    platform_preflight(settings)?;
    if let Some(pid) = start_registry(settings)? {
        started.zot_pid = Some(pid);
    }
    generate_gateway_pki(settings)?;
    write_gateway_files(settings)?;
    if settings.no_start == "1" {
        info("NO_START=1 — gateway config written, not started");
    } else {
        started.gateway = true;
        start_gateway(settings)?;
    }
    generate_service_pki(settings)?;
    write_service_config(settings)?;
    if settings.no_start == "1" {
        info("NO_START=1 — service not started");
    } else {
        started.service = true;
        start_service(settings)?;
    }
    write_agent_env(settings)?;
    warm_cache(settings)?;

    ok("provision complete");
    info(&format!(
        "gateway:   https://127.0.0.1:{}   (pid file: {})",
        settings.gateway_port,
        settings.gateway_pid_file.display()
    ));
    info(&format!(
        "service:   127.0.0.1:{}        (pid file: {})",
        settings.sandbox_port,
        settings.sandbox_pid_file.display()
    ));
    info(&format!("agent env: {}", settings.agent_env.display()));
    info("verify:    obs verify");
    Ok(())
}

impl Settings {
    fn from_environment() -> Result<Self, String> {
        let home = nonempty_env_path("HOME")
            .ok_or_else(|| "HOME is unset and provisioning roots were not provided".to_owned())?;
        let cwd = std::env::current_dir().map_err(|error| format!("cannot read cwd: {error}"))?;
        let launcher_dir = std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| cwd.clone());
        let release_line = env_or("OPENBOX_RELEASE_LINE", "base");
        let project_root =
            nonempty_env_path("OPENBOX_PROJECT_ROOT").unwrap_or_else(default_project_root);
        let bundle_dir = resolve_bundle_dir(&cwd, &project_root)?;
        let state_root = nonempty_env_path("OPENBOX_STATE_ROOT")
            .unwrap_or_else(|| home.join(".local/state/openbox-sandbox"));
        let config_root = nonempty_env_path("OPENBOX_CONFIG_ROOT")
            .unwrap_or_else(|| home.join(".config/openbox-sandbox"));
        create_private_dir(&state_root)?;
        create_private_dir(&config_root)?;
        let state_root = physical_path(&state_root)?;
        let config_root = physical_path(&config_root)?;

        let sandbox_bin = resolve_sandbox_binary(&bundle_dir, &project_root)?;
        let (policy_file, policy_id) =
            resolve_policy(&cwd, &launcher_dir, &project_root, &release_line)?;
        let dev_tar = resolve_dev_tar(&cwd, &launcher_dir)?;
        let (oci_layout, zot_bin) = resolve_registry_assets(&cwd, &launcher_dir)?;
        let gateway_port = env_or("OPENSHELL_SERVER_PORT", "17670");
        let gateway_name = env_or("OPENSHELL_GATEWAY_NAME", "openshell");
        let openshell_meta_dir = nonempty_env_path("OPENBOX_OPENSHELL_META_DIR")
            .unwrap_or_else(|| home.join(".config/openshell"));
        let vm_driver_state_dir = nonempty_env_path("OPENSHELL_VM_DRIVER_STATE_DIR")
            .unwrap_or_else(|| {
                home.join(format!(
                    ".local/state/openshell-vm-driver-{}-{gateway_name}",
                    env_or("USER", "user")
                ))
            });
        let tls_dir = nonempty_env_path("OPENSHELL_LOCAL_TLS_DIR")
            .unwrap_or_else(|| home.join(".local/state/openshell/tls"));
        let gateway_state_dir = state_root.join("gateway");
        let gateway_meta_dir = home.join(".config/openshell/gateways").join(&gateway_name);
        let gateway_mtls_dir = gateway_meta_dir.join("mtls");
        let sandbox_tls_dir = config_root.join("tls");
        let runtime_mtls_dir = nonempty_env_path("OPENBOX_RUNTIME_MTLS_DIR")
            .unwrap_or_else(|| config_root.join("runtime-mtls"));
        let (gateway_bin, cli_bin, driver_bin) =
            resolve_openshell_binaries(&cwd, &launcher_dir, &bundle_dir);
        let gateway_ready_polls = parse_i64_env("OPENBOX_GATEWAY_READY_POLLS", "60")?;
        let service_ready_polls = parse_i64_env("OPENBOX_SERVICE_READY_POLLS", "40")?;
        let warm_poll_count = parse_i64_env("OPENBOX_WARM_POLL_COUNT", "240")?;
        let warm_create_timeout = parse_u64_env("OPENBOX_WARM_CREATE_TIMEOUT", "300")?;
        let warm_get_timeout = parse_u64_env("OPENBOX_WARM_GET_TIMEOUT", "10")?;
        let warm_delete_timeout = parse_u64_env("OPENBOX_WARM_DELETE_TIMEOUT", "30")?;
        let vm_cache_default = platform_vm_cache_name();
        let explicit_sandbox_image = nonempty_env("OPENBOX_SANDBOX_IMAGE").is_some();

        Ok(Self {
            home,
            launcher_dir,
            release_line,
            sums_file: None,
            sandbox_bin,
            policy_file,
            policy_id,
            policy_version: env_or("OPENBOX_POLICY_VERSION", "1"),
            compatibility_id: env_or("OPENBOX_COMPAT_ID", "darwin-dev-1"),
            sandbox_image: env_or("OPENBOX_SANDBOX_IMAGE", DEFAULT_IMAGE),
            explicit_sandbox_image,
            dev_tar,
            dev_image_name: env_or("OPENBOX_DEV_IMAGE_NAME", "openbox-sandboxes-dev"),
            oci_layout,
            zot_bin,
            zot_port: env_or("OPENBOX_ZOT_PORT", "15000"),
            vm_cache_tar: env_or("OPENBOX_VM_CACHE_TAR", vm_cache_default),
            use_vm_cache: env_or("OPENBOX_USE_VM_CACHE", "1"),
            _vm_cache_hit_timeout: env_or("OPENBOX_VM_CACHE_HIT_TIMEOUT", "30"),
            purge_cache: env_or("OPENBOX_PURGE_CACHE", "0") == "1",
            locked_version: env_or("OPENBOX_OPENSHELL_LOCKED_VERSION", LOCKED_VERSION),
            gateway_bin,
            cli_bin,
            driver_bin,
            state_root: state_root.clone(),
            config_root: config_root.clone(),
            gateway_port,
            gateway_name,
            sandbox_port: env_or("OPENBOX_SANDBOX_PORT", "17443"),
            log_level: env_or("OPENSHELL_LOG_LEVEL", "info"),
            no_start: env_or("NO_START", "0"),
            teardown_only: env_or("OPENBOX_TEARDOWN_ONLY", "0"),
            cert_days: env_or("OPENBOX_CERT_DAYS", "825"),
            rsa_bits: env_or("OPENBOX_RSA_BITS", "2048"),
            jwt_ttl_secs: env_or("OPENBOX_JWT_TTL_SECS", "3600"),
            gateway_ready_polls,
            gateway_ready_interval: env_or("OPENBOX_GATEWAY_READY_INTERVAL", "0.5"),
            service_ready_polls,
            service_ready_interval: env_or("OPENBOX_SERVICE_READY_INTERVAL", "0.25"),
            warm_poll_count,
            warm_poll_interval: env_or("OPENBOX_WARM_POLL_INTERVAL", "5"),
            warm_create_timeout,
            warm_get_timeout,
            warm_delete_timeout,
            runtime_connect_timeout_ms: env_or("OPENBOX_RUNTIME_CONNECT_TIMEOUT_MS", "10000"),
            runtime_poll_interval_ms: env_or("OPENBOX_RUNTIME_POLL_INTERVAL_MS", "500"),
            reconcile_delete_deadline_ms: env_or("OPENBOX_RECONCILE_DELETE_DEADLINE_MS", "60000"),
            reconcile_wait_deadline_ms: env_or("OPENBOX_RECONCILE_WAIT_DEADLINE_MS", "60000"),
            maximum_connections: env_or("OPENBOX_MAX_CONNECTIONS", "64"),
            gateway_log_level: env_or("OPENBOX_GATEWAY_LOG_LEVEL", "info"),
            krun_log_level: env_or("OPENBOX_KRUN_LOG_LEVEL", "1"),
            driver_rust_log: std::env::var_os("OPENBOX_DRIVER_RUST_LOG")
                .filter(|value| !value.is_empty())
                .or_else(|| std::env::var_os("RUST_LOG")),
            drain_timeout_ms: env_or("OPENBOX_DRAIN_TIMEOUT_MS", "30000"),
            allow_degraded_landlock: env_or("OPENBOX_ALLOW_DEGRADED_LANDLOCK", "true"),
            caller_subject: env_or("OPENBOX_CALLER_SUBJ", "/CN=openbox-sandbox-runtime-caller"),
            runtime_mtls_dir,
            openshell_meta_dir,
            vm_driver_state_dir,
            tls_dir,
            gateway_state_dir: gateway_state_dir.clone(),
            gateway_meta_dir,
            gateway_mtls_dir,
            sandbox_tls_dir,
            sandbox_state_dir: state_root.join("cleanup"),
            service_config: config_root.join("service.json"),
            service_log: state_root.join("sandbox-service.log"),
            gateway_pid_file: gateway_state_dir.join("gateway.pid"),
            gateway_log: gateway_state_dir.join("gateway.log"),
            gateway_config: gateway_state_dir.join("gateway.toml"),
            sandbox_pid_file: state_root.join("sandbox-service.pid"),
            agent_env: config_root.join("agent.env"),
        })
    }
}

fn resolve_bundle_dir(cwd: &Path, project_root: &Path) -> Result<PathBuf, String> {
    let explicit = nonempty_env_path("OPENSHELL_BUNDLE_DIR");
    if let Some(path) = explicit.as_ref().filter(|path| path.is_absolute()) {
        return Ok(path.clone());
    }
    let mut base = if let Some(path) = explicit {
        physical_path(&cwd.join(path))?
    } else {
        project_root.join("openbox-sandbox-bundle")
    };
    if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        for candidate in [
            Some(base.clone()),
            Some(project_root.join("openbox-sandbox-bundle")),
            Some(cwd.join("openbox-sandbox-bundle")),
        ]
        .into_iter()
        .flatten()
        {
            if candidate.join("darwin-arm64").is_dir() {
                base = candidate.join("darwin-arm64");
                break;
            }
        }
    }
    Ok(base)
}

fn resolve_sandbox_binary(bundle_dir: &Path, project_root: &Path) -> Result<PathBuf, String> {
    let explicit = nonempty_env_path("OPENBOX_SANDBOX_BIN");
    let mut selected = match explicit {
        Some(path) if path.is_absolute() => path,
        Some(path) => project_root.join(path),
        None => project_root.join("target/release/openbox-sandbox"),
    };
    for candidate in [
        bundle_dir.join("openbox-sandbox-darwin-arm64"),
        bundle_dir.join("openbox-sandbox"),
    ] {
        if is_executable(&candidate) {
            selected = candidate;
            break;
        }
    }
    Ok(selected)
}

fn policy_defaults(release_line: &str) -> (&'static str, &'static str) {
    if release_line == "dev" {
        ("policy-allow-network-dev.yaml", "openbox-allow-network-dev")
    } else {
        ("policy-deny-network-dev.yaml", "openbox-deny-network-dev")
    }
}

fn resolve_policy(
    cwd: &Path,
    launcher_dir: &Path,
    project_root: &Path,
    release_line: &str,
) -> Result<(PathBuf, String), String> {
    let (template, default_id) = policy_defaults(release_line);
    let explicit = nonempty_env_path("OPENBOX_POLICY_FILE");
    let policy = if let Some(path) = explicit.as_ref().filter(|path| path.is_absolute()) {
        path.clone()
    } else {
        let mut found = None;
        for candidate in [
            explicit,
            Some(launcher_dir.join(template)),
            Some(cwd.join(template)),
            Some(project_root.join("deploy/policies").join(template)),
        ]
        .into_iter()
        .flatten()
        {
            if candidate.is_file() {
                found = Some(physical_file(&candidate)?);
                break;
            }
        }
        found.ok_or_else(|| {
            format!(
                "no policy template found for the {release_line} line (checked launcher dir {}, cwd, and repo defaults) — set OPENBOX_POLICY_FILE",
                launcher_dir.display()
            )
        })?
    };
    let explicit_id = nonempty_env("OPENBOX_POLICY_ID");
    let id = explicit_id.unwrap_or_else(|| {
        if policy
            .file_name()
            .is_some_and(|name| name.to_string_lossy().contains("allow"))
        {
            "openbox-allow-network-dev".to_owned()
        } else {
            default_id.to_owned()
        }
    });
    Ok((policy, id))
}

fn resolve_dev_tar(cwd: &Path, launcher_dir: &Path) -> Result<Option<PathBuf>, String> {
    let explicit = nonempty_env_path("OPENBOX_SANDBOX_DEV_TAR");
    if let Some(path) = explicit.as_ref().filter(|path| path.is_absolute()) {
        return Ok(Some(path.clone()));
    }
    let default_name = platform_dev_tar_name();
    for candidate in [
        explicit,
        Some(launcher_dir.join(default_name)),
        Some(cwd.join(default_name)),
    ]
    .into_iter()
    .flatten()
    {
        if candidate.is_file() {
            return physical_file(&candidate).map(Some);
        }
    }
    Ok(None)
}

fn resolve_registry_assets(
    cwd: &Path,
    launcher_dir: &Path,
) -> Result<(Option<PathBuf>, Option<PathBuf>), String> {
    if env_or("OPENBOX_USE_VM_CACHE", "1") != "1" {
        return Ok((
            nonempty_env_path("OPENBOX_OCI_LAYOUT"),
            nonempty_env_path("OPENBOX_ZOT_BIN"),
        ));
    }
    let (oci_default, zot_default) = platform_registry_names();
    let mut oci = nonempty_env_path("OPENBOX_OCI_LAYOUT");
    let mut zot = nonempty_env_path("OPENBOX_ZOT_BIN");
    if oci.is_none() && !oci_default.is_empty() {
        oci = [launcher_dir.join(oci_default), cwd.join(oci_default)]
            .into_iter()
            .find(|path| path.is_file());
    }
    if zot.is_none() && !zot_default.is_empty() {
        zot = [
            launcher_dir.join(zot_default),
            cwd.join(zot_default),
            launcher_dir.join("zot"),
            cwd.join("zot"),
        ]
        .into_iter()
        .find(|path| path.is_file());
    }
    Ok((oci, zot))
}

fn resolve_openshell_binaries(
    cwd: &Path,
    launcher_dir: &Path,
    bundle_dir: &Path,
) -> (PathBuf, PathBuf, PathBuf) {
    let mut gateway = first_executable([
        nonempty_env_path("OPENBOX_GATEWAY_BIN"),
        Some(launcher_dir.join("bin/openshell-gateway")),
        Some(cwd.join("bin/openshell-gateway")),
        Some(cwd.join("openshell-gateway")),
    ]);
    let mut cli = first_executable([
        nonempty_env_path("OPENBOX_CLI_BIN"),
        Some(launcher_dir.join("bin/openshell")),
        Some(cwd.join("bin/openshell")),
        Some(cwd.join("openshell")),
    ]);
    let mut driver = first_executable([
        nonempty_env_path("OPENBOX_DRIVER_BIN"),
        Some(launcher_dir.join("libexec/openshell-driver-vm")),
        Some(cwd.join("libexec/openshell-driver-vm")),
        Some(cwd.join("openshell-driver-vm")),
    ]);
    if (gateway.is_none() || cli.is_none() || driver.is_none())
        && nonempty_env_path("OPENSHELL_BIN_OVERRIDE").is_some_and(|path| path.is_dir())
    {
        let root = nonempty_env_path("OPENSHELL_BIN_OVERRIDE").unwrap_or_default();
        for (g, c, d) in [
            (
                root.join("bin/openshell-gateway"),
                root.join("bin/openshell"),
                root.join("libexec/openshell-driver-vm"),
            ),
            (
                root.join("openshell-gateway"),
                root.join("openshell"),
                root.join("openshell-driver-vm"),
            ),
        ] {
            if is_executable(&g) && is_executable(&c) && is_executable(&d) {
                gateway = Some(g);
                cli = Some(c);
                driver = Some(d);
                break;
            }
        }
    }
    (
        gateway.unwrap_or_else(|| bundle_dir.join("bin/openshell-gateway")),
        cli.unwrap_or_else(|| bundle_dir.join("bin/openshell")),
        driver.unwrap_or_else(|| bundle_dir.join("libexec/openshell-driver-vm")),
    )
}

fn first_executable<const N: usize>(paths: [Option<PathBuf>; N]) -> Option<PathBuf> {
    paths.into_iter().flatten().find(|path| is_executable(path))
}

fn verify_provision_assets(settings: &mut Settings) -> Result<(), String> {
    let sandbox_bin = settings.sandbox_bin.clone();
    let sandbox_name = sandbox_bin
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_owned();
    if let Err(reason) = verify_asset(&sandbox_bin, &sandbox_name, settings) {
        if !reason.contains(" is missing at ") {
            return Err(format!(
                "required service binary verification failed: {reason}"
            ));
        }
    }
    let policy = settings.policy_file.clone();
    let policy_name = policy
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_owned();
    verify_asset(&policy, &policy_name, settings)
        .map_err(|reason| format!("required policy verification failed: {reason}"))?;
    if let Some(dev_tar) = settings.dev_tar.clone() {
        let name = dev_tar
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_owned();
        verify_asset(&dev_tar, &name, settings)
            .map_err(|reason| format!("required dev tar verification failed: {reason}"))?;
    }
    if let Some(layout) = settings.oci_layout.clone() {
        let name = layout
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_owned();
        if let Err(reason) = verify_asset(&layout, &name, settings) {
            warn(&format!(
                "OCI layout verification failed ({reason}) — falling back to the container runtime path"
            ));
            settings.oci_layout = None;
        }
    }
    if let Some(zot) = &settings.zot_bin {
        let _ = chmod_executable(zot);
    }
    Ok(())
}

fn verify_asset(path: &Path, name: &str, settings: &mut Settings) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!(
            "{name} is missing at {}",
            if path.as_os_str().is_empty() {
                "<empty path>".to_owned()
            } else {
                path.display().to_string()
            }
        ));
    }
    let expected = published_checksum(name, settings)?;
    let Some(expected) = expected else {
        // The manifest is the root of trust. Without a published checksum the
        // file cannot be proven to be the release asset, so accepting it would
        // recreate the silent skip-hash bypass. Fail closed instead: the
        // operator re-runs once the manifest is reachable.
        return Err(format!(
            "{name}: no published checksum available (SHA256SUMS unreachable) — refusing to use an unverified copy"
        ));
    };
    let actual = sha256_file(path)?;
    if actual == expected {
        return Ok(());
    }
    let first_error = format!("sha256 mismatch for {name}: expected {expected}, got {actual}");
    warn(&format!("{first_error} — removing and re-downloading"));
    let was_executable = is_executable(path);
    remove_file_if_present(path)?;
    let tag = channel_tag(&settings.release_line);
    let parent = path
        .parent()
        .ok_or_else(|| format!("{first_error}; re-download from {tag} failed"))?;
    let downloaded = parent.join(name);
    let url =
        format!("https://github.com/OpenBox-AI/openbox-sandbox/releases/download/{tag}/{name}");
    if curl_retry3(&url, &downloaded).is_err() {
        return Err(format!("{first_error}; re-download from {tag} failed"));
    }
    if downloaded != path && downloaded.is_file() {
        fs::rename(&downloaded, path).map_err(|_| {
            format!(
                "{first_error}; re-download from {tag} did not produce {}",
                path.display()
            )
        })?;
    }
    if !path.is_file() {
        return Err(format!(
            "{first_error}; re-download from {tag} did not produce {}",
            path.display()
        ));
    }
    if was_executable {
        let _ = chmod_executable(path);
    }
    let downloaded_sha = sha256_file(path)?;
    if downloaded_sha != expected {
        warn(&format!(
            "sha256 mismatch for re-downloaded {name}: expected {expected}, got {downloaded_sha}"
        ));
        remove_file_if_present(path)?;
        return Err(format!(
            "sha256 mismatch for re-downloaded {name}: expected {expected}, got {downloaded_sha}"
        ));
    }
    ok(&format!(
        "{name} checksum verified after re-download ({expected})"
    ));
    Ok(())
}

fn published_checksum(name: &str, settings: &mut Settings) -> Result<Option<String>, String> {
    if settings.sums_file.is_none() {
        for candidate in [
            settings.launcher_dir.join("SHA256SUMS"),
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("SHA256SUMS"),
        ] {
            if candidate.is_file() {
                settings.sums_file = Some(candidate);
                break;
            }
        }
        if settings.sums_file.is_none() {
            let destination = std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("SHA256SUMS");
            let url = format!(
                "https://github.com/OpenBox-AI/openbox-sandbox/releases/download/{}/SHA256SUMS",
                channel_tag(&settings.release_line)
            );
            if curl_retry3(&url, &destination).is_ok() {
                settings.sums_file = Some(destination);
            }
        }
    }
    let Some(path) = &settings.sums_file else {
        return Ok(None);
    };
    let body = fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(body.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let candidate = fields.next()?.trim_start_matches('*');
        (candidate == name).then(|| digest.to_owned())
    }))
}

fn channel_tag(release_line: &str) -> &'static str {
    if release_line == "dev" {
        "v0.1.0-dev"
    } else {
        "v0.1.0"
    }
}

fn require_compatible_binary(path: &Path, label: &str, locked_version: &str) -> Result<(), String> {
    require_executable(
        path,
        &format!(
            "OpenShell binary missing: {} — re-run so the launcher can fetch the bundle",
            path.display()
        ),
    )?;
    let output = Command::new(path)
        .arg("--version")
        .output()
        .map_err(|error| format!("{label} --version failed: {error}"))?;
    let mut version = String::from_utf8_lossy(&output.stdout).to_string();
    version.push_str(&String::from_utf8_lossy(&output.stderr));
    let version = version.trim_end_matches(['\n', '\r']);
    if !output.status.success() {
        return Err(format!("{label} --version failed: {version}"));
    }
    if !version_has_source_marker(version) && !version.contains(locked_version) {
        return Err(format!(
            "incompatible {label}: '{version}'\nprovision: required OpenShell source marker {SOURCE_MARKER}\nprovision: or locked released version {locked_version}\nprovision: (the wire contract is proven by the live verify test)."
        ));
    }
    ok(&format!(
        "{label} verified ({SOURCE_MARKER} | {locked_version})"
    ));
    Ok(())
}

fn version_has_source_marker(version: &str) -> bool {
    version.match_indices(SOURCE_MARKER).any(|(index, marker)| {
        let prefix = &version[..index];
        let before = prefix.chars().next_back();
        let before_ok = if before == Some('g') {
            prefix[..prefix.len() - 1]
                .chars()
                .next_back()
                .is_none_or(|character| !character.is_ascii_hexdigit())
        } else {
            before.is_none_or(|character| !character.is_ascii_hexdigit())
        };
        let after = version[index + marker.len()..].chars().next();
        before_ok && after.is_none_or(|character| !character.is_ascii_hexdigit())
    })
}

fn prepare_dev_image(settings: &mut Settings) -> Result<(), String> {
    if settings.policy_id.contains("allow")
        && settings.dev_tar.is_none()
        && !command_success(
            "docker",
            &["image", "inspect", "openbox-sandboxes-dev:latest"],
        )
    {
        return Err(format!(
            "dev policy selected ({}) but no dev image is available — download the dev image tar first: ./obs update --all",
            settings.policy_id
        ));
    }
    if let Some(dev_tar) = settings.dev_tar.as_ref().filter(|_| {
        (settings.zot_bin.is_none() || settings.oci_layout.is_none())
            && !settings.explicit_sandbox_image
    }) {
        let runtime = resolve_runtime().ok_or_else(|| {
            "the dev image ref is host-less — the VM driver resolves it through a container runtime or a local registry. Install Docker/Podman, or ship the OCI layout + zot assets".to_owned()
        })?;
        info(&format!("container runtime: {runtime}"));
        let load = runtime_load(&runtime, dev_tar).map_err(|output| {
            err("dev image load failed — runtime output:");
            eprintln!("{output}");
            "dev image load failed".to_owned()
        })?;
        let digest =
            loaded_image_digest(&load, &runtime, &settings.dev_image_name).ok_or_else(|| {
                err("could not determine the loaded dev image digest — runtime output:");
                eprintln!("{load}");
                "the image tar may be malformed or the runtime refused the load".to_owned()
            })?;
        info(&format!("dev image digest: {digest}"));
        settings.sandbox_image = format!("{}:latest", settings.dev_image_name);
    }
    Ok(())
}

fn resolve_runtime() -> Option<String> {
    if let Some(runtime) = nonempty_env("CONTAINER_RUNTIME") {
        return command_exists(&runtime).then_some(runtime);
    }
    if command_exists("docker") && command_success("docker", &["ps"]) {
        return Some("docker".to_owned());
    }
    if command_exists("podman") && command_success("podman", &["ps"]) {
        return Some("podman".to_owned());
    }
    None
}

fn runtime_load(runtime: &str, tar: &Path) -> Result<String, String> {
    let mut unzip = Command::new("gunzip")
        .args([OsStr::new("-c"), tar.as_os_str()])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot run gunzip: {error}"))?;
    let input = unzip
        .stdout
        .take()
        .ok_or_else(|| "cannot pipe gunzip output".to_owned())?;
    let output = Command::new(runtime)
        .arg("load")
        .stdin(Stdio::from(input))
        .output()
        .map_err(|error| format!("cannot run {runtime} load: {error}"))?;
    let unzip_status = unzip
        .wait()
        .map_err(|error| format!("cannot wait for gunzip: {error}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    if output.status.success() && unzip_status.success() {
        Ok(text)
    } else {
        Err(text)
    }
}

fn loaded_image_digest(output: &str, runtime: &str, image: &str) -> Option<String> {
    for line in output.lines() {
        for marker in [
            "Loaded image ID: sha256:",
            &format!("Loaded image: {image}@sha256:"),
        ] {
            if let Some(rest) = line.split_once(marker).map(|(_, rest)| rest) {
                let hex: String = rest
                    .chars()
                    .take_while(|character| character.is_ascii_hexdigit())
                    .collect();
                if !hex.is_empty() {
                    return Some(format!("sha256:{hex}"));
                }
            }
        }
    }
    for args in [
        vec![
            "image",
            "inspect",
            &format!("{image}:latest"),
            "--format",
            "{{.Id}}",
        ],
        vec![
            "images",
            "--no-trunc",
            "--format",
            "{{.ID}}",
            &format!("{image}:latest"),
        ],
    ] {
        let output = Command::new(runtime).args(&args).output().ok()?;
        if output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or_default()
                .trim()
                .to_owned();
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IdentityMode {
    BinaryName,
    GatewayConfig,
}

fn process_command(pid: u32) -> String {
    Command::new("ps")
        .args(["-ww", "-p", &pid.to_string(), "-o", "command="])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default()
}

fn process_alive(pid: u32) -> bool {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "stat="])
        .output();
    output.is_ok_and(|output| {
        output.status.success()
            && String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .next()
                .is_some_and(|state| !state.starts_with('Z'))
    })
}

fn process_matches_command(
    command_line: &str,
    expected_binary: &str,
    required_marker: &str,
    mode: IdentityMode,
) -> bool {
    if command_line.is_empty() {
        return false;
    }
    let executable = command_line.split(' ').next().unwrap_or_default();
    match mode {
        IdentityMode::GatewayConfig => {
            Path::new(executable).file_name() == Some(OsStr::new("openshell-gateway"))
                && (command_line.ends_with(&format!(" --config {required_marker}"))
                    || command_line.contains(&format!(" --config {required_marker} ")))
        }
        IdentityMode::BinaryName => {
            Path::new(executable).file_name() == Some(OsStr::new(expected_binary))
        }
    }
}

fn stop_pid_file(
    file: &Path,
    label: &str,
    expected_binary: &str,
    required_marker: &str,
    mode: IdentityMode,
    interval: &str,
) -> Result<(), String> {
    if !file.is_file() {
        return Ok(());
    }
    let body = fs::read_to_string(file).unwrap_or_default();
    let pid = parse_pid_file(&body).map_err(|_| {
        format!(
            "{label} PID file is malformed at {}; refusing teardown",
            file.display()
        )
    })?;
    if !process_alive(pid) {
        warn(&format!(
            "{label} PID file is stale (pid={pid}); removing it"
        ));
        return remove_file_if_present(file);
    }
    if !process_matches_command(
        &process_command(pid),
        expected_binary,
        required_marker,
        mode,
    ) {
        let expected = if mode == IdentityMode::GatewayConfig {
            format!("openshell-gateway with exact launcher config {required_marker}")
        } else if required_marker.is_empty() {
            expected_binary.to_owned()
        } else {
            format!("{expected_binary} ... {required_marker}")
        };
        return Err(format!(
            "{label} PID {pid} does not match launcher command '{expected}'; refusing to signal it"
        ));
    }
    info(&format!("stopping validated {label} pid={pid}"));
    let _ = signal(pid, None);
    for _ in 0..20 {
        if !process_alive(pid) {
            break;
        }
        sleep_external(interval)?;
    }
    if process_alive(pid) {
        if !process_matches_command(
            &process_command(pid),
            expected_binary,
            required_marker,
            mode,
        ) {
            return Err(format!(
                "{label} PID {pid} changed identity while stopping; refusing SIGKILL"
            ));
        }
        let _ = signal(pid, Some("-9"));
    }
    remove_file_if_present(file)
}

fn parse_pid_file(body: &str) -> Result<u32, String> {
    let value = body.trim_end_matches('\n');
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("malformed PID file".to_owned());
    }
    value
        .parse::<u32>()
        .map_err(|_| "malformed PID file".to_owned())
}

fn sweep_matching_listeners(port: &str, expected_binary: &str) {
    if !command_exists("lsof") {
        return;
    }
    for pid in listening_pids(port) {
        let command_line = process_command(pid);
        let executable = command_line.split(' ').next().unwrap_or_default();
        if Path::new(executable).file_name() == Some(OsStr::new(expected_binary)) {
            warn(&format!(
                "killing stale {expected_binary} listener pid={pid} (port {port})"
            ));
            let _ = signal(pid, Some("-9"));
        }
    }
}

fn assert_port_free(port: &str, label: &str) -> Result<(), String> {
    if command_exists("lsof") {
        let pids = listening_pids(port);
        if pids.is_empty() {
            return Ok(());
        }
        warn(&format!(
            "{label} port {port} is still occupied; no unowned listener will be signalled"
        ));
        for pid in pids {
            let command_line = process_command(pid);
            warn(&format!(
                "listener pid={pid} command={}",
                if command_line.is_empty() {
                    "unknown"
                } else {
                    &command_line
                }
            ));
            if (command_line.contains("homebrew") && command_line.contains("openshell"))
                || command_line.contains("brew")
            {
                err("a Homebrew openshell is serving this port — stop it first:");
                err(&format!(
                    "  brew services stop openshell   # or: kill {pid}"
                ));
            } else {
                err("stop the process above and re-run");
            }
        }
        return Err(format!(
            "{label} port {port} remains occupied after validated PID teardown"
        ));
    }
    if port_listening(port) {
        Err(format!(
            "{label} port {port} is occupied and lsof is unavailable; refusing unowned teardown"
        ))
    } else {
        Ok(())
    }
}

fn listening_pids(port: &str) -> Vec<u32> {
    Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN", "-t"])
        .output()
        .ok()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| line.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

fn stop_scoped_vm_drivers(state_dir: &Path) -> Result<(), String> {
    if !command_exists("pgrep") {
        return Ok(());
    }
    let output = Command::new("pgrep")
        .args(["-f", "openshell-driver-vm --internal-run-vm"])
        .output();
    let pids: Vec<u32> = output
        .ok()
        .map(|output| {
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| line.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default();
    let mut scoped = Vec::new();
    for pid in pids {
        if pid == std::process::id() {
            continue;
        }
        let command_line = process_command(pid);
        if command_line.contains("openshell-driver-vm")
            && command_line.contains("--internal-run-vm")
            && command_line.contains(state_dir.to_string_lossy().as_ref())
        {
            info(&format!(
                "stopping launcher-scoped VM driver pid={pid} state={}",
                state_dir.display()
            ));
            let _ = signal(pid, None);
            scoped.push(pid);
        } else {
            warn(&format!(
                "leaving unrelated VM driver pid={pid} command={}",
                if command_line.is_empty() {
                    "unknown"
                } else {
                    &command_line
                }
            ));
        }
    }
    if !scoped.is_empty() {
        thread::sleep(Duration::from_secs(1));
    }
    for pid in scoped {
        if process_alive(pid) {
            return Err(format!(
                "launcher-scoped VM driver pid={pid} did not stop; refusing state deletion (command={})",
                process_command(pid)
            ));
        }
    }
    Ok(())
}

fn stop_zot(settings: &Settings) -> Result<(), String> {
    let pid_file = settings.state_root.join("zot/zot.pid");
    if !pid_file.is_file() {
        return Ok(());
    }
    if let Ok(body) = fs::read_to_string(&pid_file) {
        if let Ok(pid) = body.trim().parse::<u32>() {
            if process_alive(pid) {
                let _ = signal(pid, None);
                info(&format!("stopped local image registry (zot pid={pid})"));
            }
        }
    }
    remove_file_if_present(&pid_file)
}

fn state_clean(settings: &Settings, options: Options) -> Result<(), String> {
    info("removing launcher state");
    remove_tree(&settings.state_root)?;
    remove_tree(&settings.config_root)?;
    remove_tree(&settings.gateway_meta_dir)?;
    if options.uninstall || settings.purge_cache {
        remove_tree(&settings.vm_driver_state_dir)?;
    } else {
        preserve_images_only(&settings.vm_driver_state_dir)?;
    }
    if options.keep_pki {
        info(&format!(
            "--keep-pki: preserving {}",
            settings.tls_dir.display()
        ));
    } else {
        remove_tree(&settings.tls_dir)?;
    }
    let active = settings.home.join(".config/openshell/active_gateway");
    if fs::read_to_string(&active).is_ok_and(|body| body == settings.gateway_name) {
        remove_file_if_present(&active)?;
    }
    ok("state cleaned");
    Ok(())
}

fn preserve_images_only(state_dir: &Path) -> Result<(), String> {
    let entries = match fs::read_dir(state_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("cannot inspect {}: {error}", state_dir.display())),
    };
    for entry in entries {
        let path = entry
            .map_err(|error| format!("cannot inspect {}: {error}", state_dir.display()))?
            .path();
        if path.file_name() == Some(OsStr::new("images")) {
            continue;
        }
        if path.is_dir() {
            remove_tree(&path)?;
        } else {
            remove_file_if_present(&path)?;
        }
    }
    Ok(())
}

fn platform_preflight(settings: &Settings) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        if File::open("/dev/kvm").is_err() {
            return Err(format!(
                "/dev/kvm is not accessible — KVM is required for microVMs on Linux. Fix: usermod -aG kvm {}, log out and back in, or check your udev rules",
                env_or("USER", "user")
            ));
        }
        let glibc = Command::new("getconf")
            .arg("GNU_LIBC_VERSION")
            .output()
            .is_ok_and(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout)
                        .to_ascii_lowercase()
                        .starts_with("glibc ")
            })
            || Command::new("ldd")
                .arg("--version")
                .output()
                .is_ok_and(|output| {
                    let mut text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
                    text.push_str(&String::from_utf8_lossy(&output.stderr).to_ascii_lowercase());
                    text.contains("glibc") || text.contains("gnu libc")
                });
        if !glibc {
            return Err("glibc 2.28+ is required — this system appears to be musl-based (Alpine or similar), which the release binaries do not support".to_owned());
        }
        info("linux pre-flight ok (/dev/kvm readable, glibc present)");
    }
    #[cfg(target_os = "macos")]
    {
        if !command_exists("codesign") {
            return Err(
                "codesign not found — install Xcode Command Line Tools: xcode-select --install"
                    .to_owned(),
            );
        }
        let developer_mode = Command::new("DevToolsSecurity")
            .arg("-status")
            .output()
            .is_ok_and(|output| {
                let mut text = String::from_utf8_lossy(&output.stdout).to_string();
                text.push_str(&String::from_utf8_lossy(&output.stderr));
                text.contains("enabled")
            });
        if !developer_mode {
            return Err(
                "developer mode is disabled — run: sudo DevToolsSecurity -enable".to_owned(),
            );
        }
        info("codesigning openshell-driver-vm with the hypervisor entitlement");
        create_private_dir(&settings.state_root)?;
        let entitlements = settings.state_root.join("driver-vm.entitlements.plist");
        write_private(&entitlements, ENTITLEMENTS.as_bytes())?;
        // Captured, not inherited: codesign reports "replacing existing
        // signature" on every run, which is noise until it fails.
        let signed = Command::new("codesign")
            .args(["--entitlements"])
            .arg(&entitlements)
            .args(["--force", "-s", "-"])
            .arg(&settings.driver_bin)
            .output()
            .map_err(|error| format!("cannot run codesign: {error}"))?;
        let status = signed.status;
        if !status.success() {
            for line in String::from_utf8_lossy(&signed.stderr).lines() {
                err(line);
            }
            err("codesign failed — the hypervisor entitlement requires Xcode Command Line Tools and developer mode");
            info("run: xcode-select --install");
            info("then: DevToolsSecurity -enable");
            return Err("cannot sign the VM driver without developer tools".to_owned());
        }
        ok("driver-vm codesigned");
        ok("driver signed");
    }
    Ok(())
}

fn start_registry(settings: &mut Settings) -> Result<Option<u32>, String> {
    let (Some(layout), Some(zot_bin)) = (settings.oci_layout.as_ref(), settings.zot_bin.as_ref())
    else {
        return Ok(None);
    };
    let zot_dir = settings.state_root.join("zot");
    let layout_dir = zot_dir.join("layout");
    let tls_dir = zot_dir.join("tls");
    create_private_dir(&layout_dir)?;
    create_private_dir(&tls_dir)?;
    info(&format!(
        "runtime-agnostic image registry: serving the shipped OCI layout via zot on 127.0.0.1:{} (HTTPS)",
        settings.zot_port
    ));
    let status = Command::new("tar")
        .args([OsStr::new("-xzf"), layout.as_os_str(), OsStr::new("-C")])
        .arg(&layout_dir)
        .status()
        .map_err(|error| format!("cannot run tar: {error}"))?;
    if !status.success() {
        return Err(format!(
            "failed to extract the OCI layout ({})",
            layout.display()
        ));
    }
    run_openssl(
        [
            OsString::from("req"),
            OsString::from("-x509"),
            OsString::from("-newkey"),
            OsString::from("rsa:2048"),
            OsString::from("-keyout"),
            tls_dir.join("key.pem").into_os_string(),
            OsString::from("-out"),
            tls_dir.join("cert.pem").into_os_string(),
            OsString::from("-days"),
            OsString::from("825"),
            OsString::from("-nodes"),
            OsString::from("-subj"),
            OsString::from("/CN=127.0.0.1"),
            OsString::from("-addext"),
            OsString::from("subjectAltName=IP:127.0.0.1,DNS:localhost"),
        ],
        "failed to generate the registry TLS certificate",
    )?;
    chmod(&tls_dir.join("key.pem"), 0o600)?;
    chmod(&tls_dir.join("cert.pem"), 0o644)?;
    trust_registry_ca(settings, &tls_dir.join("cert.pem"))?;
    let config = format!(
        "{{\n  \"storage\": {{ \"rootDirectory\": \"{}\" }},\n  \"http\": {{\n    \"address\": \"127.0.0.1\",\n    \"port\": {},\n    \"tls\": {{ \"cert\": \"{}\", \"key\": \"{}\" }}\n  }},\n  \"log\": {{ \"level\": \"error\" }}\n}}\n",
        layout_dir.display(),
        settings.zot_port,
        tls_dir.join("cert.pem").display(),
        tls_dir.join("key.pem").display(),
    );
    let config_path = zot_dir.join("zot-config.json");
    write_private(&config_path, config.as_bytes())?;
    let log = create_log(&zot_dir.join("zot.log"))?;
    let stderr = log
        .try_clone()
        .map_err(|error| format!("cannot clone zot log: {error}"))?;
    let child = Command::new(zot_bin)
        .arg("serve")
        .arg(&config_path)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("cannot start zot: {error}"))?;
    let pid = child.id();
    if let Err(error) = write_private(&zot_dir.join("zot.pid"), format!("{pid}\n").as_bytes()) {
        let _ = signal(pid, None);
        return Err(error);
    }
    let ready_url = format!("https://127.0.0.1:{}/v2/", settings.zot_port);
    let mut ready = false;
    for _ in 0..20 {
        if curl_insecure_ok(&ready_url) {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    if !ready {
        err(&format!(
            "zot did not come up (log: {})",
            zot_dir.join("zot.log").display()
        ));
        let _ = signal(pid, None);
        return Err("local image registry failed to start".to_owned());
    }
    let manifest_url = format!(
        "https://127.0.0.1:{}/v2/openbox-sandboxes-dev/manifests/latest",
        settings.zot_port
    );
    let output = Command::new("curl")
        .args([
            "-skI",
            "-H",
            "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json",
            &manifest_url,
        ])
        .output()
        .map_err(|error| format!("cannot query local registry: {error}"))?;
    let digest = parse_manifest_digest(&output.stdout).ok_or_else(|| {
        err("could not read the manifest digest from the local registry");
        let _ = signal(pid, None);
        "local image registry has no manifest digest".to_owned()
    })?;
    settings.sandbox_image = format!(
        "127.0.0.1:{}/openbox-sandboxes-dev@{digest}",
        settings.zot_port
    );
    info(&format!(
        "dev image resolves via the local registry ({}) — no container runtime",
        settings.sandbox_image
    ));
    Ok(Some(pid))
}

fn trust_registry_ca(settings: &Settings, cert: &Path) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        // Captured: verify-cert prints a full trust report either way.
        let verified = Command::new("security")
            .args(["verify-cert", "-c"])
            .arg(cert)
            .args(["-p", "ssl"])
            .output()
            .is_ok_and(|output| output.status.success());
        let login = settings.home.join("Library/Keychains/login.keychain-db");
        let login_added = verified
            || Command::new("security")
                .args(["add-trusted-cert", "-d", "-r", "trustRoot", "-k"])
                .arg(&login)
                .arg(cert)
                .status()
                .is_ok_and(|status| status.success());
        if login_added {
            return Ok(());
        }
        info("registry CA needs system trust — prompting for sudo (this unlocks the local image registry)");
        let system_added = Command::new("sudo")
            .args([
                "-p",
                "sudo password required to trust the local image registry CA: ",
                "security",
                "add-trusted-cert",
                "-d",
                "-r",
                "trustRoot",
                "-k",
                "/Library/Keychains/System.keychain",
            ])
            .arg(cert)
            .status()
            .is_ok_and(|status| status.success());
        if system_added {
            info("registry CA trusted via the system keychain");
            return Ok(());
        }
        err("the registry CA could not be trusted");
        err("run once, then re-provision:");
        err(&format!(
            "  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}",
            cert.display()
        ));
        err("or unlock the login keychain: security unlock-keychain");
        Err("local image registry certificate is untrusted".to_owned())
    }
    #[cfg(not(target_os = "macos"))]
    {
        let cert_dir = settings.state_root.join("certs");
        create_private_dir(&cert_dir)?;
        fs::copy(cert, cert_dir.join("openbox-registry-ca.crt"))
            .map_err(|error| format!("cannot copy registry CA: {error}"))?;
        let copied = Command::new("sudo")
            .args(["-n", "cp"])
            .arg(cert)
            .arg("/usr/local/share/ca-certificates/openbox-registry-ca.crt")
            .status()
            .is_ok_and(|status| status.success());
        let updated = copied
            && Command::new("sudo")
                .args(["-n", "update-ca-certificates"])
                .status()
                .is_ok_and(|status| status.success());
        if !updated {
            warn("could not install the registry CA system-wide (sudo required) — the driver may reject the registry certificate");
        }
        Ok(())
    }
}

fn parse_manifest_digest(headers: &[u8]) -> Option<String> {
    String::from_utf8_lossy(headers).lines().find_map(|line| {
        let (name, value) = line.trim_end_matches('\r').split_once(':')?;
        name.eq_ignore_ascii_case("docker-content-digest")
            .then(|| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    })
}

fn generate_gateway_pki(settings: &Settings) -> Result<(), String> {
    info(&format!(
        "generating local PKI into {}",
        settings.tls_dir.display()
    ));
    create_private_dir(&settings.tls_dir)?;
    let status = Command::new(&settings.gateway_bin)
        .arg("generate-certs")
        .arg("--output-dir")
        .arg(&settings.tls_dir)
        .args([
            "--server-san",
            "127.0.0.1",
            "--server-san",
            "localhost",
            "--server-san",
            "host.openshell.internal",
            "--server-san",
            "host.containers.internal",
            "--server-san",
            "host.docker.internal",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot run generate-certs: {error}"))?;
    if !status.success() {
        return Err("generate-certs failed".to_owned());
    }
    harden_gateway_ca(settings)?;
    for key in [
        settings.tls_dir.join("ca.key"),
        settings.tls_dir.join("client/tls.key"),
        settings.tls_dir.join("server/tls.key"),
        settings.tls_dir.join("jwt/signing.pem"),
    ] {
        if key.is_file() {
            chmod(&key, 0o600)?;
        }
    }
    for certificate in [
        settings.tls_dir.join("ca.crt"),
        settings.tls_dir.join("client/tls.crt"),
        settings.tls_dir.join("server/tls.crt"),
    ] {
        if certificate.is_file() {
            chmod(&certificate, 0o644)?;
        }
    }

    create_private_dir(&settings.gateway_meta_dir)?;
    create_private_dir(&settings.gateway_mtls_dir)?;
    copy_mode(
        &settings.tls_dir.join("ca.crt"),
        &settings.gateway_mtls_dir.join("ca.crt"),
        0o644,
    )?;
    copy_mode(
        &settings.tls_dir.join("client/tls.crt"),
        &settings.gateway_mtls_dir.join("tls.crt"),
        0o644,
    )?;
    copy_mode(
        &settings.tls_dir.join("client/tls.key"),
        &settings.gateway_mtls_dir.join("tls.key"),
        0o600,
    )?;
    ok(&format!(
        "PKI ready (CA at {})",
        settings.tls_dir.join("ca.crt").display()
    ));
    Ok(())
}

fn harden_gateway_ca(settings: &Settings) -> Result<(), String> {
    let ca_cert = settings.tls_dir.join("ca.crt");
    let ca_key = settings.tls_dir.join("ca.key");
    let output = openssl_output([
        OsStr::new("x509"),
        OsStr::new("-in"),
        ca_cert.as_os_str(),
        OsStr::new("-noout"),
        OsStr::new("-subject"),
        OsStr::new("-nameopt"),
        OsStr::new("RFC2253"),
    ])?;
    let subject = ca_subject_from_rfc2253(&String::from_utf8_lossy(&output))?;
    let ext = settings.tls_dir.join("ca.ext");
    let csr = settings.tls_dir.join("ca.csr.tmp");
    let temporary_cert = settings.tls_dir.join("ca.crt.tmp");
    write_private(&ext, CA_EXT.as_bytes())?;
    run_openssl(
        [
            OsString::from("req"),
            OsString::from("-new"),
            OsString::from("-key"),
            ca_key.clone().into_os_string(),
            OsString::from("-subj"),
            OsString::from(subject),
            OsString::from("-out"),
            csr.clone().into_os_string(),
        ],
        "CA re-key CSR failed",
    )?;
    run_openssl(
        [
            OsString::from("x509"),
            OsString::from("-req"),
            OsString::from("-in"),
            csr.clone().into_os_string(),
            OsString::from("-signkey"),
            ca_key.into_os_string(),
            OsString::from("-out"),
            temporary_cert.clone().into_os_string(),
            OsString::from("-days"),
            OsString::from(&settings.cert_days),
            OsString::from("-extfile"),
            ext.clone().into_os_string(),
        ],
        "CA re-sign failed",
    )?;
    fs::rename(&temporary_cert, &ca_cert)
        .map_err(|error| format!("cannot replace {}: {error}", ca_cert.display()))?;
    remove_file_if_present(&csr)?;
    remove_file_if_present(&ext)?;
    let status = Command::new("openssl")
        .args(["verify", "-CAfile"])
        .arg(&ca_cert)
        .arg(&ca_cert)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot verify hardened CA: {error}"))?;
    if !status.success() {
        return Err("hardened CA failed self-verify".to_owned());
    }
    chmod(&ca_cert, 0o644)
}

fn ca_subject_from_rfc2253(output: &str) -> Result<String, String> {
    let value = output
        .trim()
        .strip_prefix("subject=")
        .unwrap_or(output.trim());
    if value.is_empty() {
        return Err("cannot parse gateway CA subject".to_owned());
    }
    Ok(value
        .split(',')
        .rev()
        .map(|component| format!("/{component}"))
        .collect())
}

fn write_gateway_files(settings: &mut Settings) -> Result<(), String> {
    create_private_dir(&settings.gateway_state_dir)?;
    create_private_dir(&settings.vm_driver_state_dir)?;
    settings.vm_driver_state_dir = physical_path(&settings.vm_driver_state_dir)?;
    settings.gateway_state_dir = physical_path(&settings.gateway_state_dir)?;
    settings.gateway_config = settings.gateway_state_dir.join("gateway.toml");
    settings.gateway_pid_file = settings.gateway_state_dir.join("gateway.pid");
    settings.gateway_log = settings.gateway_state_dir.join("gateway.log");
    let driver_dir = settings
        .driver_bin
        .parent()
        .unwrap_or_else(|| Path::new(""));
    let config = format!(
        "[openshell]\nversion = 1\n\n[openshell.gateway]\ncompute_drivers = [\"vm\"]\ndisable_tls = false\nlog_level = \"{}\"\n\n[openshell.gateway.auth]\nallow_unauthenticated_users = false\n\n[openshell.gateway.mtls_auth]\nenabled = true\n\n[openshell.gateway.gateway_jwt]\nsigning_key_path = \"{}/jwt/signing.pem\"\npublic_key_path = \"{}/jwt/public.pem\"\nkid_path = \"{}/jwt/kid\"\ngateway_id = \"{}\"\nttl_secs = {}\n\n[openshell.drivers.vm]\ndefault_image = \"{}\"\nkrun_log_level = {}\ngrpc_endpoint = \"https://host.containers.internal:{}\"\ndriver_dir = \"{}\"\nstate_dir = \"{}\"\nguest_tls_ca = \"{}/ca.crt\"\nguest_tls_cert = \"{}/client/tls.crt\"\nguest_tls_key = \"{}/client/tls.key\"\n",
        settings.gateway_log_level,
        settings.tls_dir.display(),
        settings.tls_dir.display(),
        settings.tls_dir.display(),
        settings.gateway_name,
        settings.jwt_ttl_secs,
        settings.sandbox_image,
        settings.krun_log_level,
        settings.gateway_port,
        driver_dir.display(),
        settings.vm_driver_state_dir.display(),
        settings.tls_dir.display(),
        settings.tls_dir.display(),
        settings.tls_dir.display(),
    );
    write_private(&settings.gateway_config, config.as_bytes())?;
    create_private_dir(&settings.gateway_meta_dir)?;
    let metadata = format!(
        "{{\n  \"name\": \"{}\",\n  \"gateway_endpoint\": \"https://127.0.0.1:{}\",\n  \"is_remote\": false,\n  \"gateway_port\": {},\n  \"auth_mode\": \"mtls\",\n  \"vm_driver_state_dir\": \"{}\"\n}}\n",
        settings.gateway_name,
        settings.gateway_port,
        settings.gateway_port,
        settings.vm_driver_state_dir.display(),
    );
    write_private(
        &settings.gateway_meta_dir.join("metadata.json"),
        metadata.as_bytes(),
    )?;
    create_private_dir(&settings.openshell_meta_dir)?;
    write_private(
        &settings.openshell_meta_dir.join("active_gateway"),
        settings.gateway_name.as_bytes(),
    )?;
    Ok(())
}

fn start_gateway(settings: &Settings) -> Result<(), String> {
    info(&format!(
        "starting gateway on https://127.0.0.1:{}",
        settings.gateway_port
    ));
    let log = create_log(&settings.gateway_log)?;
    let stderr = log
        .try_clone()
        .map_err(|error| format!("cannot clone gateway log: {error}"))?;
    let mut command = Command::new("nohup");
    command
        .arg(&settings.gateway_bin)
        .arg("--config")
        .arg(&settings.gateway_config)
        .arg("--port")
        .arg(&settings.gateway_port)
        .arg("--log-level")
        .arg(&settings.log_level)
        .args(["--drivers", "vm", "--db-url"])
        .arg(format!(
            "sqlite:{}/gateway.db?mode=rwc",
            settings.gateway_state_dir.display()
        ))
        .arg("--tls-cert")
        .arg(settings.tls_dir.join("server/tls.crt"))
        .arg("--tls-key")
        .arg(settings.tls_dir.join("server/tls.key"))
        .arg("--tls-client-ca")
        .arg(settings.tls_dir.join("ca.crt"))
        .args(["--enable-mtls-auth", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr));
    if let Some(rust_log) = &settings.driver_rust_log {
        command.env("RUST_LOG", rust_log);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            command.pre_exec(|| {
                unsafe extern "C" {
                    fn umask(mask: u32) -> u32;
                }
                umask(0o022);
                Ok(())
            });
        }
    }
    let child = command
        .spawn()
        .map_err(|error| format!("cannot start gateway: {error}"))?;
    let pid = child.id();
    if let Err(error) = write_private(&settings.gateway_pid_file, format!("{pid}\n").as_bytes()) {
        let _ = signal(pid, None);
        return Err(error);
    }
    for _ in 0..settings.gateway_ready_polls.max(0) {
        if port_listening(&settings.gateway_port) {
            ok(&format!("gateway up (pid={pid})"));
            return Ok(());
        }
        sleep_external(&settings.gateway_ready_interval)?;
    }
    err(&format!(
        "gateway failed to become ready after {} polls; log content ({}):",
        settings.gateway_ready_polls,
        settings.gateway_log.display()
    ));
    print_log_tail(&settings.gateway_log, 20);
    if !process_alive(pid) {
        err("the gateway process is no longer alive — it exited during startup");
    }
    Err("gateway failed to become ready".to_owned())
}

fn generate_service_pki(settings: &mut Settings) -> Result<(), String> {
    info("generating runtime-caller mTLS pair");
    create_private_dir(&settings.sandbox_tls_dir)?;
    let client_key = settings.sandbox_tls_dir.join("client.key");
    let client_csr = settings.sandbox_tls_dir.join("client.csr");
    let client_ext = settings.sandbox_tls_dir.join("client.ext");
    let client_cert = settings.sandbox_tls_dir.join("client.crt");
    run_openssl(
        [
            OsString::from("genrsa"),
            OsString::from("-out"),
            client_key.clone().into_os_string(),
            OsString::from(&settings.rsa_bits),
        ],
        "caller key generation failed",
    )?;
    run_openssl(
        [
            OsString::from("req"),
            OsString::from("-new"),
            OsString::from("-key"),
            client_key.clone().into_os_string(),
            OsString::from("-subj"),
            OsString::from(&settings.caller_subject),
            OsString::from("-out"),
            client_csr.clone().into_os_string(),
        ],
        "caller CSR failed",
    )?;
    write_private(&client_ext, CLIENT_EXT.as_bytes())?;
    sign_leaf(
        settings,
        &client_csr,
        &client_ext,
        None,
        &client_cert,
        "caller cert sign failed",
    )?;
    copy_mode(
        &settings.tls_dir.join("ca.crt"),
        &settings.sandbox_tls_dir.join("ca.crt"),
        0o644,
    )?;
    chmod(&client_key, 0o600)?;
    chmod(&client_cert, 0o644)?;
    remove_file_if_present(&client_csr)?;

    let server_key = settings.sandbox_tls_dir.join("server.key");
    let server_csr = settings.sandbox_tls_dir.join("server.csr");
    let server_cnf = settings.sandbox_tls_dir.join("server.cnf.tmp");
    let server_cert = settings.sandbox_tls_dir.join("server.crt");
    run_openssl(
        [
            OsString::from("genrsa"),
            OsString::from("-out"),
            server_key.clone().into_os_string(),
            OsString::from(&settings.rsa_bits),
        ],
        "server key generation failed",
    )?;
    write_private(&server_cnf, SERVER_CNF.as_bytes())?;
    run_openssl(
        [
            OsString::from("req"),
            OsString::from("-new"),
            OsString::from("-key"),
            server_key.clone().into_os_string(),
            OsString::from("-config"),
            server_cnf.clone().into_os_string(),
            OsString::from("-out"),
            server_csr.clone().into_os_string(),
        ],
        "server CSR failed",
    )?;
    sign_leaf(
        settings,
        &server_csr,
        &server_cnf,
        Some("v3_req"),
        &server_cert,
        "server cert sign failed",
    )?;
    chmod(&server_key, 0o600)?;
    chmod(&server_cert, 0o644)?;
    remove_file_if_present(&server_csr)?;
    remove_file_if_present(&server_cnf)?;

    create_private_dir(&settings.runtime_mtls_dir)?;
    settings.runtime_mtls_dir = physical_path(&settings.runtime_mtls_dir)?;
    copy_mode(
        &settings.tls_dir.join("ca.crt"),
        &settings.runtime_mtls_dir.join("ca.crt"),
        0o600,
    )?;
    copy_mode(
        &settings.tls_dir.join("client/tls.crt"),
        &settings.runtime_mtls_dir.join("tls.crt"),
        0o600,
    )?;
    copy_mode(
        &settings.tls_dir.join("client/tls.key"),
        &settings.runtime_mtls_dir.join("tls.key"),
        0o600,
    )?;
    Ok(())
}

fn sign_leaf(
    settings: &Settings,
    csr: &Path,
    ext: &Path,
    extensions: Option<&str>,
    output: &Path,
    message: &str,
) -> Result<(), String> {
    let mut args = vec![
        OsString::from("x509"),
        OsString::from("-req"),
        OsString::from("-sha256"),
        OsString::from("-days"),
        OsString::from(&settings.cert_days),
        OsString::from("-in"),
        csr.as_os_str().to_owned(),
        OsString::from("-CA"),
        settings.tls_dir.join("ca.crt").into_os_string(),
        OsString::from("-CAkey"),
        settings.tls_dir.join("ca.key").into_os_string(),
        OsString::from("-CAcreateserial"),
        OsString::from("-extfile"),
        ext.as_os_str().to_owned(),
    ];
    if let Some(section) = extensions {
        args.push(OsString::from("-extensions"));
        args.push(OsString::from(section));
    }
    args.push(OsString::from("-out"));
    args.push(output.as_os_str().to_owned());
    run_openssl(args, message)
}

fn write_service_config(settings: &Settings) -> Result<(), String> {
    let caller_der = openssl_output([
        OsStr::new("x509"),
        OsStr::new("-in"),
        settings.sandbox_tls_dir.join("client.crt").as_os_str(),
        OsStr::new("-outform"),
        OsStr::new("DER"),
    ])?;
    let caller_fp = sha256_bytes(&caller_der)?;
    let adapter_sha = sha256_file(&settings.sandbox_bin)?;
    let policy_sha = sha256_file(&settings.policy_file)?;
    ok(&format!("caller fingerprint: {caller_fp}"));
    ok(&format!("adapter sha:        {adapter_sha}"));
    ok(&format!("policy sha:         {policy_sha}"));
    info(&format!(
        "writing sandbox service config -> {}",
        settings.service_config.display()
    ));
    create_private_dir(&settings.sandbox_state_dir)?;
    create_private_dir(&settings.config_root)?;
    let config = format!(
        "{{\n  \"bind_address\": \"127.0.0.1:{}\",\n  \"server_certificate_path\": \"{}/server.crt\",\n  \"server_private_key_path\": \"{}/server.key\",\n  \"client_ca_path\": \"{}/ca.crt\",\n  \"authorized_callers\": [\n    {{\"certificate_sha256\": \"{}\", \"role\": \"runtime\"}}\n  ],\n  \"state_directory\": \"{}\",\n  \"provider\": \"openshell\",\n  \"provider_capability\": \"attested\",\n  \"asset_bundle\": {{\n    \"runtime_contract_version\": 1,\n    \"adapter_build_sha256\": \"{}\",\n    \"template\": \"{}\",\n    \"policy\": {{\"id\": \"{}\", \"version\": {}, \"sha256\": \"{}\"}},\n    \"compatibility_id\": \"{}\"\n  }},\n  \"runtime_endpoint\": \"https://127.0.0.1:{}\",\n  \"runtime_mtls_directory\": \"{}\",\n  \"runtime_connect_timeout_ms\": {},\n  \"runtime_poll_interval_ms\": {},\n  \"reconcile_delete_deadline_ms\": {},\n  \"reconcile_wait_deadline_ms\": {},\n  \"maximum_connections\": {},\n  \"drain_timeout_ms\": {},\n  \"allow_degraded_landlock\": {}\n}}\n",
        settings.sandbox_port,
        settings.sandbox_tls_dir.display(),
        settings.sandbox_tls_dir.display(),
        settings.sandbox_tls_dir.display(),
        caller_fp,
        settings.sandbox_state_dir.display(),
        adapter_sha,
        settings.sandbox_image,
        settings.policy_id,
        settings.policy_version,
        policy_sha,
        settings.compatibility_id,
        settings.gateway_port,
        settings.runtime_mtls_dir.display(),
        settings.runtime_connect_timeout_ms,
        settings.runtime_poll_interval_ms,
        settings.reconcile_delete_deadline_ms,
        settings.reconcile_wait_deadline_ms,
        settings.maximum_connections,
        settings.drain_timeout_ms,
        settings.allow_degraded_landlock,
    );
    write_private(&settings.service_config, config.as_bytes())?;
    ok("service config written");
    Ok(())
}

fn start_service(settings: &Settings) -> Result<(), String> {
    info(&format!(
        "starting sandbox service on 127.0.0.1:{}",
        settings.sandbox_port
    ));
    let log = create_log(&settings.service_log)?;
    let stderr = log
        .try_clone()
        .map_err(|error| format!("cannot clone service log: {error}"))?;
    let child = Command::new("nohup")
        .arg(&settings.sandbox_bin)
        .env("OPENBOX_SANDBOX_CONFIG", &settings.service_config)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|error| format!("cannot start sandbox service: {error}"))?;
    let pid = child.id();
    if let Err(error) = write_private(&settings.sandbox_pid_file, format!("{pid}\n").as_bytes()) {
        let _ = signal(pid, None);
        return Err(error);
    }
    let mut ready = false;
    for _ in 0..settings.service_ready_polls.max(0) {
        if port_listening(&settings.sandbox_port) {
            ok(&format!("service up (pid={pid})"));
            ready = true;
            break;
        }
        sleep_external(&settings.service_ready_interval)?;
    }
    if !ready {
        err(&format!(
            "sandbox service failed to become ready after {} polls; log content ({}):",
            settings.service_ready_polls,
            settings.service_log.display()
        ));
        print_log_tail(&settings.service_log, 20);
        return Err("sandbox service failed to become ready".to_owned());
    }
    let status = Command::new(&settings.sandbox_bin)
        .arg("--check-config")
        .env("OPENBOX_SANDBOX_CONFIG", &settings.service_config)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("running service rejected --check-config: {error}"))?;
    if !status.success() {
        return Err("running service rejected --check-config".to_owned());
    }
    ok("running service validates --check-config");
    Ok(())
}

fn write_agent_env(settings: &Settings) -> Result<(), String> {
    info(&format!(
        "emitting agent env -> {}",
        settings.agent_env.display()
    ));
    let adapter_sha = sha256_file(&settings.sandbox_bin)?;
    let policy_sha = sha256_file(&settings.policy_file)?;
    let timestamp = utc_timestamp();
    let body = format!(
        "# OpenBox SDK agent environment. Source this file (or copy the values) into\n# your agent's runtime — these are the credentials and parameters the SDK\n# needs to drive the local sandbox service over mutual TLS.\n#\n#   set -a; source {}; set +a\n#\n# Generated by obs at {timestamp}.\n# A clean-state rerun reproduces this schema; fresh PKI and timestamps differ.\n\n# Sandbox service boundary (mTLS, loopback).\nOPENBOX_SANDBOX_ENDPOINT=127.0.0.1:{}\nOPENBOX_SANDBOX_SERVER_NAME=localhost\nOPENBOX_SANDBOX_CA={}/ca.crt\nOPENBOX_SANDBOX_CERT={}/client.crt\nOPENBOX_SANDBOX_KEY={}/client.key\n\n# Service artifact and asset bundle identity.\nOPENBOX_SANDBOX_BINARY={}\nOPENBOX_SANDBOX_ADAPTER_SHA={}\nOPENBOX_SANDBOX_TEMPLATE={}\nOPENBOX_SANDBOX_POLICY_FILE={}\nOPENBOX_SANDBOX_POLICY_ID={}\nOPENBOX_SANDBOX_POLICY_VERSION={}\nOPENBOX_SANDBOX_POLICY_SHA256={}\nOPENBOX_SANDBOX_COMPAT_ID={}\n\n# Discovery anchors.\nOPENBOX_SANDBOX_CONFIG_PATH={}\nOPENBOX_GATEWAY_ENDPOINT=https://127.0.0.1:{}\n",
        settings.agent_env.display(),
        settings.sandbox_port,
        settings.sandbox_tls_dir.display(),
        settings.sandbox_tls_dir.display(),
        settings.sandbox_tls_dir.display(),
        settings.sandbox_bin.display(),
        adapter_sha,
        settings.sandbox_image,
        settings.policy_file.display(),
        settings.policy_id,
        settings.policy_version,
        policy_sha,
        settings.compatibility_id,
        settings.service_config.display(),
        settings.gateway_port,
    );
    write_private(&settings.agent_env, body.as_bytes())?;
    ok("agent.env written");
    Ok(())
}

fn warm_cache(settings: &mut Settings) -> Result<(), String> {
    if env_or("OPENBOX_WARM_CACHE", "1") == "0" {
        info("cache warm skipped (OPENBOX_WARM_CACHE=0)");
        return Ok(());
    }
    if settings.no_start == "1" {
        info("cache warm skipped (NO_START=1; stack not started)");
        return Ok(());
    }
    if !is_executable(&settings.cli_bin) {
        warn(&format!(
            "cache warm skipped (no CLI at {})",
            settings.cli_bin.display()
        ));
        return Ok(());
    }
    let mut cache_prepared = try_shipped_vm_cache(settings)?;
    let mut runtime = None;
    if !cache_prepared {
        runtime = resolve_runtime();
        if runtime.is_none() {
            return Err("no prepared VM cache and no container runtime available — install Docker or Podman (or re-run once the cache asset is present) and re-run".to_owned());
        }
    }
    ensure_e2fsprogs(settings)?;
    info(&format!(
        "warming VM driver image cache ({})...",
        settings.sandbox_image
    ));
    if settings.sandbox_image.starts_with("ghcr.io/") {
        warn("no dev image tar detected — the driver will PULL FROM ghcr.io on first warm");
        warn(
            "if the pull fails (offline/slow network), download the dev image: ./obs update --all",
        );
    }
    remove_old_warm_logs(&settings.state_root);
    let start = Instant::now();
    let mut warm_name = format!("w{}", unix_seconds());
    let mut warm_log = settings.state_root.join(format!("warm-{warm_name}.log"));
    let first = warm_attempt(settings, &warm_name, &warm_log, start)?;
    if first {
        if cache_prepared {
            ok(&format!(
                "prepared VM cache hit — warm completed in {}s (no image pull or build)",
                start.elapsed().as_secs()
            ));
        } else {
            ok(&format!("cache warmed: {warm_name}"));
        }
    } else {
        if cache_prepared {
            err("prepared VM cache MISS — the driver rejected or failed it; falling back to the runtime path (the extracted cache is left in place — remove it manually if you want it gone)");
            cache_prepared = false;
        }
        if !cache_prepared {
            runtime = runtime.or_else(resolve_runtime);
            if let Some(runtime) = runtime {
                info(&format!(
                    "first warm attempt failed — retrying via the container runtime ({runtime})"
                ));
                if let Some(dev_tar) = &settings.dev_tar {
                    if runtime_load(&runtime, dev_tar).is_err() {
                        warn("dev image load failed during the fallback retry — the driver may still resolve it if already loaded");
                    }
                }
                warm_name = format!("w{}r", unix_seconds());
                warm_log = settings.state_root.join(format!("warm-{warm_name}.log"));
                if warm_attempt(settings, &warm_name, &warm_log, start)? {
                    ok(&format!(
                        "cache warmed via the runtime fallback: {warm_name}"
                    ));
                } else {
                    warn(&format!(
                        "runtime-fallback warm also failed (log: {}); first request may be slow",
                        warm_log.display()
                    ));
                }
            } else if file_empty(&warm_log) {
                warn(&format!(
                    "warm sandbox did not reach ready in {}s; first request may be slow",
                    start.elapsed().as_secs()
                ));
            }
        }
    }
    let mut delete = Command::new(&settings.cli_bin);
    delete.args(["sandbox", "delete", &warm_name]);
    if !run_with_timeout(&mut delete, settings.warm_delete_timeout, None)?
        .status
        .success()
    {
        warn(&format!(
            "warm sandbox {warm_name} delete failed (gateway will reap it)"
        ));
    }
    Ok(())
}

fn try_shipped_vm_cache(settings: &mut Settings) -> Result<bool, String> {
    if settings.use_vm_cache != "1" || settings.vm_cache_tar.is_empty() {
        return Ok(false);
    }
    let raw = PathBuf::from(&settings.vm_cache_tar);
    let mut selected = raw.clone();
    if !raw.is_file() {
        for candidate in [
            settings.launcher_dir.join(&settings.vm_cache_tar),
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(&settings.vm_cache_tar),
        ] {
            if candidate.is_file() {
                selected = candidate;
                break;
            }
        }
    }
    if !selected.is_file() {
        return Ok(false);
    }
    let name = selected
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_owned();
    if let Err(reason) = verify_asset(&selected, &name, settings) {
        warn(&format!(
            "prepared cache verification failed ({reason}) — falling back to the runtime path"
        ));
        return Ok(false);
    }
    info(&format!(
        "prepared VM cache found ({}) — extracting into {}/images",
        selected.display(),
        settings.vm_driver_state_dir.display()
    ));
    let images = settings.vm_driver_state_dir.join("images");
    create_private_dir(&images)?;
    let status = Command::new("tar")
        .args([OsStr::new("-xzf"), selected.as_os_str(), OsStr::new("-C")])
        .arg(&images)
        .status()
        .map_err(|error| format!("cannot run tar: {error}"))?;
    if !status.success() {
        warn("prepared cache extraction failed — falling back to the runtime path");
        return Ok(false);
    }
    Ok(true)
}

fn ensure_e2fsprogs(settings: &Settings) -> Result<(), String> {
    if find_e2fs_tools().is_some() {
        return Ok(());
    }
    if command_exists("brew") {
        let log_path = settings.state_root.join("brew-e2fsprogs.log");
        let log = create_log(&log_path)?;
        let stderr = log
            .try_clone()
            .map_err(|error| format!("cannot clone brew log: {error}"))?;
        info(&format!(
            "installing e2fsprogs via Homebrew (may take a few minutes; log: {})",
            log_path.display()
        ));
        let status = Command::new("brew")
            .args(["install", "e2fsprogs"])
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr))
            .status()
            .map_err(|error| format!("cannot run brew: {error}"))?;
        if !status.success() {
            err(&format!(
                "brew install failed — log tail ({}):",
                log_path.display()
            ));
            print_log_tail(&log_path, 15);
            return Err(
                "brew install e2fsprogs failed — install it manually and re-run".to_owned(),
            );
        }
        ok(&format!(
            "e2fsprogs installed (full log: {})",
            log_path.display()
        ));
    }
    let Some((mkfs, debugfs)) = find_e2fs_tools() else {
        return Err("e2fsprogs (mkfs.ext4 + debugfs) is required by the VM driver — install it manually: brew install e2fsprogs".to_owned());
    };
    ok(&format!(
        "e2fsprogs ready (mkfs={} debugfs={})",
        mkfs.display(),
        debugfs.display()
    ));
    Ok(())
}

fn find_e2fs_tools() -> Option<(PathBuf, PathBuf)> {
    let mut mkfs = find_command("mkfs.ext4").or_else(|| find_command("mke2fs"));
    let mut debugfs = find_command("debugfs");
    for root in [
        Path::new("/opt/homebrew/opt/e2fsprogs"),
        Path::new("/usr/local/opt/e2fsprogs"),
    ] {
        for sub in ["sbin", "bin"] {
            if mkfs.is_none() {
                mkfs = ["mkfs.ext4", "mke2fs"]
                    .into_iter()
                    .map(|name| root.join(sub).join(name))
                    .find(|path| is_executable(path));
            }
            if debugfs.is_none() {
                let candidate = root.join(sub).join("debugfs");
                if is_executable(&candidate) {
                    debugfs = Some(candidate);
                }
            }
        }
    }
    mkfs.zip(debugfs)
}

fn warm_attempt(
    settings: &Settings,
    name: &str,
    log: &Path,
    start: Instant,
) -> Result<bool, String> {
    let mut create = Command::new(&settings.cli_bin);
    create.args(["sandbox", "create", "--name", name, "--", "/bin/true"]);
    let create_output = run_with_timeout(&mut create, settings.warm_create_timeout, None)?;
    let mut body = create_output.stdout;
    body.extend_from_slice(&create_output.stderr);
    write_private(log, &body)?;
    if !create_output.status.success() {
        warn(&format!(
            "warm sandbox create exited non-zero (CLI timeout or validation failure); see {} — polling by name",
            log.display()
        ));
    }
    let mut saw_once = false;
    let mut last_phase = String::new();
    let mut heartbeat = 0;
    for _ in 0..settings.warm_poll_count.max(0) {
        let mut get = Command::new(&settings.cli_bin);
        get.args(["sandbox", "get", name]);
        let output = run_with_timeout(&mut get, settings.warm_get_timeout, None)?;
        if !output.status.success() {
            if saw_once {
                info(&format!(
                    "warm sandbox {name} completed and reaped (elapsed {}s)",
                    start.elapsed().as_secs()
                ));
                return Ok(true);
            }
        } else {
            let status = String::from_utf8_lossy(&output.stdout).to_string();
            if !status.is_empty() {
                saw_once = true;
                if let Some(phase) = status_phase(&status) {
                    if phase != last_phase {
                        info(&format!(
                            "warm progress: phase={phase} elapsed={}s",
                            start.elapsed().as_secs()
                        ));
                        last_phase = phase.to_owned();
                        heartbeat = 0;
                    }
                }
            }
            let lowercase = status.to_ascii_lowercase();
            if ["ready", "running", "deleting"]
                .iter()
                .any(|phase| lowercase.contains(phase))
            {
                return Ok(true);
            }
            if lowercase.contains("error") || lowercase.contains("failed") {
                err(&format!(
                    "warm sandbox entered a terminal error state; log content ({}):",
                    log.display()
                ));
                print_log_tail(log, 20);
                return Ok(false);
            }
        }
        heartbeat += 1;
        if heartbeat % 6 == 0 {
            info(&format!(
                "still warming… elapsed={}s phase={}",
                start.elapsed().as_secs(),
                if last_phase.is_empty() {
                    "waiting-for-gateway"
                } else {
                    &last_phase
                }
            ));
        }
        sleep_external(&settings.warm_poll_interval)?;
    }
    Ok(false)
}

fn status_phase(status: &str) -> Option<&'static str> {
    let lower = status.to_ascii_lowercase();
    [
        "provisioning",
        "pulling",
        "booting",
        "starting",
        "creating",
        "ready",
        "running",
        "deleting",
        "error",
    ]
    .into_iter()
    .find(|phase| lower.contains(phase))
}

fn run_with_timeout(
    command: &mut Command,
    seconds: u64,
    output_file: Option<&Path>,
) -> Result<Output, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start command: {error}"))?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        if child
            .try_wait()
            .map_err(|error| format!("cannot wait for command: {error}"))?
            .is_some()
        {
            let output = child
                .wait_with_output()
                .map_err(|error| format!("cannot collect command output: {error}"))?;
            if let Some(path) = output_file {
                let mut body = output.stdout.clone();
                body.extend_from_slice(&output.stderr);
                write_private(path, &body)?;
            }
            return Ok(output);
        }
        if Instant::now() >= deadline {
            let _ = signal(child.id(), Some("-9"));
            let output = child
                .wait_with_output()
                .map_err(|error| format!("cannot collect timed-out command: {error}"))?;
            if let Some(path) = output_file {
                let mut body = output.stdout.clone();
                body.extend_from_slice(&output.stderr);
                write_private(path, &body)?;
            }
            return Ok(output);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn run_openssl<I, S>(args: I, message: &str) -> Result<(), String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let status = Command::new("openssl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("{message}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(message.to_owned())
    }
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
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!("openssl exited {}", output.status))
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
    if output.status.success() {
        parse_openssl_digest(&output.stdout)
    } else {
        Err(format!("openssl exited {}", output.status))
    }
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
        Err("cannot parse openssl SHA-256 output".to_owned())
    }
}

fn physical_path(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve physical path {}: {error}", path.display()))
}

fn physical_file(path: &Path) -> Result<PathBuf, String> {
    fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve physical path {}: {error}", path.display()))
}

fn create_private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|error| format!("cannot create directory {}: {error}", path.display()))?;
    chmod(path, 0o700)
}

fn write_private(path: &Path, body: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create directory {}: {error}", parent.display()))?;
    }
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

fn create_log(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    chmod(path, 0o600)?;
    Ok(file)
}

fn copy_mode(source: &Path, destination: &Path, mode: u32) -> Result<(), String> {
    fs::copy(source, destination).map_err(|error| {
        format!(
            "cannot copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    chmod(destination, mode)
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

fn chmod_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path)
            .map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
        chmod(path, metadata.permissions().mode() | 0o111)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
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

fn find_command(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| is_executable(candidate))
    })
}

fn command_exists(name: &str) -> bool {
    find_command(name).is_some()
}

fn command_success(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn signal(pid: u32, signal: Option<&str>) -> Result<(), String> {
    let mut command = Command::new("kill");
    if let Some(signal) = signal {
        command.arg(signal);
    }
    let status = command
        .arg(pid.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot run kill: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("kill exited {status}"))
    }
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

fn curl_retry3(url: &str, destination: &Path) -> Result<(), String> {
    let status = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(destination)
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot run curl: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("curl exited {status}"))
    }
}

fn curl_insecure_ok(url: &str) -> bool {
    Command::new("curl")
        .args(["-skf", url])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn remove_old_warm_logs(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    for path in entries.flatten().map(|entry| entry.path()) {
        let is_warm_log = path.file_name().is_some_and(|name| {
            let name = name.to_string_lossy();
            name.starts_with("warm-") && name.ends_with(".log")
        });
        if is_warm_log
            && path
                .metadata()
                .and_then(|metadata| metadata.modified())
                .is_ok_and(|modified| modified < cutoff)
        {
            let _ = fs::remove_file(path);
        }
    }
}

fn file_empty(path: &Path) -> bool {
    path.metadata().is_ok_and(|metadata| metadata.len() == 0)
}

fn utc_timestamp() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| unix_seconds().to_string())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn env_or(name: &str, default: &str) -> String {
    nonempty_env(name).unwrap_or_else(|| default.to_owned())
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

fn nonempty_env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn parse_i64_env(name: &str, default: &str) -> Result<i64, String> {
    let value = env_or(name, default);
    value
        .parse()
        .map_err(|_| format!("invalid {name}: {value}"))
}

fn parse_u64_env(name: &str, default: &str) -> Result<u64, String> {
    let value = env_or(name, default);
    value
        .parse()
        .map_err(|_| format!("invalid {name}: {value}"))
}

fn platform_dev_tar_name() -> &'static str {
    if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "openbox-sandbox-dev-darwin-arm64.tar.gz"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "openbox-sandbox-dev-linux-x86_64.tar.gz"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        "openbox-sandbox-dev-linux-aarch64.tar.gz"
    } else {
        "openbox-sandbox-dev-darwin-arm64.tar.gz"
    }
}

fn platform_vm_cache_name() -> &'static str {
    if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "prepared-vm-cache-darwin-arm64.tar.gz"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "prepared-vm-cache-linux-x86_64.tar.gz"
    } else {
        ""
    }
}

fn platform_registry_names() -> (&'static str, &'static str) {
    if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        (
            "openbox-sandbox-dev-darwin-arm64-oci.tar.gz",
            "zot-darwin-arm64",
        )
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        (
            "openbox-sandbox-dev-linux-x86_64-oci.tar.gz",
            "zot-linux-x86_64",
        )
    } else {
        ("", "")
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
    unsafe {
        umask(0o077);
    }
}

#[cfg(not(unix))]
fn set_private_umask() {}

#[cfg(test)]
mod tests {
    use super::{
        ca_subject_from_rfc2253, parse_manifest_digest, parse_pid_file, physical_path,
        policy_defaults, preserve_images_only, process_matches_command, version_has_source_marker,
        IdentityMode,
    };
    use std::fs;

    fn fixture(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("obs-openshell-{name}-{}", std::process::id()))
    }

    #[test]
    fn source_marker_must_have_hex_boundaries_or_locked_version_is_used() {
        assert!(version_has_source_marker("openshell 0.0.0-gf1690849"));
        assert!(version_has_source_marker("f1690849"));
        assert!(!version_has_source_marker("openshell 0.0.0-gf16908490"));
        assert!(!version_has_source_marker("openshell af1690849b"));
        assert!(!version_has_source_marker("openshell agf1690849"));
    }

    #[test]
    fn pid_file_accepts_only_positive_decimal_pid() {
        assert_eq!(parse_pid_file("123\n"), Ok(123));
        for malformed in ["", "0", "01", "-1", " 12", "12 ", "12x", "12\r\n"] {
            assert!(parse_pid_file(malformed).is_err(), "accepted {malformed:?}");
        }
    }

    #[test]
    fn teardown_identity_is_scoped_to_binary_and_exact_gateway_config() {
        assert!(process_matches_command(
            "/tmp/openbox-sandbox --serve",
            "openbox-sandbox",
            "",
            IdentityMode::BinaryName
        ));
        assert!(!process_matches_command(
            "/tmp/not-openbox-sandbox --serve",
            "openbox-sandbox",
            "",
            IdentityMode::BinaryName
        ));
        assert!(process_matches_command(
            "/override/openshell-gateway --config /state/gateway.toml --port 1",
            "/different/openshell-gateway",
            "/state/gateway.toml",
            IdentityMode::GatewayConfig
        ));
        assert!(!process_matches_command(
            "/override/openshell-gateway --config /other/gateway.toml",
            "/override/openshell-gateway",
            "/state/gateway.toml",
            IdentityMode::GatewayConfig
        ));
    }

    #[test]
    fn provisioning_roots_resolve_symlink_components() {
        let root = fixture("physical-root");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("real/state")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
            assert_eq!(
                physical_path(&root.join("link/state")).unwrap(),
                fs::canonicalize(root.join("real/state")).unwrap()
            );
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn clean_rerun_preserves_only_prepared_images() {
        let root = fixture("preserve-cache");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("images/cache")).unwrap();
        fs::create_dir_all(root.join("sandboxes/one")).unwrap();
        fs::write(root.join("driver.db"), b"stale").unwrap();
        preserve_images_only(&root).unwrap();
        assert!(root.join("images/cache").is_dir());
        assert!(!root.join("sandboxes").exists());
        assert!(!root.join("driver.db").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn policy_channel_defaults_match_documented_contract() {
        assert_eq!(
            policy_defaults("dev"),
            ("policy-allow-network-dev.yaml", "openbox-allow-network-dev")
        );
        assert_eq!(
            policy_defaults("base"),
            ("policy-deny-network-dev.yaml", "openbox-deny-network-dev")
        );
    }

    #[test]
    fn parses_registry_digest_and_gateway_ca_subject() {
        assert_eq!(
            parse_manifest_digest(b"HTTP/1.1 200 OK\r\nDocker-Content-Digest: sha256:abc\r\n")
                .as_deref(),
            Some("sha256:abc")
        );
        assert_eq!(
            ca_subject_from_rfc2253("subject=CN=CA,O=OpenShell\n"),
            Ok("/O=OpenShell/CN=CA".to_owned())
        );
    }
}
