//! Locked source-build path used by `obs install --local`.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::install::{DependencyMode, Options as InstallOptions};

const OPENSHELL_SOURCE_PIN: &str = "f169084923503a02a94425857b938de2841cab0c";
const OPENSHELL_VERSION_MARKER: &str = "gf1690849";
const RUSTUP_VERSION: &str = "1.28.2";
const RUST_TOOLCHAIN: &str = "1.95.0";
const LOCAL_IMAGE: &str = "ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e";
const BUILD_PACKAGES: &[&str] = &[
    "autoconf",
    "automake",
    "build-essential",
    "ca-certificates",
    "clang",
    "cmake",
    "curl",
    "dpkg-dev",
    "fuse-overlayfs",
    "git",
    "libclang-dev",
    "libtool",
    "libz3-dev",
    "openssl",
    "pkg-config",
    "podman",
    "slirp4netns",
    "systemd",
    "uidmap",
];
const SERVER_EXT: &str = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n";
const CLIENT_EXT: &str = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n";

pub struct Options {
    pub no_start: bool,
    pub dependency_mode: DependencyMode,
    pub source_root: PathBuf,
}

pub fn run(options: Options) -> Result<(), String> {
    if effective_uid() == 0 {
        return Err("local bootstrap: run as an ordinary user; privileged installation is requested only after preparation".to_owned());
    }
    if !cfg!(target_os = "linux") {
        return Err("local bootstrap: currently supports Debian-family Linux hosts".to_owned());
    }
    require_command(
        "apt-get",
        "local bootstrap currently requires apt-get; use a published release bundle on this host",
    )?;
    require_command(
        "sudo",
        "sudo is required to install local build and service prerequisites",
    )?;
    let root = fs::canonicalize(&options.source_root)
        .map_err(|error| format!("local bootstrap: cannot resolve source root: {error}"))?;
    if !root.join("Cargo.toml").is_file()
        || !root.join("Cargo.lock").is_file()
        || !root.join("packaging/launcher/Cargo.toml").is_file()
        || !root.join("packaging/launcher/src/install.rs").is_file()
    {
        return Err("local bootstrap: must run from a complete source checkout".to_owned());
    }

    eprintln!(
        "This mode builds a complete LOCAL, NON-PRODUCTION installation from the locked source."
    );
    eprintln!(
        "It downloads exact source/toolchain dependencies, generates local-only mTLS identities,"
    );
    eprintln!("and installs the pinned OpenShell gateway plus OpenBox Sandbox.");
    let install_build_dependencies = match options.dependency_mode {
        DependencyMode::No => false,
        DependencyMode::Yes => true,
        DependencyMode::Ask
            if super::install::ask_yes_no_for_local(
                "Install missing local build prerequisites with apt-get?",
            ) =>
        {
            true
        }
        DependencyMode::Ask => {
            return Err("local bootstrap: requires approved build prerequisites".to_owned());
        }
    };

    let mut missing = Vec::new();
    for package in BUILD_PACKAGES {
        let status = Command::new("dpkg-query")
            .args(["-W", "-f=${Status}", package])
            .output();
        let installed = status.is_ok_and(|output| {
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("ok installed")
        });
        if !installed {
            missing.push(*package);
        }
    }
    if !missing.is_empty() {
        if !install_build_dependencies {
            return Err(format!(
                "local bootstrap: missing local build packages: {}",
                missing.join(" ")
            ));
        }
        run_program("sudo", &["apt-get", "update"])?;
        let mut command = Command::new("sudo");
        command.args([
            "env",
            "DEBIAN_FRONTEND=noninteractive",
            "apt-get",
            "install",
            "-y",
            "--no-install-recommends",
        ]);
        command.args(&missing);
        run_command(
            &mut command,
            "local bootstrap: build prerequisite installation failed",
        )?;
    }
    for command in ["curl", "dpkg-deb", "git", "openssl", "sha256sum"] {
        require_command(command, &format!("required command unavailable: {command}"))?;
    }

    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "local bootstrap: HOME is unset".to_owned())?;
    let cargo_home = home.join(".cargo");
    let rustup_home = home.join(".rustup");
    std::env::set_var("CARGO_HOME", &cargo_home);
    std::env::set_var("RUSTUP_HOME", &rustup_home);
    let rustup = cargo_home.join("bin/rustup");
    if !is_executable(&rustup) {
        install_rustup()?;
    }
    prepend_path(&cargo_home.join("bin"))?;
    run_program("rustup", &["set", "auto-self-update", "disable"])?;
    run_program(
        "rustup",
        &[
            "toolchain",
            "install",
            RUST_TOOLCHAIN,
            "--profile",
            "minimal",
        ],
    )?;
    let mut unset = Command::new("rustup");
    unset.args(["override", "unset", "--path"]).arg(&root);
    let _ = unset.stdout(Stdio::null()).stderr(Stdio::null()).status();
    let rust_version = command_output("rustc", &[&format!("+{RUST_TOOLCHAIN}"), "--version"])?;
    if !rust_version.starts_with(&format!("rustc {RUST_TOOLCHAIN} ")) {
        return Err("local bootstrap: required Rust toolchain is unavailable".to_owned());
    }

    let local_root = root.join(".openbox-local");
    reject_symlink(
        &local_root,
        "local build directory cannot be a symbolic link",
    )?;
    for directory in [
        local_root.clone(),
        local_root.join("build"),
        local_root.join("clients"),
        local_root.join("pki"),
    ] {
        install_private_dir(&directory)?;
    }
    let openbox_target = local_root.join("build/openbox-target");
    let openshell_checkout = local_root.join("build/openshell-source");
    let openshell_target = local_root.join("build/openshell-target");
    let release = local_root.join("release");

    if openshell_checkout.exists() {
        let valid = openshell_checkout.is_dir()
            && !is_symlink(&openshell_checkout)
            && git_output(&openshell_checkout, &["rev-parse", "HEAD"]).as_deref()
                == Ok(OPENSHELL_SOURCE_PIN)
            && git_output(&openshell_checkout, &["status", "--porcelain"])
                .is_ok_and(|value| value.is_empty());
        if !valid {
            remove_tree(&openshell_checkout)?;
        }
    }
    if !openshell_checkout.is_dir() {
        let mut clone = Command::new("git");
        clone
            .args([
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                "https://github.com/NVIDIA/OpenShell.git",
            ])
            .arg(&openshell_checkout);
        run_command(&mut clone, "local bootstrap: OpenShell clone failed")?;
        git_run(
            &openshell_checkout,
            &["fetch", "--depth=128", "origin", OPENSHELL_SOURCE_PIN],
        )?;
        git_run(
            &openshell_checkout,
            &["checkout", "--detach", OPENSHELL_SOURCE_PIN],
        )?;
    }
    if git_output(&openshell_checkout, &["rev-parse", "HEAD"]).as_deref()
        != Ok(OPENSHELL_SOURCE_PIN)
    {
        return Err("local bootstrap: OpenShell source pin mismatch".to_owned());
    }
    if !git_output(&openshell_checkout, &["status", "--porcelain"])?.is_empty() {
        return Err("local bootstrap: OpenShell source checkout is not clean".to_owned());
    }

    eprintln!("Building OpenBox Sandbox from locked sources...");
    let mut build = Command::new("cargo");
    build
        .arg(format!("+{RUST_TOOLCHAIN}"))
        .args(["build", "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .args(["--release", "--locked", "--bin", "openbox-sandbox"])
        .env("CARGO_TARGET_DIR", &openbox_target);
    run_command(&mut build, "local bootstrap: OpenBox build failed")?;
    let openbox_binary = openbox_target.join("release/openbox-sandbox");

    eprintln!("Building pinned OpenShell package...");
    let mut build = Command::new("cargo");
    build
        .arg(format!("+{RUST_TOOLCHAIN}"))
        .args(["build", "--manifest-path"])
        .arg(openshell_checkout.join("Cargo.toml"))
        .args([
            "--release",
            "--locked",
            "-p",
            "openshell-cli",
            "-p",
            "openshell-server",
            "-p",
            "openshell-driver-vm",
        ])
        .env("CARGO_TARGET_DIR", &openshell_target);
    run_command(&mut build, "local bootstrap: OpenShell build failed")?;
    for (binary, label) in [
        (openshell_target.join("release/openshell"), "CLI"),
        (
            openshell_target.join("release/openshell-gateway"),
            "gateway",
        ),
    ] {
        let output = command_output_path(&binary, &["--version"])?;
        if !output.contains(OPENSHELL_VERSION_MARKER) {
            return Err(format!(
                "local bootstrap: built OpenShell {label} does not identify the approved source pin"
            ));
        }
    }

    let package_output = local_root.join("build/openshell-package");
    remove_tree(&package_output)?;
    install_private_dir(&package_output)?;
    let package_script = openshell_checkout.join("tasks/scripts/package-deb.sh");
    let mut package = Command::new(&package_script);
    package
        .env(
            "OPENSHELL_CLI_BINARY",
            openshell_target.join("release/openshell"),
        )
        .env(
            "OPENSHELL_GATEWAY_BINARY",
            openshell_target.join("release/openshell-gateway"),
        )
        .env(
            "OPENSHELL_DRIVER_VM_BINARY",
            openshell_target.join("release/openshell-driver-vm"),
        )
        .env("OPENSHELL_DEB_VERSION", "0.0.0~openboxlocal.gf1690849")
        .env("OPENSHELL_OUTPUT_DIR", &package_output)
        .stdout(Stdio::null());
    set_command_umask(&mut package, 0o022);
    run_command(
        &mut package,
        "local bootstrap: local OpenShell package assembly failed",
    )?;
    let packages = files_with_extension(&package_output, "deb")?;
    if packages.len() != 1 {
        return Err("local bootstrap: local OpenShell package assembly failed".to_owned());
    }

    for path in [
        &release,
        &local_root.join("clients"),
        &local_root.join("pki"),
    ] {
        remove_tree(path)?;
    }
    for directory in [
        release.join("tls"),
        release.join("runtime-mtls"),
        release.join("openshell"),
        local_root.join("clients/runtime"),
        local_root.join("clients/administrator"),
        local_root.join("pki"),
    ] {
        install_private_dir(&directory)?;
    }
    let pki = local_root.join("pki");
    generate_pki(&pki, &local_root)?;

    let runtime_fingerprint = certificate_fingerprint(&local_root.join("clients/runtime/tls.crt"))?;
    let admin_fingerprint =
        certificate_fingerprint(&local_root.join("clients/administrator/tls.crt"))?;
    let adapter_sha = sha256_file(&openbox_binary)?;
    let policy = root.join("deploy/policies/policy-deny-network.yaml");
    let policy_sha = sha256_file(&policy)?;

    copy(&openbox_binary, &release.join("openbox-sandbox"))?;
    copy(&pki.join("ca.crt"), &release.join("tls/client-ca.crt"))?;
    copy(&pki.join("server.crt"), &release.join("tls/server.crt"))?;
    copy(&pki.join("server.key"), &release.join("tls/server.key"))?;
    for credential in ["ca.crt", "tls.crt", "tls.key"] {
        copy(
            &local_root.join("clients/runtime").join(credential),
            &release.join("runtime-mtls").join(credential),
        )?;
    }
    copy(
        &packages[0],
        &release
            .join("openshell")
            .join(packages[0].file_name().unwrap_or_default()),
    )?;
    write_private(
        &release.join("openshell/source-commit"),
        format!("{OPENSHELL_SOURCE_PIN}\n").as_bytes(),
    )?;
    let config = format!(
        "{{\n  \"bind_address\": \"127.0.0.1:17443\",\n  \"server_certificate_path\": \"/etc/openbox-sandbox/tls/server.crt\",\n  \"server_private_key_path\": \"/etc/openbox-sandbox/tls/server.key\",\n  \"client_ca_path\": \"/etc/openbox-sandbox/tls/client-ca.crt\",\n  \"authorized_callers\": [\n    {{\"certificate_sha256\": \"{runtime_fingerprint}\", \"role\": \"runtime\"}},\n    {{\"certificate_sha256\": \"{admin_fingerprint}\", \"role\": \"administrator\"}}\n  ],\n  \"state_directory\": \"/var/lib/openbox-sandbox/cleanup\",\n  \"asset_bundle\": {{\n    \"runtime_contract_version\": 1,\n    \"adapter_build_sha256\": \"{adapter_sha}\",\n    \"template\": \"{LOCAL_IMAGE}\",\n    \"policy\": {{\"id\": \"openbox-deny-network-local\", \"version\": 1, \"sha256\": \"{policy_sha}\"}},\n    \"compatibility_id\": \"local-development-f1690849-contract-1\"\n  }},\n  \"runtime_endpoint\": \"https://127.0.0.1:17670\",\n  \"runtime_mtls_directory\": \"/etc/openbox-sandbox/runtime-mtls\",\n  \"runtime_connect_timeout_ms\": 10000,\n  \"runtime_poll_interval_ms\": 250,\n  \"reconcile_delete_deadline_ms\": 60000,\n  \"reconcile_wait_deadline_ms\": 60000,\n  \"maximum_connections\": 64,\n  \"drain_timeout_ms\": 30000\n}}\n"
    );
    write_private(&release.join("service.json"), config.as_bytes())?;
    chmod(&release.join("openbox-sandbox"), 0o755)?;
    let mut release_files = Vec::new();
    walk_files(&release, &release, &mut release_files)?;
    release_files.retain(|(_, path)| path.file_name() != Some(OsStr::new("SHA256SUMS")));
    release_files.sort_by(|left, right| left.0.cmp(&right.0));
    for (_, path) in &release_files {
        chmod(path, 0o600)?;
    }
    chmod(&release.join("openbox-sandbox"), 0o600)?;
    let mut manifest = String::new();
    for (relative, path) in &release_files {
        manifest.push_str(&format!("{}  {}\n", sha256_file(path)?, relative));
    }
    write_private(&release.join("SHA256SUMS"), manifest.as_bytes())?;

    let target_uid = command_output("id", &["-u"])?;
    let target_user = command_output("id", &["-un"])?;
    run_program("sudo", &["loginctl", "enable-linger", &target_user])?;
    run_program(
        "sudo",
        &["systemctl", "start", &format!("user@{target_uid}.service")],
    )?;
    let runtime = format!("/run/user/{target_uid}");
    let bus = format!("unix:path={runtime}/bus");
    let mut systemctl = Command::new("systemctl");
    systemctl
        .args(["--user", "enable", "--now", "podman.socket"])
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("DBUS_SESSION_BUS_ADDRESS", &bus);
    run_command(
        &mut systemctl,
        "local bootstrap: cannot start rootless Podman socket",
    )?;
    let active = Command::new("systemctl")
        .args(["--user", "is-active", "--quiet", "podman.socket"])
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("DBUS_SESSION_BUS_ADDRESS", &bus)
        .status()
        .is_ok_and(|status| status.success());
    if !active {
        return Err("local bootstrap: rootless Podman socket did not become active".to_owned());
    }

    super::install::run(InstallOptions {
        local: false,
        no_start: options.no_start,
        dependency_mode: options.dependency_mode,
        release: Some(release.clone()),
        privileged_phase: false,
        original_arguments: install_arguments(options.no_start, options.dependency_mode, &release),
    })?;
    println!("Local non-production installation complete.");
    println!(
        "Runtime caller credentials: {}",
        local_root.join("clients/runtime").display()
    );
    println!(
        "Administrator caller credentials: {}",
        local_root.join("clients/administrator").display()
    );
    println!("Pinned policy: {}", policy.display());
    println!(
        "Local artifacts and private keys remain under {} (mode 0700).",
        local_root.display()
    );
    Ok(())
}

fn install_rustup() -> Result<(), String> {
    let architecture = command_output("uname", &["-m"])?;
    let (target, expected) = match architecture.as_str() {
        "x86_64" | "amd64" => (
            "x86_64-unknown-linux-gnu",
            "20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c",
        ),
        "aarch64" | "arm64" => (
            "aarch64-unknown-linux-gnu",
            "e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c",
        ),
        _ => {
            return Err(format!(
                "local bootstrap: unsupported local Rust architecture: {architecture}"
            ));
        }
    };
    let temporary = PathBuf::from(command_output(
        "mktemp",
        &["-d", "/tmp/openbox-rustup.XXXXXXXX"],
    )?);
    let installer = temporary.join("rustup-init");
    let mut curl = Command::new("curl");
    curl.args([
        "--fail",
        "--location",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--tlsv1.2",
        &format!(
            "https://static.rust-lang.org/rustup/archive/{RUSTUP_VERSION}/{target}/rustup-init"
        ),
        "--output",
    ])
    .arg(&installer);
    let result = run_command(&mut curl, "local bootstrap: rustup download failed").and_then(|()| {
        if sha256_file(&installer)? != expected {
            return Err("local bootstrap: rustup-init checksum mismatch".to_owned());
        }
        chmod(&installer, 0o700)?;
        let mut command = Command::new(&installer);
        command.args([
            "-y",
            "--profile",
            "minimal",
            "--default-toolchain",
            RUST_TOOLCHAIN,
            "--no-modify-path",
        ]);
        run_command(&mut command, "local bootstrap: rustup installation failed")
    });
    let _ = fs::remove_dir_all(temporary);
    result
}

fn generate_pki(pki: &Path, local_root: &Path) -> Result<(), String> {
    openssl(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:3072",
        "-sha256",
        "-days",
        "30",
        "-nodes",
        "-subj",
        "/CN=OpenBox Local Development CA",
        "-keyout",
        &path_string(&pki.join("ca.key"))?,
        "-out",
        &path_string(&pki.join("ca.crt"))?,
    ])?;
    chmod(&pki.join("ca.key"), 0o600)?;
    write_private(&pki.join("server.ext"), SERVER_EXT.as_bytes())?;
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:3072",
        "-nodes",
        "-subj",
        "/CN=127.0.0.1",
        "-keyout",
        &path_string(&pki.join("server.key"))?,
        "-out",
        &path_string(&pki.join("server.csr"))?,
    ])?;
    openssl(&[
        "x509",
        "-req",
        "-sha256",
        "-days",
        "30",
        "-in",
        &path_string(&pki.join("server.csr"))?,
        "-CA",
        &path_string(&pki.join("ca.crt"))?,
        "-CAkey",
        &path_string(&pki.join("ca.key"))?,
        "-CAcreateserial",
        "-extfile",
        &path_string(&pki.join("server.ext"))?,
        "-out",
        &path_string(&pki.join("server.crt"))?,
    ])?;
    make_client("runtime", "Runtime", pki, local_root)?;
    make_client("administrator", "Administrator", pki, local_root)
}

fn make_client(name: &str, role: &str, pki: &Path, local_root: &Path) -> Result<(), String> {
    let directory = local_root.join("clients").join(name);
    write_private(&pki.join(format!("{name}.ext")), CLIENT_EXT.as_bytes())?;
    openssl(&[
        "req",
        "-new",
        "-newkey",
        "rsa:3072",
        "-nodes",
        "-subj",
        &format!("/CN=OpenBox Local {role}"),
        "-keyout",
        &path_string(&directory.join("tls.key"))?,
        "-out",
        &path_string(&pki.join(format!("{name}.csr")))?,
    ])?;
    openssl(&[
        "x509",
        "-req",
        "-sha256",
        "-days",
        "30",
        "-in",
        &path_string(&pki.join(format!("{name}.csr")))?,
        "-CA",
        &path_string(&pki.join("ca.crt"))?,
        "-CAkey",
        &path_string(&pki.join("ca.key"))?,
        "-CAcreateserial",
        "-extfile",
        &path_string(&pki.join(format!("{name}.ext")))?,
        "-out",
        &path_string(&directory.join("tls.crt"))?,
    ])?;
    copy(&pki.join("ca.crt"), &directory.join("ca.crt"))?;
    for credential in ["ca.crt", "tls.crt", "tls.key"] {
        chmod(&directory.join(credential), 0o600)?;
    }
    Ok(())
}

fn certificate_fingerprint(path: &Path) -> Result<String, String> {
    let output = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(path)
        .args(["-outform", "DER"])
        .output()
        .map_err(|error| format!("local bootstrap: cannot run openssl: {error}"))?;
    if !output.status.success() {
        return Err("local bootstrap: certificate conversion failed".to_owned());
    }
    sha256_bytes(&output.stdout)
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let output = Command::new("sha256sum")
        .arg(path)
        .output()
        .map_err(|error| format!("local bootstrap: cannot run sha256sum: {error}"))?;
    parse_sha256(&output.stdout, output.status.success())
}

fn sha256_bytes(bytes: &[u8]) -> Result<String, String> {
    let mut child = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("local bootstrap: cannot run sha256sum: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "local bootstrap: cannot open sha256sum stdin".to_owned())?
        .write_all(bytes)
        .map_err(|error| format!("local bootstrap: cannot write sha256sum stdin: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("local bootstrap: cannot wait for sha256sum: {error}"))?;
    parse_sha256(&output.stdout, output.status.success())
}

fn parse_sha256(output: &[u8], success: bool) -> Result<String, String> {
    let digest = String::from_utf8_lossy(output)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();
    if success
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(digest)
    } else {
        Err("local bootstrap: cannot parse SHA-256 output".to_owned())
    }
}

fn walk_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "local bootstrap: cannot inspect {}: {error}",
            directory.display()
        )
    })? {
        let path = entry
            .map_err(|error| format!("local bootstrap: cannot inspect release: {error}"))?
            .path();
        if path.is_dir() {
            walk_files(root, &path, files)?;
        } else if path.is_file() {
            let relative = path
                .strip_prefix(root)
                .ok()
                .and_then(Path::to_str)
                .ok_or_else(|| "local bootstrap: release path is not UTF-8".to_owned())?
                .to_owned();
            files.push((relative, path));
        }
    }
    Ok(())
}

fn install_arguments(no_start: bool, mode: DependencyMode, release: &Path) -> Vec<String> {
    let mut args = Vec::new();
    match mode {
        DependencyMode::Yes => args.push("--install-dependencies".to_owned()),
        DependencyMode::No => args.push("--no-install-dependencies".to_owned()),
        DependencyMode::Ask => {}
    }
    if no_start {
        args.push("--no-start".to_owned());
    }
    args.push(release.display().to_string());
    args
}

fn git_run(directory: &Path, args: &[&str]) -> Result<(), String> {
    let mut command = Command::new("git");
    command.arg("-C").arg(directory).args(args);
    run_command(&mut command, "local bootstrap: git command failed")
}

fn git_output(directory: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .map_err(|error| format!("local bootstrap: cannot run git: {error}"))?;
    if !output.status.success() {
        return Err("local bootstrap: git command failed".to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\n', '\r'])
        .to_owned())
}

fn openssl(args: &[&str]) -> Result<(), String> {
    let status = Command::new("openssl")
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("local bootstrap: cannot run openssl: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("local bootstrap: openssl command failed".to_owned())
    }
}

fn files_with_extension(directory: &Path, extension: &str) -> Result<Vec<PathBuf>, String> {
    let mut files: Vec<PathBuf> = fs::read_dir(directory)
        .map_err(|error| format!("local bootstrap: cannot inspect package output: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension() == Some(OsStr::new(extension)))
        .collect();
    files.sort();
    Ok(files)
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
        .map_err(|error| format!("local bootstrap: cannot write {}: {error}", path.display()))?;
    file.write_all(body)
        .map_err(|error| format!("local bootstrap: cannot write {}: {error}", path.display()))?;
    chmod(path, 0o600)
}

fn copy(source: &Path, destination: &Path) -> Result<(), String> {
    fs::copy(source, destination).map(|_| ()).map_err(|error| {
        format!(
            "local bootstrap: cannot copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })
}

fn install_private_dir(path: &Path) -> Result<(), String> {
    let mut command = Command::new("install");
    command.args(["-d", "-m", "0700"]).arg(path);
    run_command(
        &mut command,
        "local bootstrap: cannot create private directory",
    )
}

fn remove_tree(path: &Path) -> Result<(), String> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "local bootstrap: cannot remove {}: {error}",
            path.display()
        )),
    }
}

fn reject_symlink(path: &Path, message: &str) -> Result<(), String> {
    if is_symlink(path) {
        Err(format!("local bootstrap: {message}"))
    } else {
        Ok(())
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
}

fn require_command(name: &str, message: &str) -> Result<(), String> {
    if find_command(name).is_some() {
        Ok(())
    } else {
        Err(format!("local bootstrap: {message}"))
    }
}

fn find_command(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| is_executable(candidate))
    })
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

fn prepend_path(directory: &Path) -> Result<(), String> {
    let old = std::env::var_os("PATH").unwrap_or_default();
    let mut paths = vec![directory.to_owned()];
    paths.extend(std::env::split_paths(&old));
    let joined = std::env::join_paths(paths)
        .map_err(|error| format!("local bootstrap: cannot construct PATH: {error}"))?;
    std::env::set_var("PATH", joined);
    Ok(())
}

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("local bootstrap: cannot run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "local bootstrap: {program} exited {}",
            output.status
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\n', '\r'])
        .to_owned())
}

fn command_output_path(program: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("local bootstrap: cannot run {}: {error}", program.display()))?;
    if !output.status.success() {
        return Err(format!(
            "local bootstrap: {} exited {}",
            program.display(),
            output.status
        ));
    }
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(text.trim_end_matches(['\n', '\r']).to_owned())
}

fn run_program(program: &str, args: &[&str]) -> Result<(), String> {
    let mut command = Command::new(program);
    command.args(args);
    run_command(&mut command, &format!("local bootstrap: {program} failed"))
}

fn run_command(command: &mut Command, message: &str) -> Result<(), String> {
    let status = command
        .status()
        .map_err(|error| format!("{message}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{message}: {status}"))
    }
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "local bootstrap: path is not valid UTF-8".to_owned())
}

#[cfg(unix)]
fn chmod(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("local bootstrap: cannot chmod {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn chmod(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn set_command_umask(command: &mut Command, mask: u32) {
    use std::os::unix::process::CommandExt;
    unsafe {
        command.pre_exec(move || {
            unsafe extern "C" {
                fn umask(mask: u32) -> u32;
            }
            umask(mask);
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn set_command_umask(_command: &mut Command, _mask: u32) {}

#[cfg(unix)]
fn effective_uid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(not(unix))]
fn effective_uid() -> u32 {
    u32::MAX
}
