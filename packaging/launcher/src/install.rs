//! Root-level Linux system-service installation without an external shell script.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use crate::local_bootstrap;

const SERVICE_NAME: &str = "openbox-sandbox.service";
const SERVICE_USER: &str = "openbox-sandbox";
const SERVICE_GROUP: &str = "openbox-sandbox";
const BINARY_DESTINATION: &str = "/opt/openbox/bin/openbox-sandbox";
const CONFIG_DESTINATION: &str = "/etc/openbox-sandbox/service.json";
const TLS_DESTINATION: &str = "/etc/openbox-sandbox/tls";
const RUNTIME_MTLS_DESTINATION: &str = "/etc/openbox-sandbox/runtime-mtls";
const STATE_DESTINATION: &str = "/var/lib/openbox-sandbox/cleanup";
const UNIT_DESTINATION: &str = "/etc/systemd/system/openbox-sandbox.service";
const OPENSHELL_SOURCE_PIN: &str = "f169084923503a02a94425857b938de2841cab0c";
const OPENSHELL_VERSION_MARKER: &str = "gf1690849";
const OPENSHELL_LOCKED_VERSION: &str = "0.0.88";
const BASE_RELEASE_FILES: &[&str] = &[
    "openbox-sandbox",
    "runtime-mtls/ca.crt",
    "runtime-mtls/tls.crt",
    "runtime-mtls/tls.key",
    "service.json",
    "tls/client-ca.crt",
    "tls/server.crt",
    "tls/server.key",
];
const REQUIRED_COMMANDS: &[&str] = &[
    "awk",
    "basename",
    "chmod",
    "chown",
    "cp",
    "curl",
    "diff",
    "dirname",
    "env",
    "find",
    "getent",
    "groupadd",
    "id",
    "install",
    "loginctl",
    "mktemp",
    "mv",
    "readlink",
    "rm",
    "runuser",
    "sed",
    "sha256sum",
    "sleep",
    "sort",
    "systemctl",
    "uname",
    "useradd",
];
const DESTINATIONS: &[&str] = &[
    BINARY_DESTINATION,
    CONFIG_DESTINATION,
    "/etc/openbox-sandbox/tls/client-ca.crt",
    "/etc/openbox-sandbox/tls/server.crt",
    "/etc/openbox-sandbox/tls/server.key",
    "/etc/openbox-sandbox/runtime-mtls/ca.crt",
    "/etc/openbox-sandbox/runtime-mtls/tls.crt",
    "/etc/openbox-sandbox/runtime-mtls/tls.key",
    UNIT_DESTINATION,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyMode {
    Ask,
    Yes,
    No,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub local: bool,
    pub no_start: bool,
    pub dependency_mode: DependencyMode,
    pub release: Option<PathBuf>,
    pub privileged_phase: bool,
    pub original_arguments: Vec<String>,
}

#[derive(Clone, Copy)]
enum PackageFamily {
    Deb,
    Rpm(&'static str),
}

struct Release {
    directory: PathBuf,
    files: Vec<String>,
    package_files: Vec<PathBuf>,
    has_openshell: bool,
}

struct TemporaryDirectories {
    snapshot: PathBuf,
    backup: PathBuf,
}

impl Drop for TemporaryDirectories {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.snapshot);
        let _ = fs::remove_dir_all(&self.backup);
    }
}

pub fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut privileged_phase = false;
    let mut start = 0;
    if args
        .first()
        .is_some_and(|arg| arg == "--_openbox-privileged-phase")
    {
        privileged_phase = true;
        start = 1;
    }
    let original_arguments = args[start..].to_vec();
    let mut local = false;
    let mut no_start = false;
    let mut dependency_mode = DependencyMode::Ask;
    let mut index = start;
    while index < args.len() {
        match args[index].as_str() {
            "--local" => local = true,
            "--no-start" => no_start = true,
            "--install-dependencies" => dependency_mode = DependencyMode::Yes,
            "--no-install-dependencies" => dependency_mode = DependencyMode::No,
            value if value.starts_with('-') => {
                return Err(format!("unsupported install option: {value}"));
            }
            _ => break,
        }
        index += 1;
    }
    if args.len().saturating_sub(index) > 1 {
        return Err("install accepts at most one release path".to_owned());
    }
    Ok(Options {
        local,
        no_start,
        dependency_mode,
        release: args.get(index).map(PathBuf::from),
        privileged_phase,
        original_arguments,
    })
}

pub fn run(options: Options) -> Result<(), String> {
    set_private_umask();
    if options.privileged_phase && effective_uid() != 0 {
        return Err("internal privileged phase requires administrator authorization".to_owned());
    }
    let root = installer_root()?;
    let default_release = root.join("release");
    let release_input = options.release.clone().unwrap_or(default_release);
    let automatic_local = options.release.is_none() && !release_input.is_dir();
    if options.local || automatic_local {
        if options.privileged_phase || effective_uid() == 0 {
            return Err("local bootstrap must begin as an ordinary user".to_owned());
        }
        if options.release.is_some() {
            return Err("--local does not accept a release path".to_owned());
        }
        return local_bootstrap::run(local_bootstrap::Options {
            no_start: options.no_start,
            dependency_mode: options.dependency_mode,
            source_root: root,
        });
    }

    if effective_uid() != 0 {
        if options.privileged_phase {
            return Err("internal privilege state is invalid".to_owned());
        }
        require_linux()?;
        basic_release_preflight(&root, &release_input)?;
        let sudo = if is_executable(Path::new("/usr/bin/sudo")) {
            Path::new("/usr/bin/sudo")
        } else if is_executable(Path::new("/bin/sudo")) {
            Path::new("/bin/sudo")
        } else {
            return Err("system installation requires sudo; install it or ask an administrator to run this installer".to_owned());
        };
        eprintln!("Release structure preflight passed.");
        eprintln!("Administrator authorization is now required to install the verified pinned OpenShell dependency,");
        eprintln!("any approved missing host prerequisites, the locked service account, protected configuration,");
        eprintln!("credentials, and the systemd service.");
        let executable = std::env::current_exe()
            .map_err(|error| format!("cannot resolve current executable: {error}"))?;
        let mut command = Command::new(sudo);
        command
            .arg("--")
            .arg(executable)
            .arg("install")
            .arg("--_openbox-privileged-phase")
            .args(&options.original_arguments);
        return exec_command(command, "cannot enter privileged installation phase");
    }

    if options.privileged_phase {
        std::env::set_var(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        );
        for name in ["BASH_ENV", "CDPATH", "ENV"] {
            std::env::remove_var(name);
        }
    }
    require_linux()?;
    basic_release_preflight(&root, &release_input)?;
    privileged_install(&root, &release_input, options)
}

fn privileged_install(root: &Path, release_input: &Path, options: Options) -> Result<(), String> {
    let family = package_family()?;
    handle_prerequisites(family, options.dependency_mode)?;
    let release_directory = canonical_absolute_directory(release_input)?;
    let unit_source = root.join("deploy").join(SERVICE_NAME);
    require_regular_file(&unit_source, "trusted systemd unit is unavailable")?;
    let release = inspect_release(release_directory, family)?;
    let temporary = TemporaryDirectories {
        snapshot: mktemp("/tmp/openbox-sandbox-install.XXXXXXXX")?,
        backup: mktemp("/tmp/openbox-sandbox-backup.XXXXXXXX")?,
    };
    snapshot_release(&release, &unit_source, &temporary.snapshot)?;
    verify_snapshot(&release, &temporary.snapshot)?;

    let mut installed_now = false;
    if !openshell_matches_pin() {
        if !release.has_openshell {
            return Err(
                "required pinned OpenShell is not installed and the release has no usable package"
                    .to_owned(),
            );
        }
        install_pinned_openshell(&release, &temporary.snapshot, family)?;
        installed_now = true;
    }
    let runtime_mtls = snapshot_openshell_mtls(&temporary.snapshot, installed_now)?;
    reject_unsafe_destinations()?;
    ensure_service_identity()?;

    let was_active = command_success("systemctl", &["is-active", "--quiet", SERVICE_NAME]);
    let was_enabled = command_success("systemctl", &["is-enabled", "--quiet", SERVICE_NAME]);
    backup_destinations(&temporary.backup)?;
    let result = mutate_install(
        &temporary.snapshot,
        &runtime_mtls,
        options.no_start,
        was_active,
    );
    if let Err(error) = result {
        rollback(&temporary.backup, was_active, was_enabled);
        eprintln!("openbox-sandbox installer: installation rolled back");
        return Err(error);
    }

    println!(
        "openbox-sandbox installed from verified local release: {}",
        release.directory.display()
    );
    if options.no_start {
        println!("service not started (--no-start)");
    }
    Ok(())
}

fn basic_release_preflight(root: &Path, release: &Path) -> Result<(), String> {
    if !release.is_absolute() {
        return Err("release path must be absolute".to_owned());
    }
    require_real_directory(release, "release path must be a real directory")?;
    for relative in std::iter::once("SHA256SUMS").chain(BASE_RELEASE_FILES.iter().copied()) {
        require_regular_file(
            &release.join(relative),
            &format!("release preflight rejected required file: {relative}"),
        )?;
    }
    require_regular_file(
        &root.join("deploy").join(SERVICE_NAME),
        "trusted systemd unit is unavailable",
    )
}

fn package_family() -> Result<PackageFamily, String> {
    if command_exists("apt-get") {
        Ok(PackageFamily::Deb)
    } else if command_exists("dnf") {
        Ok(PackageFamily::Rpm("dnf"))
    } else if command_exists("yum") {
        Ok(PackageFamily::Rpm("yum"))
    } else {
        Err("requires apt-get, dnf, or yum".to_owned())
    }
}

fn handle_prerequisites(family: PackageFamily, mode: DependencyMode) -> Result<(), String> {
    let missing: Vec<&str> = REQUIRED_COMMANDS
        .iter()
        .copied()
        .filter(|command| !command_exists(command))
        .collect();
    if !missing.is_empty() {
        let prompt = format!(
            "Install missing host prerequisites ({})?",
            missing.join(" ")
        );
        if !approved(mode, &prompt) {
            return Err(format!("missing host prerequisites: {}", missing.join(" ")));
        }
        match family {
            PackageFamily::Deb => {
                run_program("apt-get", &["update"])?;
                let mut command = Command::new("env");
                command.args([
                    "DEBIAN_FRONTEND=noninteractive",
                    "apt-get",
                    "install",
                    "-y",
                    "--no-install-recommends",
                    "ca-certificates",
                    "coreutils",
                    "curl",
                    "diffutils",
                    "findutils",
                    "gawk",
                    "libc-bin",
                    "passwd",
                    "sed",
                    "systemd",
                    "util-linux",
                ]);
                run_command(&mut command, "host prerequisite installation failed")?;
            }
            PackageFamily::Rpm(installer) => run_program(
                installer,
                &[
                    "install",
                    "-y",
                    "ca-certificates",
                    "coreutils",
                    "curl",
                    "diffutils",
                    "findutils",
                    "gawk",
                    "glibc-common",
                    "shadow-utils",
                    "sed",
                    "systemd",
                    "util-linux",
                ],
            )?,
        }
    }
    for command in REQUIRED_COMMANDS {
        if !command_exists(command) {
            return Err(format!(
                "required command unavailable after prerequisite handling: {command}"
            ));
        }
    }
    Ok(())
}

fn inspect_release(directory: PathBuf, family: PackageFamily) -> Result<Release, String> {
    let mut files: Vec<String> = BASE_RELEASE_FILES
        .iter()
        .map(|value| (*value).to_owned())
        .collect();
    let mut package_files = Vec::new();
    let openshell = directory.join("openshell");
    let mut has_openshell = false;
    if openshell.exists() {
        require_real_directory(&openshell, "OpenShell payload must be a real directory")?;
        require_regular_file(
            &openshell.join("source-commit"),
            "OpenShell payload is missing source-commit",
        )?;
        package_files = fs::read_dir(&openshell)
            .map_err(|error| format!("cannot inspect OpenShell payload: {error}"))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.is_file()
                    && path.extension().is_some_and(|extension| {
                        extension
                            == if matches!(family, PackageFamily::Deb) {
                                "deb"
                            } else {
                                "rpm"
                            }
                    })
            })
            .collect();
        package_files.sort();
        match family {
            PackageFamily::Deb if package_files.len() != 1 => {
                return Err("Debian OpenShell payload must contain exactly one .deb".to_owned());
            }
            PackageFamily::Rpm(_) if package_files.len() != 2 => {
                return Err("RPM OpenShell payload must contain exactly two .rpm files".to_owned());
            }
            PackageFamily::Rpm(_) => {
                let names: Vec<String> = package_files
                    .iter()
                    .filter_map(|path| path.file_name())
                    .map(|name| name.to_string_lossy().into_owned())
                    .collect();
                let gateways = names
                    .iter()
                    .filter(|name| name.starts_with("openshell-gateway-") && name.ends_with(".rpm"))
                    .count();
                let clients = names
                    .iter()
                    .filter(|name| {
                        name.starts_with("openshell-")
                            && !name.starts_with("openshell-gateway-")
                            && name.ends_with(".rpm")
                    })
                    .count();
                if gateways != 1 || clients != 1 {
                    return Err(
                        "RPM OpenShell payload requires one CLI and one gateway package".to_owned(),
                    );
                }
            }
            _ => {}
        }
        files.push("openshell/source-commit".to_owned());
        for package in &package_files {
            files.push(format!(
                "openshell/{}",
                package.file_name().unwrap_or_default().to_string_lossy()
            ));
        }
        has_openshell = true;
    }
    let mut expected = files.clone();
    expected.push("SHA256SUMS".to_owned());
    expected.sort();
    let actual = list_release_files(&directory)?;
    if actual != expected {
        return Err("release contains missing or unexpected files".to_owned());
    }
    Ok(Release {
        directory,
        files,
        package_files,
        has_openshell,
    })
}

fn list_release_files(root: &Path) -> Result<Vec<String>, String> {
    let mut files = Vec::new();
    walk_release(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn walk_release(root: &Path, directory: &Path, files: &mut Vec<String>) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot inspect release {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect release: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect release file {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err("release contains a symbolic link".to_owned());
        }
        if metadata.is_dir() {
            walk_release(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "cannot derive release path".to_owned())?;
            files.push(path_text(relative)?);
        } else {
            return Err("release contains a special file".to_owned());
        }
    }
    Ok(())
}

fn snapshot_release(release: &Release, unit_source: &Path, snapshot: &Path) -> Result<(), String> {
    install_directory(&snapshot.join("release"), "root", "root", "0700")?;
    let all_files = release
        .files
        .iter()
        .map(String::as_str)
        .chain(std::iter::once("SHA256SUMS"));
    for relative in all_files {
        let source = release.directory.join(relative);
        require_regular_file(&source, &format!("release file rejected: {relative}"))?;
        let parent = snapshot
            .join("release")
            .join(relative)
            .parent()
            .unwrap()
            .to_owned();
        install_directory(&parent, "root", "root", "0700")?;
        let destination = snapshot.join("release").join(relative);
        run_os(
            "cp",
            &[
                OsStr::new("--no-dereference"),
                OsStr::new("--"),
                source.as_os_str(),
                destination.as_os_str(),
            ],
        )?;
        require_regular_file(
            &destination,
            &format!("release file changed during the privileged snapshot: {relative}"),
        )?;
        chown(&destination, "root", "root")?;
        chmod(&destination, "0600")?;
    }
    let unit_destination = snapshot.join(SERVICE_NAME);
    run_os(
        "cp",
        &[
            OsStr::new("--no-dereference"),
            OsStr::new("--"),
            unit_source.as_os_str(),
            unit_destination.as_os_str(),
        ],
    )?;
    require_regular_file(
        &unit_destination,
        "systemd unit changed during the privileged snapshot",
    )?;
    chown(&unit_destination, "root", "root")?;
    chmod(&unit_destination, "0600")
}

fn verify_snapshot(release: &Release, snapshot: &Path) -> Result<(), String> {
    let manifest_path = snapshot.join("release/SHA256SUMS");
    let manifest = fs::read_to_string(&manifest_path)
        .map_err(|error| format!("cannot read SHA256SUMS: {error}"))?;
    let mut names = Vec::new();
    let mut seen = BTreeSet::new();
    for line in manifest.lines() {
        let mut fields = line.split_whitespace();
        let digest = fields.next().unwrap_or_default();
        let raw_name = fields.next().unwrap_or_default();
        if fields.next().is_some()
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("SHA256SUMS is malformed".to_owned());
        }
        let name = raw_name.strip_prefix('*').unwrap_or(raw_name);
        let path = Path::new(name);
        if name.is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| component == std::path::Component::ParentDir)
            || !seen.insert(name.to_owned())
        {
            return Err("SHA256SUMS is malformed".to_owned());
        }
        names.push(name.to_owned());
    }
    names.sort();
    let mut expected = release.files.clone();
    expected.sort();
    if names != expected {
        return Err("SHA256SUMS does not cover the exact release".to_owned());
    }
    let status = Command::new("sha256sum")
        .args(["--check", "--strict", "SHA256SUMS"])
        .current_dir(snapshot.join("release"))
        .stdout(Stdio::null())
        .status()
        .map_err(|error| format!("cannot run sha256sum: {error}"))?;
    if !status.success() {
        return Err("release checksum verification failed".to_owned());
    }
    if release.has_openshell {
        let source = fs::read_to_string(snapshot.join("release/openshell/source-commit"))
            .map_err(|error| format!("cannot read OpenShell source attestation: {error}"))?;
        if source.trim_end_matches('\n') != OPENSHELL_SOURCE_PIN {
            return Err("OpenShell payload does not attest the required source commit".to_owned());
        }
    }
    Ok(())
}

fn openshell_matches_pin() -> bool {
    ["openshell", "openshell-gateway"].into_iter().all(|name| {
        let Some(binary) = find_command(name) else {
            return false;
        };
        let Ok(output) = Command::new(binary).arg("--version").output() else {
            return false;
        };
        let mut version = String::from_utf8_lossy(&output.stdout).to_string();
        version.push_str(&String::from_utf8_lossy(&output.stderr));
        output.status.success()
            && (version.contains(OPENSHELL_VERSION_MARKER)
                || version.contains(OPENSHELL_LOCKED_VERSION))
    })
}

fn install_pinned_openshell(
    release: &Release,
    snapshot: &Path,
    family: PackageFamily,
) -> Result<(), String> {
    if !release.has_openshell {
        return Err("the verified release does not include a pinned OpenShell package".to_owned());
    }
    let packages: Vec<PathBuf> = release
        .package_files
        .iter()
        .map(|path| {
            snapshot
                .join("release/openshell")
                .join(path.file_name().unwrap_or_default())
        })
        .collect();
    match family {
        PackageFamily::Deb => {
            let mut command = Command::new("env");
            command.args([
                "DEBIAN_FRONTEND=noninteractive",
                "apt-get",
                "install",
                "-y",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confnew",
            ]);
            command.args(&packages);
            run_command(&mut command, "pinned OpenShell package installation failed")?;
        }
        PackageFamily::Rpm(installer) => {
            let mut command = Command::new(installer);
            command.args(["install", "-y"]).args(&packages);
            run_command(&mut command, "pinned OpenShell package installation failed")?;
        }
    }
    if !openshell_matches_pin() {
        return Err(format!(
            "installed OpenShell binaries do not identify source pin {OPENSHELL_SOURCE_PIN}"
        ));
    }
    Ok(())
}

fn snapshot_openshell_mtls(snapshot: &Path, installed_now: bool) -> Result<PathBuf, String> {
    let target_user = std::env::var("SUDO_USER").unwrap_or_else(|_| "root".to_owned());
    if !command_success("id", &[&target_user]) {
        return Err(format!(
            "cannot resolve OpenShell service user: {target_user}"
        ));
    }
    let target_uid = command_output("id", &["-u", &target_user])?;
    let passwd = command_output("getent", &["passwd", &target_user])?;
    let target_home = passwd.split(':').nth(5).unwrap_or_default().trim();
    if !Path::new(target_home).is_absolute() {
        return Err("cannot resolve OpenShell service home".to_owned());
    }
    let runtime = format!("/run/user/{target_uid}");
    run_program("loginctl", &["enable-linger", &target_user])?;
    run_program(
        "systemctl",
        &["start", &format!("user@{target_uid}.service")],
    )?;
    run_as_user(
        &target_user,
        target_home,
        &runtime,
        "systemctl",
        &["--user", "daemon-reload"],
    )?;
    run_as_user(
        &target_user,
        target_home,
        &runtime,
        "systemctl",
        &["--user", "enable", "openshell-gateway.service"],
    )?;
    if installed_now {
        run_as_user(
            &target_user,
            target_home,
            &runtime,
            "systemctl",
            &["--user", "restart", "openshell-gateway.service"],
        )?;
    } else if !run_as_user_success(
        &target_user,
        target_home,
        &runtime,
        "systemctl",
        &[
            "--user",
            "is-active",
            "--quiet",
            "openshell-gateway.service",
        ],
    ) {
        run_as_user(
            &target_user,
            target_home,
            &runtime,
            "systemctl",
            &["--user", "start", "openshell-gateway.service"],
        )?;
    }

    let source = Path::new(target_home).join(".config/openshell/gateways/openshell/mtls");
    let mut ready = false;
    for _ in 0..30 {
        if ["ca.crt", "tls.crt", "tls.key"]
            .iter()
            .all(|name| source.join(name).is_file())
            && Command::new("curl")
                .args(["--silent", "--show-error", "--max-time", "2", "--cacert"])
                .arg(source.join("ca.crt"))
                .arg("--cert")
                .arg(source.join("tls.crt"))
                .arg("--key")
                .arg(source.join("tls.key"))
                .args(["--output", "/dev/null", "https://127.0.0.1:17670/"])
                .status()
                .is_ok_and(|status| status.success())
        {
            ready = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
    if !ready {
        return Err("pinned OpenShell gateway did not become ready".to_owned());
    }
    let destination = snapshot.join("openshell-mtls");
    install_directory(&destination, "root", "root", "0700")?;
    for credential in ["ca.crt", "tls.crt", "tls.key"] {
        let input = source.join(credential);
        require_regular_file(&input, "OpenShell generated a symbolic-link credential")?;
        let output = destination.join(credential);
        run_os(
            "cp",
            &[
                OsStr::new("--no-dereference"),
                OsStr::new("--"),
                input.as_os_str(),
                output.as_os_str(),
            ],
        )?;
        chown(&output, "root", "root")?;
        chmod(&output, "0600")?;
    }
    Ok(destination)
}

fn reject_unsafe_destinations() -> Result<(), String> {
    for destination in DESTINATIONS {
        if is_symlink(Path::new(destination))? {
            return Err(format!(
                "installation destination contains a symbolic link: {destination}"
            ));
        }
    }
    for directory in [
        "/opt/openbox",
        "/opt/openbox/bin",
        "/etc/openbox-sandbox",
        TLS_DESTINATION,
        RUNTIME_MTLS_DESTINATION,
        "/var/lib/openbox-sandbox",
        STATE_DESTINATION,
    ] {
        if is_symlink(Path::new(directory))? {
            return Err(format!(
                "installation directory contains a symbolic link: {directory}"
            ));
        }
    }
    Ok(())
}

fn ensure_service_identity() -> Result<(), String> {
    let nologin =
        find_command("nologin").ok_or_else(|| "nologin shell is unavailable".to_owned())?;
    if !command_success("getent", &["group", SERVICE_GROUP]) {
        run_program("groupadd", &["--system", SERVICE_GROUP])?;
    }
    if command_success("id", &[SERVICE_USER]) {
        let group = command_output("id", &["-gn", SERVICE_USER])?;
        if group != SERVICE_GROUP {
            return Err("existing service user has the wrong primary group".to_owned());
        }
    } else {
        let mut command = Command::new("useradd");
        command
            .args([
                "--system",
                "--gid",
                SERVICE_GROUP,
                "--home-dir",
                "/var/lib/openbox-sandbox",
                "--no-create-home",
                "--shell",
            ])
            .arg(nologin)
            .arg(SERVICE_USER);
        run_command(&mut command, "cannot create service user")?;
    }
    Ok(())
}

fn backup_destinations(backup: &Path) -> Result<(), String> {
    for (index, destination) in DESTINATIONS.iter().enumerate() {
        let path = Path::new(destination);
        if path.exists() {
            run_os(
                "cp",
                &[
                    OsStr::new("-a"),
                    OsStr::new("--no-dereference"),
                    OsStr::new("--"),
                    path.as_os_str(),
                    backup.join(index.to_string()).as_os_str(),
                ],
            )?;
        } else {
            File::create(backup.join(format!("{index}.absent")))
                .map_err(|error| format!("cannot record absent destination: {error}"))?;
        }
    }
    Ok(())
}

fn mutate_install(
    snapshot: &Path,
    runtime_mtls: &Path,
    no_start: bool,
    was_active: bool,
) -> Result<(), String> {
    for directory in ["/opt/openbox", "/opt/openbox/bin"] {
        install_directory(Path::new(directory), "root", "root", "0755")?;
    }
    for directory in [
        "/etc/openbox-sandbox",
        TLS_DESTINATION,
        RUNTIME_MTLS_DESTINATION,
        "/var/lib/openbox-sandbox",
        STATE_DESTINATION,
    ] {
        install_directory(Path::new(directory), SERVICE_USER, SERVICE_GROUP, "0700")?;
    }
    install_atomic(
        &snapshot.join("release/openbox-sandbox"),
        Path::new(BINARY_DESTINATION),
        "root",
        "root",
        "0755",
    )?;
    install_atomic(
        &snapshot.join("release/service.json"),
        Path::new(CONFIG_DESTINATION),
        SERVICE_USER,
        SERVICE_GROUP,
        "0600",
    )?;
    for credential in ["client-ca.crt", "server.crt", "server.key"] {
        install_atomic(
            &snapshot.join("release/tls").join(credential),
            &Path::new(TLS_DESTINATION).join(credential),
            SERVICE_USER,
            SERVICE_GROUP,
            "0600",
        )?;
    }
    for credential in ["ca.crt", "tls.crt", "tls.key"] {
        install_atomic(
            &runtime_mtls.join(credential),
            &Path::new(RUNTIME_MTLS_DESTINATION).join(credential),
            SERVICE_USER,
            SERVICE_GROUP,
            "0600",
        )?;
    }
    install_atomic(
        &snapshot.join(SERVICE_NAME),
        Path::new(UNIT_DESTINATION),
        "root",
        "root",
        "0644",
    )?;
    let mut check = Command::new("runuser");
    check
        .args(["-u", SERVICE_USER, "--", "env"])
        .arg(format!("OPENBOX_SANDBOX_CONFIG={CONFIG_DESTINATION}"))
        .arg(BINARY_DESTINATION)
        .arg("--check-config");
    run_command(
        &mut check,
        "installed service configuration validation failed",
    )?;
    run_program("systemctl", &["daemon-reload"])?;
    if !no_start {
        run_program("systemctl", &["enable", SERVICE_NAME])?;
        if was_active {
            run_program("systemctl", &["restart", SERVICE_NAME])?;
        } else {
            run_program("systemctl", &["start", SERVICE_NAME])?;
        }
        if !command_success("systemctl", &["is-active", "--quiet", SERVICE_NAME]) {
            return Err("installed service did not become active".to_owned());
        }
    }
    Ok(())
}

fn rollback(backup: &Path, was_active: bool, was_enabled: bool) {
    for (index, destination) in DESTINATIONS.iter().enumerate() {
        let destination = Path::new(destination);
        let saved = backup.join(index.to_string());
        let _ = fs::remove_file(destination);
        if saved.exists() {
            let _ = Command::new("cp")
                .args(["-a", "--no-dereference", "--"])
                .arg(saved)
                .arg(destination)
                .status();
        }
    }
    let _ = Command::new("systemctl").arg("daemon-reload").status();
    if !was_enabled {
        let _ = Command::new("systemctl")
            .args(["disable", SERVICE_NAME])
            .status();
    }
    if was_active {
        let _ = Command::new("systemctl")
            .args(["restart", SERVICE_NAME])
            .status();
    } else {
        let _ = Command::new("systemctl")
            .args(["stop", SERVICE_NAME])
            .status();
    }
}

fn install_atomic(
    source: &Path,
    destination: &Path,
    owner: &str,
    group: &str,
    mode: &str,
) -> Result<(), String> {
    let temporary = PathBuf::from(format!(
        "{}.install.{}",
        destination.display(),
        std::process::id()
    ));
    let _ = fs::remove_file(&temporary);
    let mut command = Command::new("install");
    command
        .args(["-o", owner, "-g", group, "-m", mode, "--"])
        .arg(source)
        .arg(&temporary);
    run_command(&mut command, "atomic file staging failed")?;
    let mut command = Command::new("mv");
    command.args(["-f", "--"]).arg(&temporary).arg(destination);
    run_command(&mut command, "atomic file replacement failed")
}

fn install_directory(path: &Path, owner: &str, group: &str, mode: &str) -> Result<(), String> {
    let mut command = Command::new("install");
    command
        .args(["-d", "-o", owner, "-g", group, "-m", mode])
        .arg(path);
    run_command(&mut command, "cannot install directory")
}

fn run_as_user(
    user: &str,
    home: &str,
    runtime: &str,
    program: &str,
    args: &[&str],
) -> Result<(), String> {
    let mut command = as_user_command(user, home, runtime, program, args);
    run_command(&mut command, "OpenShell user service command failed")
}

fn run_as_user_success(
    user: &str,
    home: &str,
    runtime: &str,
    program: &str,
    args: &[&str],
) -> bool {
    as_user_command(user, home, runtime, program, args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn as_user_command(user: &str, home: &str, runtime: &str, program: &str, args: &[&str]) -> Command {
    let mut command = Command::new("runuser");
    command
        .args(["-u", user, "--", "env"])
        .arg(format!("HOME={home}"))
        .arg(format!("XDG_RUNTIME_DIR={runtime}"))
        .arg(format!("DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus"))
        .arg(program)
        .args(args);
    command
}

fn canonical_absolute_directory(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err("release path must be absolute".to_owned());
    }
    require_real_directory(path, "release path must be a real directory")?;
    let canonical =
        fs::canonicalize(path).map_err(|error| format!("cannot resolve release path: {error}"))?;
    if canonical != path {
        return Err("release path must be canonical".to_owned());
    }
    Ok(canonical)
}

fn installer_root() -> Result<PathBuf, String> {
    if let Some(explicit) = std::env::var_os("OPENBOX_INSTALL_ROOT") {
        let root = PathBuf::from(explicit);
        return fs::canonicalize(&root)
            .map_err(|error| format!("cannot resolve installer root {}: {error}", root.display()));
    }
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot resolve current executable: {error}"))?;
    if let Some(parent) = executable.parent() {
        if parent.join("deploy").join(SERVICE_NAME).is_file() {
            return Ok(parent.to_owned());
        }
    }
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."));
    if source.join("deploy").join(SERVICE_NAME).is_file() {
        return fs::canonicalize(source)
            .map_err(|error| format!("cannot resolve source root: {error}"));
    }
    Err("cannot locate trusted installer assets beside obs or in the source checkout".to_owned())
}

fn require_linux() -> Result<(), String> {
    if cfg!(target_os = "linux") && command_output("uname", &["-s"]).as_deref() == Ok("Linux") {
        Ok(())
    } else {
        Err("requires Linux and systemd".to_owned())
    }
}

fn approved(mode: DependencyMode, prompt: &str) -> bool {
    match mode {
        DependencyMode::Yes => true,
        DependencyMode::No => false,
        DependencyMode::Ask => ask_yes_no(prompt),
    }
}

pub(crate) fn ask_yes_no_for_local(prompt: &str) -> bool {
    ask_yes_no(prompt)
}

fn ask_yes_no(prompt: &str) -> bool {
    let Ok(mut writer) = OpenOptions::new().write(true).open("/dev/tty") else {
        return false;
    };
    let Ok(reader) = OpenOptions::new().read(true).open("/dev/tty") else {
        return false;
    };
    if write!(writer, "{prompt} [y/N] ")
        .and_then(|_| writer.flush())
        .is_err()
    {
        return false;
    }
    let mut answer = String::new();
    if BufReader::new(reader).read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim_end(), "y" | "Y" | "yes" | "YES")
}

fn require_real_directory(path: &Path, message: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| message.to_owned())?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn require_regular_file(path: &Path, message: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| message.to_owned())?;
    if metadata.is_file() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn is_symlink(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_symlink()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("cannot inspect {}: {error}", path.display())),
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

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("cannot run {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program} exited {}", output.status));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim_end_matches(['\n', '\r'])
        .to_owned())
}

fn run_program(program: &str, args: &[&str]) -> Result<(), String> {
    let mut command = Command::new(program);
    command.args(args);
    run_command(&mut command, &format!("{program} failed"))
}

fn run_os(program: &str, args: &[&OsStr]) -> Result<(), String> {
    let mut command = Command::new(program);
    command.args(args);
    run_command(&mut command, &format!("{program} failed"))
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

fn mktemp(template: &str) -> Result<PathBuf, String> {
    command_output("mktemp", &["-d", template]).map(PathBuf::from)
}

fn chmod(path: &Path, mode: &str) -> Result<(), String> {
    let mut command = Command::new("chmod");
    command.arg(mode).arg(path);
    run_command(&mut command, "chmod failed")
}

fn chown(path: &Path, owner: &str, group: &str) -> Result<(), String> {
    let mut command = Command::new("chown");
    command.arg(format!("{owner}:{group}")).arg(path);
    run_command(&mut command, "chown failed")
}

fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| "release paths must be valid UTF-8".to_owned())
}

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

#[cfg(unix)]
fn exec_command(mut command: Command, message: &str) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let error = command.exec();
    Err(format!("{message}: {error}"))
}

#[cfg(not(unix))]
fn exec_command(_command: Command, message: &str) -> Result<(), String> {
    Err(message.to_owned())
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
    use super::{parse_options, DependencyMode, Options};
    use std::path::PathBuf;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn parses_install_options_and_release() {
        assert_eq!(
            parse_options(&args(&["--install-dependencies", "--no-start", "/release"])),
            Ok(Options {
                local: false,
                no_start: true,
                dependency_mode: DependencyMode::Yes,
                release: Some(PathBuf::from("/release")),
                privileged_phase: false,
                original_arguments: args(&["--install-dependencies", "--no-start", "/release"]),
            })
        );
    }

    #[test]
    fn internal_phase_is_only_accepted_first() {
        assert!(parse_options(&args(&["--local", "--_openbox-privileged-phase"])).is_err());
        assert!(parse_options(&args(&["--_openbox-privileged-phase", "/release"])).is_ok());
    }
}
