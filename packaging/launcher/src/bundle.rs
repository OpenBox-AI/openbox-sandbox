//! Artifact discovery.
//!
//! `obs` is a thin launcher. Artifacts (the external `OpenShell` gateway,
//! CLI, driver, and OpenBox policies) resolve from operator-installed paths.
//! Resolution order:
//!   1. `$OPENBOX_BUNDLE_DIR` — an operator-provided release bundle. Binaries
//!      may use either its conventional `bin/` and `libexec/` layout (as emitted
//!      by `scripts/fetch-openshell-deps.sh`) or live directly at its root.
//!   2. A well-known install location (Homebrew on macOS, `/usr/local` on Linux).
//!   3. `PATH` (for the `openshell` / `openshell-gateway` binaries).
//!   4. The in-repo build output, so `cargo run` works from a source checkout.

use std::env;
use std::path::{Path, PathBuf};

/// The resolved, on-disk artifacts the launcher will run.
pub struct Artifacts {
    /// OpenShell gateway daemon.
    pub gateway: PathBuf,
    /// OpenShell CLI.
    pub cli: PathBuf,
    /// OpenShell microVM driver, when installed. It is optional because
    /// container/kubernetes deployments do not need it.
    pub driver_vm: Option<PathBuf>,
    /// Strict floor policy (Landlock hard_requirement).
    pub policy_strict: PathBuf,
    /// Degraded dev policy (Landlock best_effort).
    pub policy_dev: PathBuf,
}

impl Artifacts {
    /// Policy path for the requested tier.
    pub fn policy(&self, dev: bool) -> &Path {
        if dev {
            &self.policy_dev
        } else {
            &self.policy_strict
        }
    }
}

/// Resolve every required artifact, or return the name of the first one that is
/// missing so the caller can print an actionable error.
pub fn resolve() -> Result<Artifacts, &'static str> {
    let gateway = find_binary("openshell-gateway").ok_or("openshell-gateway")?;
    let cli = find_binary("openshell").ok_or("openshell")?;
    let policy_strict =
        find_policy("policy-deny-network.yaml").ok_or("policy-deny-network.yaml")?;
    let policy_dev =
        find_policy("policy-deny-network-dev.yaml").ok_or("policy-deny-network-dev.yaml")?;
    Ok(Artifacts {
        gateway,
        cli,
        driver_vm: find_driver_vm(),
        policy_strict,
        policy_dev,
    })
}

/// The operator-provided bundle directory, if set.
fn bundle_dir() -> Option<PathBuf> {
    env::var_os("OPENBOX_BUNDLE_DIR").map(PathBuf::from)
}

/// Locate an executable artifact by name.
fn find_binary(name: &str) -> Option<PathBuf> {
    if let Some(dir) = bundle_dir() {
        for candidate in [dir.join(name), dir.join("bin").join(name)] {
            if is_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    for prefix in install_prefixes() {
        let candidate = prefix.join("bin").join(name);
        if is_file(&candidate) {
            return Some(candidate);
        }
    }
    find_on_path(name)
}

/// Locate the optional VM driver in the release/Homebrew layouts OpenShell
/// itself probes. This is not required for container/kubernetes deployments.
fn find_driver_vm() -> Option<PathBuf> {
    const NAME: &str = "openshell-driver-vm";
    if let Some(dir) = bundle_dir() {
        for candidate in [
            dir.join(NAME),
            dir.join("libexec").join(NAME),
            dir.join("bin").join(NAME),
        ] {
            if is_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    for prefix in install_prefixes() {
        for candidate in [
            prefix.join("libexec").join(NAME),
            prefix.join("libexec").join("openshell").join(NAME),
            prefix.join("bin").join(NAME),
        ] {
            if is_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    find_on_path(NAME)
}

/// Locate a policy file by name.
fn find_policy(name: &str) -> Option<PathBuf> {
    if let Some(dir) = bundle_dir() {
        for candidate in [
            dir.join(name),
            dir.join("share").join("openbox-sandbox").join(name),
        ] {
            if is_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    let mut candidates = Vec::new();
    for prefix in install_prefixes() {
        candidates.push(prefix.join("share/openbox-sandbox").join(name));
    }
    // In-repo checkout: policies live under deploy/policies relative to the
    // launcher crate (packaging/launcher/../../deploy/policies).
    if let Some(repo) = repo_root() {
        candidates.push(repo.join("deploy/policies").join(name));
    }
    candidates.into_iter().find(|path| is_file(path))
}

/// Platform install prefixes to probe for artifacts.
fn install_prefixes() -> Vec<PathBuf> {
    let mut prefixes = Vec::new();
    if cfg!(target_os = "macos") {
        prefixes.push(PathBuf::from("/opt/homebrew/opt/openshell"));
        prefixes.push(PathBuf::from("/opt/homebrew"));
    }
    prefixes.push(PathBuf::from("/usr/local"));
    prefixes.push(PathBuf::from("/usr"));
    prefixes
}

/// The repository root, derived from this crate's compile-time location, so a
/// `cargo run` from a source checkout finds the in-repo policies.
fn repo_root() -> Option<PathBuf> {
    // CARGO_MANIFEST_DIR = <repo>/packaging/launcher
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.parent()?.parent().map(Path::to_path_buf)
}

/// Search `PATH` for an executable.
fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| is_file(candidate))
}

fn is_file(path: &Path) -> bool {
    path.is_file()
}
