//! Dependency detection and installation.
//!
//! Checks for required runtime dependencies (container/hypervisor drivers,
//! package managers) and installs missing ones via the platform package
//! manager. The flow is identical on macOS and Linux — only the underlying
//! commands differ (brew vs apt/dnf).

use std::process::Command;

use crate::{info, ok, warn};

/// A dependency the launcher needs to function.
pub struct Dep {
    pub name: &'static str,
    pub required: bool,
    pub check_cmd: &'static [&'static str],
    pub install_cmd: Option<&'static str>,
}

impl Dep {
    fn is_installed(&self) -> bool {
        Command::new(self.check_cmd[0])
            .args(&self.check_cmd[1..])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

/// Returns the platform-appropriate dependency list.
///
/// None of these are hard-required at setup time. The launcher only needs
/// at least one runtime (podman OR docker OR hypervisor) at actual runtime.
/// curl is only needed during the fetch step; it ships with every macOS
/// install and most Linux distros.
pub fn required_deps() -> Vec<Dep> {
    if cfg!(target_os = "macos") {
        vec![
            Dep {
                name: "podman",
                required: false,
                check_cmd: &["podman", "--version"],
                install_cmd: Some("brew install podman"),
            },
            Dep {
                name: "docker",
                required: false,
                check_cmd: &["docker", "--version"],
                install_cmd: None, // Docker Desktop is a manual install
            },
        ]
    } else if cfg!(target_os = "linux") {
        vec![
            Dep {
                name: "podman",
                required: false,
                check_cmd: &["podman", "--version"],
                install_cmd: Some("sudo apt-get install -y podman || sudo dnf install -y podman"),
            },
            Dep {
                name: "docker",
                required: false,
                check_cmd: &["docker", "--version"],
                install_cmd: Some(
                    "sudo apt-get install -y docker.io || sudo dnf install -y docker",
                ),
            },
            Dep {
                name: "curl",
                required: false,
                check_cmd: &["curl", "--version"],
                install_cmd: Some("sudo apt-get install -y curl || sudo dnf install -y curl"),
            },
        ]
    } else {
        vec![]
    }
}

/// Check if at least one runtime (container or hypervisor) is available.
/// Returns true if the system can actually run a sandbox.
pub fn has_runtime(deps: &[Dep]) -> bool {
    let has_container = deps
        .iter()
        .any(|d| matches!(d.name, "podman" | "docker") && d.is_installed());
    if has_container {
        return true;
    }
    if cfg!(target_os = "macos") {
        Command::new("sysctl")
            .args(["-n", "kern.hv_support"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "1")
            .unwrap_or(false)
    } else if cfg!(target_os = "linux") {
        std::path::Path::new("/dev/kvm").exists()
    } else {
        false
    }
}

/// Check all dependencies and print their status.
/// Returns (missing_required, missing_optional).
pub fn check_all(deps: &[Dep]) -> (Vec<&Dep>, Vec<&Dep>) {
    let mut missing_required = Vec::new();
    let mut missing_optional = Vec::new();
    for dep in deps {
        if dep.is_installed() {
            ok(&format!("{} installed", dep.name));
        } else if dep.required {
            warn(&format!("{} not found (required)", dep.name));
            missing_required.push(dep);
        } else {
            info(&format!("{} not found", dep.name));
            missing_optional.push(dep);
        }
    }
    (missing_required, missing_optional)
}

/// Install missing dependencies. Runs the install commands automatically.
/// If a command fails (e.g. no sudo), logs and continues — never blocks the
/// wizard.
pub fn install_missing(deps: &[&Dep]) {
    for dep in deps {
        let cmd = match dep.install_cmd {
            Some(cmd) => cmd,
            None => {
                info(&format!(
                    "{}: no automated install (install manually)",
                    dep.name
                ));
                continue;
            }
        };

        info(&format!("{}: {cmd}", dep.name));
        let status = Command::new("sh").arg("-c").arg(cmd).status();
        match status {
            Ok(s) if s.success() => ok(&format!("{} installed", dep.name)),
            Ok(s) => {
                warn(&format!(
                    "{}: install failed (exit {}), skipping",
                    dep.name,
                    s.code().unwrap_or(-1)
                ));
            }
            Err(e) => {
                warn(&format!("{}: install failed ({e}), skipping", dep.name));
            }
        }
    }
}
