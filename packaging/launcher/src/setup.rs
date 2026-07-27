//! First-run setup orchestration.
//!
//! `setup` is a single command that runs the full wizard:
//!   1. Check dependencies.
//!   2. Install missing dependencies (silently — logs failures, never blocks).
//!   3. Download the pinned OpenShell release.
//!   4. Verify the pin.
//!   5. Set up the service.
//!
//! The wizard runs to completion without stopping. If something fails
//! (e.g. sudo denied for a dep install), it logs and moves on.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::deps;
use crate::{banner, err, info, ok, pin, step, warn};

/// Path to the fetch script relative to the launcher crate.
fn fetch_script() -> Option<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let script = manifest.join("scripts/fetch-openshell-deps.sh");
    if script.exists() {
        Some(script)
    } else {
        None
    }
}

/// Run the full setup flow.
pub fn run(skip_deps: bool, skip_service: bool, no_start: bool) -> ExitCode {
    banner();
    let (os, arch) = crate::platform();
    info(&format!("{os}/{arch}"));

    if os == "windows" {
        err("Windows is not supported directly; use WSL2.");
        return ExitCode::FAILURE;
    }

    // ── Step 1: Check dependencies ──────────────────────────────────────
    println!();
    step("Checking dependencies");
    let deps = deps::required_deps();
    let (missing_required, missing_optional) = deps::check_all(&deps);

    if !missing_required.is_empty() {
        err("required dependencies are missing");
        for dep in &missing_required {
            info(&format!(
                "{}: {}",
                dep.name,
                dep.install_cmd.unwrap_or("install manually")
            ));
        }
        return ExitCode::FAILURE;
    }

    if !deps::has_runtime(&deps) {
        println!();
        warn("no runtime detected — install Podman or Docker before running.");
        if cfg!(target_os = "macos") {
            info("brew install podman");
        } else {
            info("sudo apt-get install podman   # or docker.io");
        }
    }

    // ── Step 2: Install missing deps ────────────────────────────────────
    println!();
    step("Installing missing dependencies");
    if !skip_deps && !missing_optional.is_empty() {
        deps::install_missing(&missing_optional.to_vec());
    } else if missing_optional.is_empty() {
        ok("all dependencies present");
    } else {
        info("skipped (--skip-deps)");
    }

    // ── Step 3: Download OpenShell ──────────────────────────────────────
    println!();
    step("Downloading pinned OpenShell");
    let script = match fetch_script() {
        Some(s) => s,
        None => {
            err("fetch-openshell-deps.sh not found");
            info("ensure the launcher is built from the source repository");
            return ExitCode::FAILURE;
        }
    };

    let bundle_dir = PathBuf::from("./openbox-sandbox-bundle");
    if bundle_dir.join("bin/openshell-gateway").exists() {
        ok("already present in bundle");
    } else {
        info(&format!("fetching v{}", pin::REQUIRED_VERSION));
        let status = Command::new("bash")
            .arg(script.to_str().unwrap_or(""))
            .current_dir(std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
            .status();
        match status {
            Ok(s) if s.success() => ok("downloaded and verified"),
            Ok(s) => {
                err(&format!("fetch failed (exit {})", s.code().unwrap_or(-1)));
                return ExitCode::FAILURE;
            }
            Err(e) => {
                err(&format!("fetch failed: {e}"));
                return ExitCode::FAILURE;
            }
        }
    }

    // ── Step 4: Verify pin ──────────────────────────────────────────────
    println!();
    step("Verifying version pin");
    std::env::set_var("OPENBOX_BUNDLE_DIR", &bundle_dir);
    match crate::bundle::resolve() {
        Ok(artifacts) => {
            info(&format!("gateway: {}", artifacts.gateway.display()));
            match pin::verify(&artifacts, true) {
                Ok(()) => {
                    ok(&format!("openshell {} verified", pin::REQUIRED_VERSION));
                }
                Err(err_msg) => {
                    err(&format!("{}: {}", err_msg.artifact, err_msg.reason));
                    return ExitCode::FAILURE;
                }
            }
        }
        Err(missing) => {
            err(&format!("artifact not found: {missing}"));
            return ExitCode::FAILURE;
        }
    }

    // ── Service setup ───────────────────────────────────────────────────
    if !skip_service {
        println!();
        step("Setting up service");
        let gateway = bundle_dir.join("bin/openshell-gateway");
        if let Err(code) = crate::service::setup(&gateway, &bundle_dir, no_start) {
            return code;
        }
    }

    // ── Done ────────────────────────────────────────────────────────────
    println!();
    ok("openbox-sandbox is set up");
    info(&format!("bundle: {}", bundle_dir.display()));
    println!();
    info("CONSTRAIN is fail-closed: if the sandbox runtime is unavailable,");
    info("the governed activity fails. There is no host fallback.");
    ExitCode::SUCCESS
}
