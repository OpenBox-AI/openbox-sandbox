//! `obs update` — download the latest release assets into the current dir.

use std::process::{Command, ExitCode, Stdio};

/// Download the platform release assets for `tag` (default: latest release)
/// into the current directory, verify SHA256SUMS, and replace the local obs.
pub fn run(tag: Option<&str>, all: bool) -> ExitCode {
    let gh = match which_gh() {
        Some(gh) => gh,
        None => {
            crate::err("gh CLI is required — install: brew install gh && gh auth login");
            return ExitCode::FAILURE;
        }
    };
    let repo = "OpenBox-AI/openbox-sandbox";
    // Default channel: detect which release line the current directory holds.
    // The dev release ships the dev image tar + allow policy; the base ships
    // the deny policy. When neither is present, fall back to the latest.
    let release = match tag {
        Some(t) => t.to_owned(),
        None => {
            let dev_markers = [
                "openbox-sandbox-dev-darwin-arm64.tar.gz",
                "openbox-sandbox-dev-linux-x86_64.tar.gz",
                "policy-allow-network-dev.yaml",
            ];
            let base_markers = ["policy-deny-network-dev.yaml"];
            if dev_markers.iter().any(|m| std::path::Path::new(m).is_file()) {
                crate::info("dev channel detected — targeting v0.1.0-dev");
                "v0.1.0-dev".to_owned()
            } else if base_markers.iter().any(|m| std::path::Path::new(m).is_file()) {
                crate::info("base channel detected — targeting v0.1.0");
                "v0.1.0".to_owned()
            } else {
                let out = Command::new(&gh)
                    .args([
                        "release",
                        "view",
                        "--repo",
                        repo,
                        "--json",
                        "tagName",
                        "--jq",
                        ".tagName",
                    ])
                    .output();
                match out {
                    Ok(o) if o.status.success() => {
                        String::from_utf8_lossy(&o.stdout).trim().to_owned()
                    }
                    _ => {
                        crate::err("could not resolve the latest release tag");
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
    };
    if release.is_empty() {
        crate::err("no release tag resolved");
        return ExitCode::FAILURE;
    }
    crate::info(&format!("updating to {release} into the current directory"));

    let (svc, dev_tar) = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        (
            "openbox-sandbox-darwin-arm64",
            "openbox-sandbox-dev-darwin-arm64.tar.gz",
        )
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        (
            "openbox-sandbox-linux-x86_64",
            "openbox-sandbox-dev-linux-x86_64.tar.gz",
        )
    } else {
        ("openbox-sandbox", "")
    };
    let obs_name = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "obs-darwin-arm64"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "obs-linux-x86_64"
    } else {
        crate::err("no release assets for this platform (darwin-arm64 and linux-x86_64 are published)");
        return ExitCode::FAILURE;
    };

    // Default: only obs + the checksums needed to verify it. --all adds the
    // service binary, policies, and the dev image tar — scoped to the release
    // line so patterns that can't exist on the target tag are never tried.
    let is_dev = release.contains("-dev");
    let mut patterns: Vec<&str> = vec![obs_name, "SHA256SUMS"];
    if all {
        patterns.push(svc);
        patterns.push(if is_dev {
            "policy-allow-network-dev.yaml"
        } else {
            "policy-deny-network-dev.yaml"
        });
        if is_dev && !dev_tar.is_empty() {
            patterns.push(dev_tar);
        }
    }
    for pattern in patterns.iter().filter(|p| !p.is_empty()) {
        crate::info(&format!("downloading {pattern}"));
        let status = Command::new(&gh)
            .args([
                "release",
                "download",
                &release,
                "--repo",
                repo,
                "--pattern",
                pattern,
                "--clobber",
            ])
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        // An unmatched pattern is fine; a real transport failure surfaces in
        // the required-files check below.
        let _ = status;
    }

    let required = if all {
        vec![obs_name, svc, "SHA256SUMS"]
    } else {
        vec![obs_name, "SHA256SUMS"]
    };
    let missing: Vec<&str> = required
        .iter()
        .filter(|name| !std::path::Path::new(**name).is_file())
        .copied()
        .collect();
    if !missing.is_empty() {
        crate::err(&format!(
            "release download incomplete — missing: {}",
            missing.join(", ")
        ));
        return ExitCode::FAILURE;
    }

    // Verify the downloaded assets against the published sums (only the files
    // present in this directory are checked).
    let sums = Command::new("shasum")
        .args(["-a", "256", "-c", "SHA256SUMS", "--ignore-missing"])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();
    if !matches!(sums, Ok(s) if s.success()) {
        crate::err("SHA256SUMS verification failed — deleting nothing, inspect the output");
        return ExitCode::FAILURE;
    }

    // Replace the binary the user actually invoked — a renamed copy of obs is
    // updated in place, not ignored. Resolution: args[0] with a directory
    // component wins; a bare name is resolved through PATH; the final
    // fallback is ./obs.
    let invoked = std::env::args().next().unwrap_or_else(|| "obs".to_owned());
    let target = if invoked.contains('/') {
        invoked.clone()
    } else if let Some(dir) = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .and_then(|dirs| dirs.into_iter().find(|d| d.join(&invoked).is_file()))
    {
        dir.join(&invoked).to_string_lossy().to_string()
    } else if std::path::Path::new(&invoked).is_file() {
        invoked.clone()
    } else {
        "obs".to_owned()
    };
    crate::info(&format!("replacing {target}"));
    if let Err(e) = std::fs::copy(obs_name, &target) {
        crate::err(&format!("could not replace {target}: {e}"));
        return ExitCode::FAILURE;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&target) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&target, perms);
        }
    }
    crate::ok(&format!("{target} updated to {release} — assets verified"));
    ExitCode::SUCCESS
}

fn which_gh() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join("gh");
        candidate.is_file().then_some(candidate)
    })
}
