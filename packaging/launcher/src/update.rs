//! `obs update` — download the latest release assets into the current dir.

use std::process::{Command, ExitCode, Stdio};

/// Download the platform release assets for `tag` (default: latest release)
/// into the current directory, verify SHA256SUMS, and replace the local obs.
pub fn run(tag: Option<&str>) -> ExitCode {
    let gh = match which_gh() {
        Some(gh) => gh,
        None => {
            crate::err("gh CLI is required — install: brew install gh && gh auth login");
            return ExitCode::FAILURE;
        }
    };
    let repo = "OpenBox-AI/openbox-sandbox";
    let release = match tag {
        Some(t) => t.to_owned(),
        None => {
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
        "obs"
    };

    // Download per-pattern so a release that lacks one asset (base has no dev
    // tar; either may lack one of the policy names) doesn't fail the update.
    let patterns: &[&str] = &[
        obs_name,
        svc,
        "SHA256SUMS",
        "policy-allow-network-dev.yaml",
        "policy-deny-network-dev.yaml",
        dev_tar,
    ];
    for pattern in patterns.iter().filter(|p| !p.is_empty()) {
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

    let required = [obs_name, svc, "SHA256SUMS"];
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

    // Replace the running obs binary (macOS/Linux allow overwriting the
    // running executable; Windows-style locks don't apply).
    if let Err(e) = std::fs::copy(obs_name, "obs") {
        crate::err(&format!("could not replace obs: {e}"));
        return ExitCode::FAILURE;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata("obs") {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions("obs", perms);
        }
    }
    crate::ok(&format!("obs updated to {release} — assets verified"));
    ExitCode::SUCCESS
}

fn which_gh() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join("gh");
        candidate.is_file().then_some(candidate)
    })
}
