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
    // The binary knows its channel — update targets the SAME line by default.
    let release = match tag {
        Some(t) => t.to_owned(),
        None => {
            let t = if crate::channel() == "base" {
                "v0.1.0"
            } else {
                "v0.1.0-dev"
            };
            crate::info(&format!("release line: {} — updating within the same channel", crate::channel()));
            t.to_owned()
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
    let vm_cache = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "prepared-vm-cache-darwin-arm64.tar.gz"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "prepared-vm-cache-linux-x86_64.tar.gz"
    } else {
        ""
    };

    // Default: update both executable components plus the checksums needed to
    // verify them. --all also adds policies and large cache/image assets —
    // scoped to the release line so absent patterns are never requested.
    let is_dev = release.contains("-dev");
    let mut patterns: Vec<&str> = vec![obs_name, svc, "SHA256SUMS"];
    if all {
        patterns.push(if is_dev {
            "policy-allow-network-dev.yaml"
        } else {
            "policy-deny-network-dev.yaml"
        });
        if is_dev && !dev_tar.is_empty() {
            patterns.push(dev_tar);
        }
        if !vm_cache.is_empty() {
            patterns.push(vm_cache);
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

    let sums_txt = std::fs::read_to_string("SHA256SUMS").unwrap_or_default();
    for name in [obs_name, svc] {
        let expected = sums_txt
            .lines()
            .find(|line| line.ends_with(&format!("  {name}")))
            .and_then(|line| line.split_whitespace().next())
            .unwrap_or("")
            .to_owned();
        if expected.is_empty() {
            crate::err(&format!(
                "SHA256SUMS has no entry for {name} — refusing to replace"
            ));
            return ExitCode::FAILURE;
        }
        let actual = Command::new("shasum")
            .args(["-a", "256", name])
            .output();
        let actual = match actual {
            Ok(output) => String::from_utf8_lossy(&output.stdout)
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_owned(),
            Err(_) => String::new(),
        };
        if actual != expected {
            crate::err(&format!(
                "{name} checksum mismatch (expected {expected}, got {actual}) — deleting nothing"
            ));
            return ExitCode::FAILURE;
        }
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
