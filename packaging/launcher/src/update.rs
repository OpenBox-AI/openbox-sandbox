//! `obs update` — download the latest release assets into the current dir.

use std::process::{Command, ExitCode, Stdio};

/// Download the release assets for the launcher's own line into the current
/// directory, verify SHA256SUMS, and replace the local obs.
pub fn run(all: bool) -> ExitCode {
    let repo = "OpenBox-AI/openbox-sandbox";
    // A launcher updates within its own release line and never switches lines:
    // a dev binary replacing itself with a base binary would quietly start
    // provisioning deny-network on the next run.
    //
    // The tag used to be pinned to v0.1.0/v0.1.0-dev, which made this command a
    // no-op at best: a newer launcher running `obs update` would fetch the
    // frozen release and downgrade itself. Resolve the newest published tag on
    // this line instead, keeping the pin only as an offline fallback.
    let dev = crate::channel() != "base";
    let pinned = crate::asset_tag(dev);
    let release = latest_release(repo, dev, pinned);

    // `obs update` converges on the newest published release for this line,
    // even when that moves backwards: an unreleased local build carries a
    // version number, not a guarantee, and refusing to move would leave a
    // broken build unrepairable by the very command meant to repair it. Going
    // backwards is legitimate, but it must never be silent — a downgrade
    // discards whatever the running binary carried, so say so plainly.
    if let Some(newest) = tag_version(&release) {
        if newest < parse_version(env!("CARGO_PKG_VERSION")) {
            crate::warn(&format!(
                "running {} is NEWER than the newest published {} release ({release})",
                env!("CARGO_PKG_VERSION"),
                crate::channel()
            ));
            crate::warn(&format!(
                "updating replaces it with {release} — anything only in the running build is lost"
            ));
        }
    }
    crate::info(&format!(
        "release line: {} — updating within the same channel to {release}",
        crate::channel()
    ));

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
        crate::err(
            "no release assets for this platform (darwin-arm64 and linux-x86_64 are published)",
        );
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
        let url = format!("https://github.com/{repo}/releases/download/{release}/{pattern}");
        let status = Command::new("curl")
            .args(["-fsSL", "--retry", "3", "-o", pattern])
            .arg(url)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        // An absent optional asset is fine; a required fetch failure surfaces
        // in the required-files check below.
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
        let actual = Command::new("shasum").args(["-a", "256", name]).output();
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
    // Linux refuses to open a running executable for writing (ETXTBSY), so
    // copying straight over `target` fails with "Text file busy" whenever obs
    // updates itself — which is every time. Stage the new binary beside it and
    // rename over the top: rename only swaps the directory entry, the running
    // process keeps its own inode, and the replacement stays atomic. macOS
    // allowed the direct copy, which is why this only ever bit Linux.
    let staged = format!("{target}.new");
    let _ = std::fs::remove_file(&staged);
    if let Err(e) = std::fs::copy(obs_name, &staged) {
        crate::err(&format!("could not stage {staged}: {e}"));
        return ExitCode::FAILURE;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&staged) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&staged, perms);
        }
    }
    if let Err(e) = std::fs::rename(&staged, &target) {
        let _ = std::fs::remove_file(&staged);
        crate::err(&format!("could not replace {target}: {e}"));
        return ExitCode::FAILURE;
    }
    crate::ok(&format!("{target} updated to {release} — assets verified"));
    ExitCode::SUCCESS
}

/// Newest published release tag on this launcher's line.
///
/// `releases/latest` is unusable here: GitHub marks a single release latest
/// across every line, and that is the base line, so a dev launcher would
/// silently pull base assets. List the releases and take the first whose tag
/// matches this line — the API returns them newest first. Any failure (no
/// network, rate limit, malformed body) falls back to the pinned tag so
/// `obs update` degrades to its previous behaviour rather than erroring.
fn latest_release(repo: &str, dev: bool, pinned: &str) -> String {
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "--retry",
            "2",
            "-H",
            "Accept: application/vnd.github+json",
        ])
        .arg(format!(
            "https://api.github.com/repos/{repo}/releases?per_page=100"
        ))
        .output();
    let Ok(output) = output else {
        return pinned.to_owned();
    };
    if !output.status.success() {
        return pinned.to_owned();
    }
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&output.stdout) else {
        return pinned.to_owned();
    };
    body.as_array()
        .and_then(|releases| {
            releases.iter().find_map(|release| {
                let draft = release
                    .get("draft")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                if draft {
                    return None;
                }
                let tag = release.get("tag_name")?.as_str()?;
                (tag.ends_with("-dev") == dev).then(|| tag.to_owned())
            })
        })
        .unwrap_or_else(|| pinned.to_owned())
}

/// Numeric version from a release tag (`v0.1.0-dev` -> `[0, 1, 0]`).
fn tag_version(tag: &str) -> Option<[u32; 3]> {
    let core = tag.trim_start_matches('v').split('-').next()?;
    let parsed = parse_version(core);
    (parsed != [0, 0, 0]).then_some(parsed)
}

/// Lenient dotted-version parse; missing or unparsable parts read as zero.
fn parse_version(value: &str) -> [u32; 3] {
    let mut out = [0u32; 3];
    for (slot, part) in out.iter_mut().zip(value.split('.')) {
        *slot = part.parse().unwrap_or(0);
    }
    out
}
