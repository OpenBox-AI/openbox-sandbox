//! `obs publish` — publish a release directory to GitHub Releases.
//!
//! Single "latest" slot: a floating tag (default `hosted-bin`) always points
//! at the current release; publishing replaces the previous release and tag,
//! so a stale release can be removed without a git-history trail (release
//! assets are not part of git history). Designed as if the repository were
//! public: asset URLs are stable public download links once public.
//!
//! Requires the `gh` CLI and the explicit `salamisandwich77` account token on
//! the dev host. Shells out to `gh` and `sha256sum`; the launcher stays
//! dependency-free.

use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use crate::{err, info, ok, step};

const DEFAULT_TAG: &str = "hosted-bin";
const REPO: &str = "OpenBox-AI/openbox-sandbox";
const PUBLISH_ACCOUNT: &str = "salamisandwich77";

/// `obs publish <release-dir> [tag]`
pub fn run(release_dir: &str, tag: &str) -> ExitCode {
    banner_publish();
    let tag = if tag.is_empty() { DEFAULT_TAG } else { tag };

    // ── Preflight ─────────────────────────────────────────────────────────
    let gh = std::env::var_os("GH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("gh"));
    if !Command::new(&gh)
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_ok()
    {
        err("gh CLI is required (https://cli.github.com)");
        return ExitCode::FAILURE;
    }
    let token_output = Command::new(&gh)
        .args(["auth", "token", "--user", PUBLISH_ACCOUNT])
        .stderr(Stdio::null())
        .output();
    let token = match token_output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        }
        _ => String::new(),
    };
    if token.is_empty() {
        err(&format!(
            "gh token for {PUBLISH_ACCOUNT} is required — run `gh auth login --hostname github.com`"
        ));
        return ExitCode::FAILURE;
    }

    let dir = PathBuf::from(release_dir);
    if !dir.is_dir() {
        err(&format!("release dir not found: {}", dir.display()));
        return ExitCode::FAILURE;
    }
    let sums = dir.join("SHA256SUMS");
    if !sums.is_file() {
        err(&format!("SHA256SUMS not found in {}", dir.display()));
        return ExitCode::FAILURE;
    }

    // ── Verify checksums ──────────────────────────────────────────────────
    step("Verifying release checksums");
    let verify = Command::new("sha256sum")
        .arg("-c")
        .arg(&sums)
        .current_dir(&dir)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status();
    match verify {
        Ok(s) if s.success() => ok("checksums verified"),
        Ok(_) => {
            err("checksum verification failed");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            err(&format!("sha256sum failed: {e}"));
            return ExitCode::FAILURE;
        }
    }

    // ── Atomic replace ────────────────────────────────────────────────────
    // Upload under a staging tag first so a failed upload leaves the current
    // release untouched; only after the staging release exists do we delete
    // the old one and retag the staging release to the final tag.
    step(&format!("Publishing tag '{tag}'"));
    let staging = format!("{tag}-staging-{}", std::process::id());
    let display = tag.trim_start_matches('v');
    let title = format!("OpenBox Sandbox {display}");
    let notes = notes_markdown(tag);
    let mut create = gh_command(&gh, &token);
    create.args([
        "release", "create", &staging, "--repo", REPO, "--draft", "--title", &title, "--notes",
        &notes,
    ]);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => {
            err(&format!("cannot read release dir: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let mut count = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            create.arg(&path);
            count += 1;
        }
    }
    let created = create
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status();
    match created {
        Ok(s) if s.success() => ok(&format!(
            "staging release '{staging}' uploaded ({count} assets)"
        )),
        Ok(_) => {
            err(&format!(
                "gh release create failed; the current '{tag}' release is untouched"
            ));
            return ExitCode::FAILURE;
        }
        Err(e) => {
            err(&format!(
                "gh release create failed: {e}; the current '{tag}' release is untouched"
            ));
            return ExitCode::FAILURE;
        }
    }

    // Retag the staging release to the final tag, replacing the old one.
    let staging_id = match staging_release_id(&gh, &token, &staging) {
        Ok(id) => id,
        Err(code) => return code,
    };
    // The new release is fully uploaded; only now remove the old one so the
    // final tag is free for the retag.
    let old_exists = gh_command(&gh, &token)
        .args(["release", "view", tag, "--repo", REPO])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if matches!(old_exists, Ok(s) if s.success()) {
        let _ = gh_command(&gh, &token)
            .args([
                "release",
                "delete",
                tag,
                "--yes",
                "--cleanup-tag",
                "--repo",
                REPO,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status();
    }
    let retag = gh_command(&gh, &token)
        .args([
            "api",
            "--method",
            "PATCH",
            &format!("repos/{REPO}/releases/{staging_id}"),
            "-f",
            &format!("tag_name={tag}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status();
    match retag {
        Ok(s) if s.success() => {}
        _ => {
            err(&format!(
                "staging upload succeeded but retagging to '{tag}' failed;                  the previous release is still current (staging tag: {staging})"
            ));
            return ExitCode::FAILURE;
        }
    }
    // The previous tag was moved by the retag; delete any leftover tag ref.
    let _ = gh_command(&gh, &token)
        .args([
            "api",
            "--method",
            "DELETE",
            &format!("repos/{REPO}/git/refs/tags/{staging}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    // Un-draft so the release becomes visible (and "latest" eligible).
    let publish = gh_command(&gh, &token)
        .args([
            "api",
            "--method",
            "PATCH",
            &format!("repos/{REPO}/releases/{staging_id}"),
            "-f",
            "draft=false",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status();
    if !matches!(publish, Ok(s) if s.success()) {
        err(&format!(
            "release retagged to '{tag}' but could not be published (still draft at {staging})"
        ));
        return ExitCode::FAILURE;
    }
    ok(&format!("release '{tag}' published ({count} assets)"));

    // ── Report ────────────────────────────────────────────────────────────
    info("download base (public when the repo is public):");
    info(&format!(
        "  https://github.com/{REPO}/releases/download/{tag}/"
    ));
    let listed = gh_command(&gh, &token)
        .args([
            "release",
            "view",
            tag,
            "--repo",
            REPO,
            "--json",
            "assets",
            "--jq",
            ".assets[].name",
        ])
        .stdout(Stdio::inherit())
        .status();
    if !matches!(listed, Ok(s) if s.success()) {
        info("(could not list assets)");
    }
    ExitCode::SUCCESS
}

fn gh_command(gh: &std::path::Path, token: &str) -> Command {
    let mut command = Command::new(gh);
    command.env("GH_TOKEN", token);
    command
}

fn staging_release_id(
    gh: &std::path::Path,
    token: &str,
    staging: &str,
) -> Result<String, ExitCode> {
    // releases/tags/<tag> hides drafts; the list endpoint includes them.
    let output = gh_command(gh, token)
        .args([
            "api",
            &format!("repos/{REPO}/releases"),
            "--jq",
            &format!(".[] | select(.tag_name==\"{staging}\") | .id"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output();
    match output {
        Ok(o) if o.status.success() => {
            let id = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if id.is_empty() {
                err("cannot resolve staging release id");
                Err(ExitCode::FAILURE)
            } else {
                Ok(id)
            }
        }
        _ => {
            err("cannot resolve staging release id");
            Err(ExitCode::FAILURE)
        }
    }
}

fn notes_markdown(tag: &str) -> String {
    format!(
        "## OpenBox Sandbox {version}

Pinned components:
- openbox-sandbox service + obs launcher: source-pinned releases (see git history)
- OpenShell: locked release **0.0.88** (upstream sha256-verified tarballs)

Platforms: linux x86_64, linux aarch64, macOS arm64

Assets: per-platform obs, openbox-sandbox, openbox-sandbox-verify and the
OpenShell bundle tarball, plus the sandbox policy, SHA256SUMS, SPDX +
CycloneDX SBOMs and keyless cosign bundles.

Verification:
```
sha256sum -c SHA256SUMS
cosign verify-blob --bundle <asset>.spdx.json.sbom.bundle.json \
  --certificate-identity-regexp 'https://github.com/{repo}' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com <asset>.spdx.json
```

Consumption: obs provision with OPENBOX_OPENSHELL_BUNDLE_URL (see packaging/launcher/README.md).",
        version = tag.trim_start_matches('v'),
        repo = REPO
    )
}

fn banner_publish() {
    crate::banner();
    crate::info("publish release dir -> GitHub Releases (atomic replace)");
}
