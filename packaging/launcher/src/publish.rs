//! `obs publish` — publish a release directory to GitHub Releases.
//!
//! Single "latest" slot: a floating tag (default `hosted-bin`) always points
//! at the current release; publishing replaces the previous release and tag,
//! so a stale release can be removed without a git-history trail (release
//! assets are not part of git history). Designed as if the repository were
//! public: asset URLs are stable public download links once public.
//!
//! Requires the `gh` CLI (installed and authenticated on the dev host).
//! Shells out to `gh` and `sha256sum`; the launcher stays dependency-free.

use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};

use crate::{err, info, ok, step};

const DEFAULT_TAG: &str = "hosted-bin";
const REPO: &str = "OpenBox-AI/openbox-sandbox";

/// `obs publish <release-dir> [tag]`
pub fn run(release_dir: &str, tag: &str) -> ExitCode {
    banner_publish();
    let tag = if tag.is_empty() { DEFAULT_TAG } else { tag };

    // ── Preflight ─────────────────────────────────────────────────────────
    let gh = std::env::var_os("GH").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("gh"));
    if !Command::new(&gh).arg("--version").stdout(Stdio::null()).status().is_ok() {
        err("gh CLI is required (https://cli.github.com)");
        return ExitCode::FAILURE;
    }
    let auth = Command::new(&gh)
        .args(["auth", "status"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match auth {
        Ok(s) if s.success() => {}
        _ => {
            err("gh is not authenticated — run `gh auth login` first");
            return ExitCode::FAILURE;
        }
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

    // ── Replace the floating tag ──────────────────────────────────────────
    step(&format!("Publishing tag '{tag}'"));
    let exists = Command::new(&gh)
        .args(["release", "view", tag, "--repo", REPO])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if matches!(exists, Ok(s) if s.success()) {
        info(&format!("replacing existing release '{tag}'"));
        let replaced = Command::new(&gh)
            .args(["release", "delete", tag, "--yes", "--cleanup-tag", "--repo", REPO])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status();
        if !matches!(replaced, Ok(s) if s.success()) {
            err(&format!("could not delete previous release '{tag}'"));
            return ExitCode::FAILURE;
        }
    }

    // ── Upload assets ─────────────────────────────────────────────────────
    let mut create = Command::new(&gh);
    create.args(["release", "create", tag, "--repo", REPO, "--title", &format!("OpenBox Sandbox hosted bin ({tag})"),
        "--notes", "Single-bin obs (embedded scripts), root service, prebuilt verify harness, pinned OpenShell bundle (source pin f1690849), policy, SBOMs.\n\nVerify: sha256sum -c SHA256SUMS   (then scan with Syft v1.20.0)."]);
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
        Ok(s) if s.success() => ok(&format!("release '{tag}' published ({count} assets)")),
        Ok(_) => {
            err("gh release create failed");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            err(&format!("gh release create failed: {e}"));
            return ExitCode::FAILURE;
        }
    }

    // ── Report ────────────────────────────────────────────────────────────
    info("download base (public when the repo is public):");
    info(&format!(
        "  https://github.com/{REPO}/releases/download/{tag}/"
    ));
    let listed = Command::new(&gh)
        .args(["release", "view", tag, "--repo", REPO, "--json", "assets", "--jq", ".assets[].name"])
        .stdout(Stdio::inherit())
        .status();
    if !matches!(listed, Ok(s) if s.success()) {
        info("(could not list assets)");
    }
    ExitCode::SUCCESS
}

fn banner_publish() {
    crate::banner();
    crate::info("publish release dir -> GitHub Releases (floating tag)");
}
