//! `obs-release publish` — publish a release directory to GitHub Releases.
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

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use crate::{err, info, ok, step};

const DEFAULT_TAG: &str = "hosted-bin";
const REPO: &str = "OpenBox-AI/openbox-sandbox";
const PUBLISH_ACCOUNT: &str = "salamisandwich77";

/// `obs-release publish <release-dir> [tag]`
pub fn run(release_dir: &str, tag: &str) -> ExitCode {
    banner_publish();
    let tag = if tag.is_empty() { DEFAULT_TAG } else { tag };

    // ── Preflight ─────────────────────────────────────────────────────────
    let gh = std::env::var_os("GH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("gh"));
    if Command::new(&gh)
        .arg("--version")
        .stdout(Stdio::null())
        .status()
        .is_err()
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

    // ── Manifest covers the payload ───────────────────────────────────────
    // sha256sum -c only checks files the manifest lists. An asset present in
    // the directory but absent from SHA256SUMS would upload unverified, and an
    // entry with no file would pass by being skipped.
    if let Err(message) = manifest_covers_payload(&dir, &sums) {
        err(&message);
        return ExitCode::FAILURE;
    }
    ok("manifest covers every asset");

    // ── No build-machine paths in the payload ─────────────────────────────
    // A release binary must not carry the builder's home directory. It leaks
    // whoever built it and embeds paths that mean nothing on the machine
    // running the binary. Build with --remap-path-prefix; this refuses the
    // upload when that was forgotten.
    if let Err(message) = payload_has_no_builder_paths(&dir) {
        err(&message);
        err(
            "rebuild with RUSTFLAGS=\"--remap-path-prefix=$PWD=/openbox-sandbox \
--remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup\"",
        );
        return ExitCode::FAILURE;
    }
    ok("no build-machine paths in the payload");

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
    // Collect the payload first so the notes can describe exactly what ships.
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) => {
            err(&format!("cannot read release dir: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let mut files = Vec::new();
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
                names.push(name.to_owned());
            }
            files.push(path);
        }
    }
    let count = files.len();
    let notes = notes_markdown(tag, &names);
    let mut create = gh_command(&gh, &token);
    create.args([
        "release", "create", &staging, "--repo", REPO, "--draft", "--title", &title, "--notes",
        &notes,
    ]);
    for path in &files {
        create.arg(path);
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
            discard_staging(&gh, &token, &staging);
            return ExitCode::FAILURE;
        }
        Err(e) => {
            err(&format!(
                "gh release create failed: {e}; the current '{tag}' release is untouched"
            ));
            discard_staging(&gh, &token, &staging);
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

/// Release notes describing what this release actually contains.
///
/// The asset list is taken from the directory being published rather than
/// written by hand, because a hand-written list drifts: the previous text
/// promised a linux aarch64 platform and an OpenShell bundle tarball, neither
/// of which any release has ever carried.
/// Remove a staging release left behind by a failed upload.
///
/// `gh release create` can fail after the release exists, which stranded a
/// draft holding a full copy of the payload. Publishing is meant to leave
/// either the new release or the old one, never a third.
fn discard_staging(gh: &Path, token: &str, staging: &str) {
    let removed = gh_command(gh, token)
        .args(["release", "delete", staging, "--repo", REPO, "--yes"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    if matches!(removed, Ok(status) if status.success()) {
        info(&format!("discarded the staging release '{staging}'"));
    } else {
        err(&format!(
            "could not discard the staging release '{staging}'; delete it by hand"
        ));
    }
}

/// Reject any asset that embeds a build machine's home directory.
///
/// Scans raw bytes for `/Users/<name>/` and `/home/<name>/`, which is what a
/// Rust binary compiled without --remap-path-prefix carries in panic locations
/// and dependency paths.
fn payload_has_no_builder_paths(dir: &Path) -> Result<(), String> {
    let needles: [&[u8]; 2] = [b"/Users/", b"/home/"];
    for entry in std::fs::read_dir(dir)
        .map_err(|error| format!("cannot read {}: {error}", dir.display()))?
        .flatten()
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or_default()
            .to_owned();
        // Image and cache tarballs legitimately contain guest filesystem paths.
        if name.ends_with(".tar.gz") || name == "SHA256SUMS" {
            continue;
        }
        let body = std::fs::read(&path)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        for needle in needles {
            if let Some(at) = body
                .windows(needle.len())
                .position(|window| window == needle)
            {
                let end = (at + 96).min(body.len());
                let sample = String::from_utf8_lossy(&body[at..end]);
                let sample = sample.split('\0').next().unwrap_or_default();
                return Err(format!("{name} embeds a build machine path: {sample}"));
            }
        }
    }
    Ok(())
}

/// Fail when SHA256SUMS and the release directory disagree.
///
/// Every file that ships must have an entry, and every entry must have a file.
/// SHA256SUMS itself is excluded: a manifest cannot list its own digest.
fn manifest_covers_payload(dir: &Path, sums: &Path) -> Result<(), String> {
    let body = std::fs::read_to_string(sums)
        .map_err(|error| format!("cannot read {}: {error}", sums.display()))?;
    let listed: std::collections::BTreeSet<String> = body
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .map(str::to_owned)
        .collect();
    let mut present = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(dir)
        .map_err(|error| format!("cannot read {}: {error}", dir.display()))?
        .flatten()
    {
        let path = entry.path();
        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
                if name != "SHA256SUMS" {
                    present.insert(name.to_owned());
                }
            }
        }
    }
    let unlisted: Vec<&String> = present.difference(&listed).collect();
    let missing: Vec<&String> = listed.difference(&present).collect();
    if !unlisted.is_empty() {
        return Err(format!(
            "assets present but absent from SHA256SUMS: {unlisted:?}"
        ));
    }
    if !missing.is_empty() {
        return Err(format!(
            "SHA256SUMS lists files that are not in the release: {missing:?}"
        ));
    }
    Ok(())
}

fn notes_markdown(tag: &str, assets: &[String]) -> String {
    let mut listed: Vec<&String> = assets.iter().collect();
    listed.sort();
    let asset_lines = listed
        .iter()
        .map(|name| format!("- `{name}`"))
        .collect::<Vec<_>>()
        .join("\n");
    let platforms = {
        let mac = assets.iter().any(|name| name.contains("darwin-arm64"));
        let linux = assets.iter().any(|name| name.contains("linux-x86_64"));
        match (mac, linux) {
            (true, true) => "macOS arm64, Linux x86_64",
            (true, false) => "macOS arm64",
            (false, true) => "Linux x86_64",
            (false, false) => "none detected",
        }
    };
    format!(
        "## OpenBox Sandbox {version}

Runs one authorized command inside an isolated sandbox, behind a loopback-only
TLS 1.3 mTLS service.

Platforms: {platforms}

Pinned components:
- `openbox-sandbox` service and `obs` launcher: built from this tag
- OpenShell: locked release **0.0.88**, sha256-verified

Assets:
{asset_lines}

Verify before use:
```
sha256sum -c SHA256SUMS
```

Use:
```
chmod +x obs
./obs provision --yes            # service runs here; Ctrl-C drains and stops it
./obs provision --yes --detach   # background, own process group
./obs provision --yes --systemd  # Linux: supervised, restarts on failure
```

Provisioning writes `~/.config/openbox-sandbox/agent.env`, which is the whole
boundary contract an SDK client needs.",
        version = tag.trim_start_matches('v')
    )
}

fn banner_publish() {
    crate::banner();
    crate::info("publish release dir -> GitHub Releases (atomic replace)");
}
