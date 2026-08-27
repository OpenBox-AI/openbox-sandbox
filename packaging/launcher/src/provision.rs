//! Local lifecycle — `obs provision`, `obs uninstall`, `obs verify`,
//! `obs status`.
//!
//! Both the OpenShell and native providers are implemented in-crate.
//! Verification uses the in-crate
//! `live_service_create_exec_delete` integration test:
//!
//! - `obs provision` = teardown, then provision.
//! - `obs uninstall` = teardown, delete launcher-owned state, and exit.
//! - `obs verify` = prove create→ready→exec→delete over mTLS through the root
//!   service and the external `OpenShell` microVM runtime.
//! - `obs status` = report ports, PID files, and generated artifacts.
//!
//! `obs provision` always tears down stale processes first. A clean-state run
//! is explicit with `obs provision --clean-rerun`.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use crate::{err, info, ok, step, warn};

fn selected_provider() -> String {
    if let Ok(provider) = std::env::var("OPENBOX_PROVIDER") {
        return provider;
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let config_root = std::env::var_os("OPENBOX_CONFIG_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config/openbox-sandbox"));
    if let Ok(body) = std::fs::read_to_string(config_root.join("service.json")) {
        if body.contains("\"provider\": \"openshell\"") || !body.contains("\"provider\"") {
            return "openshell".to_owned();
        }
    }
    "native".to_owned()
}

/// Auto-acquire the pinned OpenShell bundle when it is missing, so a fresh
/// machine needs only `obs provision`. Uses the in-crate pinned fetcher.
fn curl_download(
    repo: &str,
    cwd: &Path,
    tag: &str,
    asset: &str,
    destination: &Path,
) -> Result<(), String> {
    let url = format!("https://github.com/{repo}/releases/download/{tag}/{asset}");
    let status = Command::new("curl")
        .current_dir(cwd)
        // -sS: no progress meter in structured output, but errors still shown.
        .args(["-fsSL", "--retry", "3", "-o"])
        .arg(destination)
        .arg(&url)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|error| format!("could not run curl for {url}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("curl exited {status} while downloading {url}"))
    }
}

/// A file's size, rendered for a progress line.
///
/// Downloads are silent now, so the size is reported once the file is on disk
/// rather than through a progress meter that broke up the structured output.
fn human_size(path: &Path) -> String {
    let Ok(metadata) = std::fs::metadata(path) else {
        return "unknown size".to_owned();
    };
    let bytes = metadata.len();
    if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} kB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

/// SHA-256 of a file, using whichever tool the host provides.
fn file_digest(path: &Path) -> Option<String> {
    for (program, args) in [("sha256sum", vec![]), ("shasum", vec!["-a", "256"])] {
        let output = Command::new(program)
            .args(&args)
            .arg(path)
            .stdin(Stdio::null())
            .output();
        if let Ok(output) = output {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout);
                if let Some(digest) = text.split_whitespace().next() {
                    return Some(digest.to_owned());
                }
            }
        }
    }
    None
}

/// The digest a release manifest records for one asset.
///
/// The manifest is fetched from the same tag as the asset, so this proves the
/// download is intact and belongs to that release. It is not proof of
/// authorship: an attacker who can replace the asset can replace the manifest.
fn manifest_digest(cwd: &Path, tag: &str, asset: &str) -> Option<String> {
    // Kept in a per-process temporary path, never in the operator's directory:
    // a cached manifest survives a re-cut release and would then reject a
    // genuine asset. Reused within one run so a provision fetches it once.
    let sums = std::env::temp_dir().join(format!("obs-SHA256SUMS-{}-{tag}", std::process::id()));
    if !sums.is_file()
        && curl_download("OpenBox-AI/openbox-sandbox", cwd, tag, "SHA256SUMS", &sums).is_err()
    {
        return None;
    }
    let body = std::fs::read_to_string(&sums).ok()?;
    digest_from_manifest(&body, asset)
}

/// The digest a manifest body records for one asset name.
///
/// Split out from the fetch so it can be tested without touching the network.
fn digest_from_manifest(body: &str, asset: &str) -> Option<String> {
    body.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let name = fields.next()?.trim_start_matches('*');
        (name == asset).then(|| digest.to_owned())
    })
}

/// Download a release asset and verify it against that release's manifest.
///
/// The OpenShell path has always verified what it fetches. The native path did
/// not: it downloaded the service binary and policy templates over HTTPS and
/// ran them unchecked. A mismatch removes the file rather than leaving a
/// corrupt or foreign artefact on disk for provisioning to use.
/// Ensure an asset is present and matches the release manifest.
///
/// Verifying only fresh downloads left the larger hole: a file already sitting
/// in the working directory was used as-is, so a corrupt, stale, or planted
/// artefact was trusted. A local file that does not match is removed and
/// re-fetched, which is what the OpenShell path has always done.
///
/// An operator who names a binary explicitly through OPENBOX_SANDBOX_BIN is
/// not second-guessed: that is the documented escape hatch for a local build.
fn ensure_verified_asset(cwd: &Path, tag: &str, asset: &str, label: &str) -> bool {
    let destination = cwd.join(asset);
    if destination.is_file() {
        match (manifest_digest(cwd, tag, asset), file_digest(&destination)) {
            (Some(expected), Some(actual)) if expected == actual => return true,
            (Some(expected), Some(actual)) => {
                warn(&format!(
                    "{asset}: local copy does not match {tag}\n  expected {expected}\n  found    {actual}"
                ));
                let _ = std::fs::remove_file(&destination);
            }
            _ => return true,
        }
    }
    info(&format!("{label} missing — fetching {asset} from {tag}"));
    download_openbox_asset(cwd, tag, asset, &destination)
}

fn download_openbox_asset(cwd: &Path, tag: &str, asset: &str, destination: &Path) -> bool {
    if let Err(error) = curl_download("OpenBox-AI/openbox-sandbox", cwd, tag, asset, destination) {
        warn(&error);
        return false;
    }
    let Some(expected) = manifest_digest(cwd, tag, asset) else {
        warn(&format!(
            "{asset}: no SHA256SUMS entry from {tag}; cannot verify the download"
        ));
        let _ = std::fs::remove_file(destination);
        return false;
    };
    match file_digest(destination) {
        Some(actual) if actual == expected => {
            ok(&format!(
                "{asset} verified against {tag} SHA256SUMS ({})",
                human_size(destination)
            ));
            true
        }
        Some(actual) => {
            warn(&format!(
                "{asset}: sha256 mismatch against {tag}\n  expected {expected}\n  found    {actual}"
            ));
            let _ = std::fs::remove_file(destination);
            false
        }
        None => {
            warn(&format!("{asset}: no sha256 tool available to verify it"));
            let _ = std::fs::remove_file(destination);
            false
        }
    }
}

fn fetch_pinned_zot(cwd: &Path, pin: crate::pin::ZotPin) -> Result<(), String> {
    let downloaded = cwd.join(pin.asset);
    curl_download(
        "project-zot/zot",
        cwd,
        crate::pin::ZOT_VERSION,
        pin.asset,
        &downloaded,
    )?;

    let local = cwd.join(pin.local_name);
    std::fs::rename(&downloaded, &local).map_err(|error| {
        format!(
            "could not rename {} to {}: {error}",
            downloaded.display(),
            local.display()
        )
    })?;
    if let Err(error) = crate::pin::check_sha256(&local, pin.sha256) {
        let _ = std::fs::remove_file(&local);
        return Err(error);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&local)
            .map_err(|error| format!("could not read {} permissions: {error}", local.display()))?
            .permissions();
        permissions.set_mode(permissions.mode() | 0o111);
        std::fs::set_permissions(&local, permissions)
            .map_err(|error| format!("could not chmod +x {}: {error}", local.display()))?;
    }

    ok(&format!(
        "official zot {} verified ({})",
        crate::pin::ZOT_VERSION,
        pin.sha256
    ));
    Ok(())
}

/// Provision must self-heal: anything missing from the detected release line
/// (service binary, policy, dev image tar) is fetched from the matching tag.
fn ensure_release_assets(cwd: &std::path::Path, svc_name: &str) {
    let dev_tar = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "openbox-sandbox-dev-darwin-arm64.tar.gz"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "openbox-sandbox-dev-linux-x86_64.tar.gz"
    } else {
        ""
    };
    let vm_cache = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "prepared-vm-cache-darwin-arm64.tar.gz"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "prepared-vm-cache-linux-x86_64.tar.gz"
    } else {
        ""
    };
    let zot_pin = crate::pin::zot_pin();
    let dev_channel = match std::env::var("OPENBOX_RELEASE_LINE").as_deref() {
        Ok("dev") => true,
        Ok(_) => false,
        Err(_) => crate::channel() != "base",
    };
    let tag = if dev_channel { "v0.1.0-dev" } else { "v0.1.0" };
    info(&format!(
        "release line: {} ({tag}) — OpenBox assets fetch from this tag only ({} template)",
        if dev_channel { "dev" } else { "base" },
        if dev_channel {
            "allow-network"
        } else {
            "deny-network"
        }
    ));
    if std::env::var_os("OPENBOX_SANDBOX_BIN").is_none() {
        let _ = ensure_verified_asset(cwd, tag, svc_name, "native service");
    }
    // TEMPLATES: ALL policy templates are always provided, regardless of the
    // channel — the channel only selects the DEFAULT. Each template is fetched
    // from the release that canonically carries it (allow -> dev tag,
    // deny -> base tag), so no pattern is ever tried against a release that
    // cannot have it.
    let _ = ensure_verified_asset(
        cwd,
        "v0.1.0-dev",
        "policy-allow-network-dev.yaml",
        "allow policy template",
    );
    let _ = ensure_verified_asset(
        cwd,
        "v0.1.0",
        "policy-deny-network-dev.yaml",
        "deny policy template",
    );
    // Channel-locked assets beyond the templates.
    if dev_channel {
        if !dev_tar.is_empty() && !cwd.join(dev_tar).is_file() {
            info(&format!("{dev_tar} missing — fetching from v0.1.0-dev"));
            let _ = download_openbox_asset(cwd, "v0.1.0-dev", dev_tar, &cwd.join(dev_tar));
        }
        if !vm_cache.is_empty() && !cwd.join(vm_cache).is_file() {
            info(&format!("{vm_cache} missing — fetching from v0.1.0-dev"));
            let _ = download_openbox_asset(cwd, "v0.1.0-dev", vm_cache, &cwd.join(vm_cache));
        }
        // Runtime-agnostic registry assets: our OCI layout plus the separately
        // pinned binary from project-zot's official release.
        let oci_layout = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
            "openbox-sandbox-dev-darwin-arm64-oci.tar.gz"
        } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
            "openbox-sandbox-dev-linux-x86_64-oci.tar.gz"
        } else {
            ""
        };
        if !oci_layout.is_empty() && !cwd.join(oci_layout).is_file() {
            info(&format!("{oci_layout} missing — fetching from v0.1.0-dev"));
            let _ = download_openbox_asset(cwd, "v0.1.0-dev", oci_layout, &cwd.join(oci_layout));
        }
        if let Some(pin) = zot_pin.filter(|pin| !cwd.join(pin.local_name).is_file()) {
            info(&format!(
                "{} (local image registry) missing — fetching {} from official project-zot/zot {}",
                pin.local_name,
                pin.asset,
                crate::pin::ZOT_VERSION
            ));
            if let Err(error) = fetch_pinned_zot(cwd, pin) {
                warn(&format!("could not fetch pinned official zot: {error}"));
            }
        }
    } else if !vm_cache.is_empty() && !cwd.join(vm_cache).is_file() {
        info(&format!("{vm_cache} missing — fetching from v0.1.0"));
        let _ = download_openbox_asset(cwd, "v0.1.0", vm_cache, &cwd.join(vm_cache));
    }
}

fn auto_fetch_bundle() -> Result<(), ExitCode> {
    // Always compute the bundle dir from the CWD — never inherit from
    // the parent environment (a leaked OPENSHELL_BUNDLE_DIR from a
    // previous provision or operator setup would route the fetch to a
    // wrong directory).
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let bundle_dir = {
        let base = cwd.join("openbox-sandbox-bundle");
        let darwin_arm = base.join("darwin-arm64");
        if cfg!(target_os = "macos")
            && cfg!(target_arch = "aarch64")
            && darwin_arm.join("bin/openshell-gateway").is_file()
        {
            darwin_arm
        } else {
            base
        }
    };
    let svc_name = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "openbox-sandbox-darwin-arm64"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "openbox-sandbox-linux-x86_64"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        "openbox-sandbox-linux-aarch64"
    } else {
        "openbox-sandbox"
    };
    // The default policy comes from the release line alone: the operator's
    // --dev/--base choice, else the channel baked into this launcher. Files
    // that happen to sit in the working directory never change the default.
    let policy_name = if release_line_is_dev() {
        "policy-allow-network-dev.yaml"
    } else {
        "policy-deny-network-dev.yaml"
    };
    // Already present — pin it and let the launcher proceed.
    // The service binary and policy are SEPARATE release assets that land
    // either inside the bundle dir (fetched) or in the CWD next to obs
    // (downloaded release layout). Check both before fetching anything.
    let bundle_bin = bundle_dir.join("bin");
    let openshell_ready = bundle_bin.join("openshell-gateway").is_file()
        && bundle_bin.join("openshell").is_file()
        && bundle_dir.join("libexec/openshell-driver-vm").is_file();
    let svc_bin = if bundle_dir.join(svc_name).is_file() {
        bundle_dir.join(svc_name)
    } else if cwd.join(svc_name).is_file() {
        cwd.join(svc_name)
    } else {
        bundle_dir.join(svc_name)
    };
    let policy_file = if cwd.join(policy_name).is_file() {
        cwd.join(policy_name)
    } else {
        bundle_dir.join(policy_name)
    };
    let ready = openshell_ready && svc_bin.is_file() && policy_file.is_file();
    if ready {
        unsafe {
            std::env::set_var("OPENSHELL_BUNDLE_DIR", &bundle_dir);
            std::env::set_var("OPENBOX_SANDBOX_BIN", &svc_bin);
            std::env::set_var("OPENBOX_POLICY_FILE", &policy_file);
        }
        return Ok(());
    }
    info("OpenShell binaries missing — fetching the pinned release");
    // The locked release is the only version this launcher fetches. An env
    // override here would defeat the pin that the rest of the code enforces.
    if let Err(reason) =
        crate::openshell_fetch::fetch(&bundle_dir, crate::pin::LOCKED_RELEASE_VERSION)
    {
        err(&format!("OpenShell fetch failed: {reason}"));
        return Err(ExitCode::FAILURE);
    }
    // The sandbox service binary must also be available to the launcher. In a
    // standalone release it ships as a per-arch release asset alongside the
    // split bundle dirs; fetch it into the bundle dir when missing.
    let svc_bin = if cwd.join(svc_name).is_file() {
        cwd.join(svc_name)
    } else {
        bundle_dir.join(svc_name)
    };
    if !svc_bin.is_file() {
        info(&format!("sandbox service missing — fetching {svc_name}"));
        let fetch_tag = if release_line_is_dev() {
            "v0.1.0-dev"
        } else {
            "v0.1.0"
        };
        if !download_openbox_asset(&cwd, fetch_tag, svc_name, &svc_bin) {
            err(&format!(
                "failed to fetch the sandbox service binary {svc_name}"
            ));
            return Err(ExitCode::FAILURE);
        }
        // GitHub release assets do not preserve the executable bit; the
        // launcher's `-x` check will fail without it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&svc_bin) {
                let mut perms = meta.permissions();
                let mode = perms.mode() | 0o111;
                perms.set_mode(mode);
                if let Err(e) = std::fs::set_permissions(&svc_bin, perms) {
                    err(&format!("cannot chmod service binary: {e}"));
                    return Err(ExitCode::FAILURE);
                }
            }
        }
    }
    if !svc_bin.is_file() {
        // Build from the source tree when the download is unavailable.
        if cwd.join("Cargo.toml").is_file() {
            info("building sandbox service from the source tree");
            let cargo = which_cargo().unwrap_or_else(|| PathBuf::from("cargo"));
            let build = Command::new(&cargo)
                .args(["build", "--release", "--locked", "--bin", "openbox-sandbox"])
                .current_dir(&cwd)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status();
            if !matches!(build, Ok(s) if s.success()) {
                err("source-tree build failed (see output above)");
                return Err(ExitCode::FAILURE);
            }
            let built = cwd.join("target").join("release").join("openbox-sandbox");
            if let Err(e) = std::fs::copy(&built, &svc_bin) {
                err(&format!("cannot copy built service binary: {e}"));
                return Err(ExitCode::FAILURE);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&svc_bin) {
                    let mut perms = meta.permissions();
                    perms.set_mode(meta.permissions().mode() | 0o111);
                    let _ = std::fs::set_permissions(&svc_bin, perms);
                }
            }
        }
    }
    if !svc_bin.is_file() {
        err(&format!(
            "sandbox service binary not found at {} (set OPENBOX_SANDBOX_BIN)",
            svc_bin.display()
        ));
        return Err(ExitCode::FAILURE);
    }
    // The sandbox policy file must also be available to the launcher.
    // Fetch it from the same release alongside the service binary.
    let policy_path = bundle_dir.join(policy_name);
    if !policy_path.is_file() {
        info(&format!("policy file missing — fetching {policy_name}"));
        let fetch_tag = if release_line_is_dev() {
            "v0.1.0-dev"
        } else {
            "v0.1.0"
        };
        if !download_openbox_asset(&cwd, fetch_tag, policy_name, &policy_path) {
            err(&format!("failed to fetch the sandbox policy {policy_name}"));
            return Err(ExitCode::FAILURE);
        }
    }
    if !policy_path.is_file() {
        // Try the source tree's policy directory.
        for candidate in &[
            cwd.join("deploy").join("policies").join(policy_name),
            cwd.join(policy_name),
        ] {
            if candidate.is_file() {
                if let Err(e) = std::fs::copy(candidate, &policy_path) {
                    err(&format!("cannot copy policy file: {e}"));
                    return Err(ExitCode::FAILURE);
                }
                break;
            }
        }
    }
    // The launcher must consume exactly this bundle + service binary + policy.
    unsafe { std::env::set_var("OPENSHELL_BUNDLE_DIR", &bundle_dir) };
    unsafe { std::env::set_var("OPENBOX_SANDBOX_BIN", &svc_bin) };
    unsafe { std::env::set_var("OPENBOX_POLICY_FILE", &policy_path) };
    Ok(())
}

/// Locate Cargo for the source-checkout fallback.
fn which_cargo() -> Option<PathBuf> {
    // Honour the CARGO env var when set (e.g. cargo run, rustup overrides).
    if let Some(cargo) = std::env::var_os("CARGO") {
        let p = PathBuf::from(cargo);
        if p.is_file() {
            return Some(p);
        }
    }
    for dir in std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .unwrap_or_default()
    {
        let candidate = dir.join("cargo");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// The release line in effect: the operator's choice, else the baked channel.
fn release_line_is_dev() -> bool {
    std::env::var("OPENBOX_RELEASE_LINE")
        .map_or_else(|_| crate::channel() != "base", |line| line == "dev")
}

/// The root of the source checkout containing `directory`, if there is one.
///
/// Identified by the workspace manifest plus the launcher crate beside it, so
/// a nested crate directory is not mistaken for the checkout root.
fn source_checkout_root(directory: &Path) -> Option<PathBuf> {
    let mut candidate = Some(directory);
    while let Some(current) = candidate {
        if current.join("Cargo.toml").is_file()
            && current.join("packaging/launcher/Cargo.toml").is_file()
        {
            return Some(current.to_path_buf());
        }
        candidate = current.parent();
    }
    None
}

fn auto_fetch_native_assets() -> Result<(), ExitCode> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let svc_name = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "openbox-sandbox-darwin-arm64"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "openbox-sandbox-linux-x86_64"
    } else {
        "openbox-sandbox"
    };
    let explicit = std::env::var_os("OPENBOX_SANDBOX_BIN").map(PathBuf::from);
    let mut service = explicit.clone();
    let candidate = cwd.join(svc_name);
    // --dev and --base set OPENBOX_RELEASE_LINE, and it must select the
    // service binary as well as the policy. Honouring it for only one of them
    // mixed a base service with a dev policy, which is exactly the split the
    // release notes warn against.
    let tag = if release_line_is_dev() {
        "v0.1.0-dev"
    } else {
        "v0.1.0"
    };
    // Exactly one rule decides the service binary, with no silent alternative.
    //
    // A source checkout builds the binary it is going to run: there is no
    // manifest for a build that does not exist yet. Everywhere else the release
    // asset is used and must match SHA256SUMS, including a path named through
    // --sandbox-bin. A failed verification is fatal; it previously fell through
    // to building from source, so a rejected binary silently became a different
    // binary.
    // The checkout root, not merely a directory that happens to hold a
    // Cargo.toml: packaging/launcher has one too, and building there looks for
    // a binary that crate does not define.
    if let Some(root) = source_checkout_root(&cwd) {
        info("source checkout: building the native service from source");
        let status = Command::new(which_cargo().unwrap_or_else(|| PathBuf::from("cargo")))
            .current_dir(&root)
            .args(["build", "--release", "--locked", "--bin", "openbox-sandbox"])
            .status();
        if !matches!(status, Ok(value) if value.success()) {
            err("could not build the native service from this source checkout");
            return Err(ExitCode::FAILURE);
        }
        service = Some(root.join("target/release/openbox-sandbox"));
    } else {
        let named = service.clone().filter(|path| path.is_file());
        if let Some(path) = named {
            // A named binary is verified like any other release asset, by the
            // digest the manifest records for this platform's asset name.
            match (manifest_digest(&cwd, tag, svc_name), file_digest(&path)) {
                (Some(expected), Some(actual)) if expected == actual => {
                    ok(&format!(
                        "{} verified against {tag} SHA256SUMS",
                        path.display()
                    ));
                }
                (Some(expected), Some(actual)) => {
                    err(&format!(
                        "{}: does not match {tag}\n  expected {expected}\n  found    {actual}",
                        path.display()
                    ));
                    return Err(ExitCode::FAILURE);
                }
                _ => {
                    err(&format!(
                        "{}: cannot be verified against {tag}",
                        path.display()
                    ));
                    return Err(ExitCode::FAILURE);
                }
            }
        } else if ensure_verified_asset(&cwd, tag, svc_name, "native service")
            && candidate.is_file()
        {
            service = Some(candidate.clone());
        } else {
            err("native service binary could not be verified against the release");
            return Err(ExitCode::FAILURE);
        }
    }
    let service = service.filter(|path| path.is_file()).ok_or_else(|| {
        err("native service binary is unavailable; no fallback to OpenShell");
        ExitCode::FAILURE
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if let Ok(metadata) = std::fs::metadata(&service) {
            let mut permissions = metadata.permissions();
            permissions.set_mode(permissions.mode() | 0o111);
            let _ = std::fs::set_permissions(&service, permissions);
        }
    }

    // Resolve the same channel-selected template used by the OpenShell path.
    // An explicit operator policy still wins; otherwise dev is allow-list and
    // base is deny-network, regardless of which other template is present.
    let dev_channel = release_line_is_dev();
    let policy_name = if dev_channel {
        "policy-allow-network-dev.yaml"
    } else {
        "policy-deny-network-dev.yaml"
    };
    let tag = if dev_channel { "v0.1.0-dev" } else { "v0.1.0" };
    let mut policy = std::env::var_os("OPENBOX_POLICY_FILE").map(PathBuf::from);
    for candidate in [
        cwd.join(policy_name),
        cwd.join("deploy/policies").join(policy_name),
    ] {
        if policy.as_ref().is_none_or(|path| !path.is_file()) && candidate.is_file() {
            policy = Some(candidate);
        }
    }
    // Every provision fetches BOTH policy templates regardless of line, so
    // switching lines later never needs a re-download. The channel only
    // selects which one is the default.
    for (template, from_tag) in [
        ("policy-allow-network-dev.yaml", "v0.1.0-dev"),
        ("policy-deny-network-dev.yaml", "v0.1.0"),
    ] {
        let dest = cwd.join(template);
        if !dest.is_file() {
            let _ = download_openbox_asset(&cwd, from_tag, template, &dest);
        }
    }
    if policy.as_ref().is_none_or(|path| !path.is_file()) {
        info(&format!(
            "native policy missing — fetching {policy_name} from {tag}"
        ));
        let downloaded = cwd.join(policy_name);
        let _ = download_openbox_asset(&cwd, tag, policy_name, &downloaded);
        if downloaded.is_file() {
            policy = Some(downloaded);
        }
    }
    let policy = policy.filter(|path| path.is_file()).ok_or_else(|| {
        err(&format!(
            "native channel policy {policy_name} is unavailable; refusing an unpinned default"
        ));
        ExitCode::FAILURE
    })?;
    unsafe {
        std::env::set_var("OPENBOX_SANDBOX_BIN", service);
        std::env::set_var("OPENBOX_POLICY_FILE", policy);
    }
    Ok(())
}

/// `obs provision` — teardown and provision, optionally cleaning state first.
pub fn run_provision(
    clean_rerun: bool,
    keep_pki: bool,
    overrides: Vec<(String, String)>,
) -> ExitCode {
    // Apply flag overrides to this process too — channel detection and the
    // asset fetches must see the same values the provision script will.
    for (key, value) in &overrides {
        std::env::set_var(key, value);
    }
    // The channel is the BINARY's channel — always pass it down so the
    // script never guesses.
    if std::env::var("OPENBOX_RELEASE_LINE").is_err() {
        std::env::set_var("OPENBOX_RELEASE_LINE", crate::channel());
    }
    if std::env::var("OPENBOX_PROVIDER").is_err() {
        std::env::set_var("OPENBOX_PROVIDER", "native");
    }
    let provider = selected_provider();
    if !matches!(provider.as_str(), "native" | "openshell") {
        err("OPENBOX_PROVIDER must be native or openshell");
        return ExitCode::FAILURE;
    }
    // Asset resolution ran before any phase banner, so the first thing an
    // operator saw was unlabelled download chatter. Both providers now open
    // with the same phase.
    banner_phase("ASSETS");
    info(&format!(
        "provider={provider}; every asset is verified against the release manifest"
    ));
    let fetched = if provider == "native" {
        auto_fetch_native_assets()
    } else {
        auto_fetch_bundle()
    };
    if let Err(code) = fetched {
        return code;
    }
    let svc_name = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "openbox-sandbox-darwin-arm64"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "x86_64") {
        "openbox-sandbox-linux-x86_64"
    } else {
        "openbox-sandbox"
    };
    if provider == "openshell" {
        ensure_release_assets(
            &std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")),
            svc_name,
        );
    }
    banner_phase("PROVISION");
    if provider == "native" {
        info("provider=native -> native profile -> local mTLS service -> smoke -> agent.env");
        return run_native(crate::native_provision::Options {
            uninstall: false,
            clean_rerun,
            _keep_pki: keep_pki,
        });
    }

    info("provider=openshell -> gateway -> mTLS -> service -> agent.env");
    run_openshell(crate::openshell_provision::Options {
        uninstall: false,
        clean_rerun,
        keep_pki,
    })
}

/// `obs uninstall` — stop everything the launcher started and wipe its state.
pub fn run_uninstall(keep_pki: bool) -> ExitCode {
    banner_phase("UNINSTALL");
    info("teardown -> delete state root / config root / gateway metadata / PKI");
    if selected_provider() == "native" {
        return run_native(crate::native_provision::Options {
            uninstall: true,
            clean_rerun: false,
            _keep_pki: keep_pki,
        });
    }

    run_openshell(crate::openshell_provision::Options {
        uninstall: true,
        clean_rerun: false,
        keep_pki,
    })
}

fn run_native(options: crate::native_provision::Options) -> ExitCode {
    match crate::native_provision::run(options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            err(&format!("provision: {error}"));
            ExitCode::FAILURE
        }
    }
}

fn run_openshell(options: crate::openshell_provision::Options) -> ExitCode {
    match crate::openshell_provision::run(options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            err(&format!("provision: {error}"));
            ExitCode::FAILURE
        }
    }
}

/// `obs status` — quick run-state report.
pub fn run_status() -> ExitCode {
    banner_phase("STATUS");
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    let state_root = std::env::var_os("OPENBOX_STATE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".local/state/openbox-sandbox"));
    let config_root = std::env::var_os("OPENBOX_CONFIG_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config/openbox-sandbox"));
    let gateway_pid_file = state_root.join("gateway/gateway.pid");
    let sandbox_pid_file = state_root.join("sandbox-service.pid");
    let agent_env = config_root.join("agent.env");
    let service_config = config_root.join("service.json");
    let gateway_log = state_root.join("gateway/gateway.log");
    let sandbox_log = state_root.join("sandbox-service.log");
    let provider = std::fs::read_to_string(&service_config)
        .ok()
        .filter(|body| body.contains("\"provider\": \"native\""))
        .map_or("openshell", |_| "native");

    // The launcher records the actual ports (OPENSHELL_SERVER_PORT and
    // OPENBOX_SANDBOX_PORT overrides are honored); read them back instead of
    // assuming the defaults.
    let gateway_port = read_gateway_port(&home).unwrap_or(17670);
    let sandbox_port = read_sandbox_port(&service_config).unwrap_or(17443);

    info(&format!("provider: {provider}"));
    if provider == "openshell" {
        port_phase(gateway_port, "gateway");
        pid_phase(&gateway_pid_file, "gateway");
    }
    port_phase(sandbox_port, "sandbox service");
    pid_phase(&sandbox_pid_file, "sandbox service");
    artifact_phase(&agent_env, "agent.env");
    artifact_phase(&service_config, "service.json");
    info(&format!("config root: {}", config_root.display()));
    info(&format!("state root:  {}", state_root.display()));
    info(&format!("gateway log: {}", gateway_log.display()));
    info(&format!("sandbox log: {}", sandbox_log.display()));
    let all_up = port_open(sandbox_port) && (provider == "native" || port_open(gateway_port));
    if all_up {
        ok("stack ready — run `obs verify` to exercise the lifecycle");
    } else {
        warn("stack not fully up — run `obs provision`");
    }
    ExitCode::SUCCESS
}

/// Read the gateway port from the launcher-written metadata (active gateway).
/// Dependency-free: the launcher has no JSON crate, and the metadata format
/// is launcher-owned (`"gateway_port": <n>`), so a bounded string scan suffices.
fn read_gateway_port(home: &Path) -> Option<u16> {
    let name = std::fs::read_to_string(home.join(".config/openshell/active_gateway"))
        .ok()?
        .trim()
        .to_string();
    let meta = home
        .join(".config/openshell/gateways")
        .join(if name.is_empty() { "openshell" } else { &name })
        .join("metadata.json");
    let body = std::fs::read_to_string(meta).ok()?;
    let key = "\"gateway_port\"";
    let start = body.find(key)? + key.len();
    let rest = &body[start..];
    let digits: String = rest
        .chars()
        .skip_while(|c| !c.is_ascii_digit())
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u16>().ok()
}

/// Read the sandbox service port from the generated service.json
/// (`"bind_address": "127.0.0.1:<port>"`).
fn read_sandbox_port(service_config: &Path) -> Option<u16> {
    let body = std::fs::read_to_string(service_config).ok()?;
    let key = "\"bind_address\"";
    let start = body.find(key)? + key.len();
    let rest = &body[start..];
    let quoted = rest.trim_start().strip_prefix(':')?.trim_start();
    let value = quoted.strip_prefix('"')?;
    let end = value.find('"')?;
    value[..end].rsplit_once(':')?.1.parse::<u16>().ok()
}

fn banner_phase(name: &str) {
    step(name);
}

fn port_open(port: u16) -> bool {
    Command::new("lsof")
        .args(["-nP", &format!("-iTCP:{port}"), "-sTCP:LISTEN"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn port_phase(port: u16, label: &str) {
    if port_open(port) {
        ok(&format!("{label}: listening on {port}"));
    } else {
        warn(&format!("{label}: not listening on {port}"));
    }
}

fn pid_phase(pid_file: &Path, label: &str) {
    match std::fs::read_to_string(pid_file)
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
    {
        Some(pid) => {
            let alive = libc_kill_alive(pid);
            if alive {
                ok(&format!("{label}: pid={pid} alive"));
            } else {
                warn(&format!("{label}: stale pid file (pid={pid} not alive)"));
            }
        }
        None => warn(&format!("{label}: no pid file at {}", pid_file.display())),
    }
}

fn artifact_phase(path: &Path, label: &str) {
    if path.is_file() {
        ok(&format!("{label}: {}", path.display()));
    } else {
        warn(&format!("{label}: missing -> {}", path.display()));
    }
}
#[cfg(test)]

fn verify_service_binary(values: &[(&str, &str)]) -> Result<(), String> {
    let binary = env_value(values, "OPENBOX_SANDBOX_BINARY")
        .ok_or_else(|| "OPENBOX_SANDBOX_BINARY is missing".to_owned())?;
    let expected = env_value(values, "OPENBOX_SANDBOX_ADAPTER_SHA")
        .ok_or_else(|| "OPENBOX_SANDBOX_ADAPTER_SHA is missing".to_owned())?;
    let actual = file_sha256(Path::new(binary))?;
    if actual.eq_ignore_ascii_case(expected) {
        info(&format!("service binary identity verified: {binary}"));
        Ok(())
    } else {
        Err(format!(
            "service binary hash mismatch for {binary}: expected {expected}, found {actual}"
        ))
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn env_value<'a>(values: &'a [(&str, &str)], key: &str) -> Option<&'a str> {
    values
        .iter()
        .find_map(|(candidate, value)| (*candidate == key).then_some(*value))
}

#[cfg_attr(not(test), allow(dead_code))]
fn file_sha256(path: &Path) -> Result<String, String> {
    let (program, prefix): (&str, &[&str]) = if cfg!(target_os = "macos") {
        ("shasum", &["-a", "256"])
    } else {
        ("sha256sum", &[])
    };
    let output = Command::new(program)
        .args(prefix)
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("cannot hash service binary {}: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "cannot hash service binary {}: {program} exited {}",
            path.display(),
            output.status
        ));
    }
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .filter(|digest| !digest.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| format!("cannot parse service binary hash for {}", path.display()))
}

#[cfg_attr(not(test), allow(dead_code))]
fn parse_agent_env(body: &str) -> Result<Vec<(&str, &str)>, String> {
    let mut values = Vec::new();
    let mut has_endpoint = false;
    for (line_number, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {} is not KEY=VALUE", line_number + 1))?;
        if key.is_empty() || value.is_empty() {
            return Err(format!(
                "line {} has an empty key or value",
                line_number + 1
            ));
        }
        if values.iter().any(|(existing, _)| *existing == key) {
            return Err(format!("line {} duplicates {key}", line_number + 1));
        }
        has_endpoint |= key == "OPENBOX_SANDBOX_ENDPOINT";
        values.push((key, value));
    }
    if !has_endpoint {
        return Err(
            "OPENBOX_SANDBOX_ENDPOINT is missing; refusing a skippable live test".to_owned(),
        );
    }
    Ok(values)
}

/// Best-effort `kill(pid, 0)` liveness check via `kill -0` (no libc FFI).
fn libc_kill_alive(pid: i32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{parse_agent_env, verify_service_binary};

    #[test]
    fn manifest_lookup_matches_only_the_named_asset() {
        let body = "aaaa  openbox-sandbox-darwin-arm64\n\
                    bbbb  policy-allow-network-dev.yaml\n\
                    cccc *starred-entry\n";
        assert_eq!(
            super::digest_from_manifest(body, "openbox-sandbox-darwin-arm64"),
            Some("aaaa".to_owned())
        );
        // A name that only prefixes an entry must not match it.
        assert_eq!(super::digest_from_manifest(body, "openbox-sandbox"), None);
        // sha256sum marks binary entries with a leading star.
        assert_eq!(
            super::digest_from_manifest(body, "starred-entry"),
            Some("cccc".to_owned())
        );
        assert_eq!(super::digest_from_manifest(body, "absent"), None);
    }

    #[test]
    fn agent_env_requires_endpoint_so_live_verify_cannot_skip() {
        assert!(parse_agent_env("OPENBOX_SANDBOX_CA=/tmp/ca.crt\n").is_err());
        assert_eq!(
            parse_agent_env("OPENBOX_SANDBOX_ENDPOINT=127.0.0.1:17443\n"),
            Ok(vec![("OPENBOX_SANDBOX_ENDPOINT", "127.0.0.1:17443")])
        );
    }

    #[test]
    fn malformed_agent_env_fails_closed() {
        assert!(parse_agent_env("not-an-assignment\n").is_err());
        assert!(parse_agent_env("OPENBOX_SANDBOX_ENDPOINT=\n").is_err());
        assert!(parse_agent_env(
            "OPENBOX_SANDBOX_ENDPOINT=127.0.0.1:1\n\
                 OPENBOX_SANDBOX_ENDPOINT=127.0.0.1:2\n"
        )
        .is_err());
    }

    #[test]
    fn service_binary_hash_must_match_before_live_verify() {
        let path =
            std::env::temp_dir().join(format!("openbox-adapter-test-{}", std::process::id()));
        std::fs::write(&path, b"adapter").expect("write adapter fixture");
        let path_text = path.to_string_lossy();
        let matching = [
            ("OPENBOX_SANDBOX_BINARY", path_text.as_ref()),
            (
                "OPENBOX_SANDBOX_ADAPTER_SHA",
                "ae1eae1d76e5b7c865c4122ce366a08025842566d2d96c75cc13e6353a73db0d",
            ),
        ];
        assert_eq!(verify_service_binary(&matching), Ok(()));

        let mismatch = [
            ("OPENBOX_SANDBOX_BINARY", path_text.as_ref()),
            (
                "OPENBOX_SANDBOX_ADAPTER_SHA",
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ];
        let error = verify_service_binary(&mismatch).expect_err("mismatch must fail");
        assert!(error.contains(path_text.as_ref()));
        assert!(error.contains("service binary hash mismatch"));
        std::fs::remove_file(path).expect("remove adapter fixture");
    }
}
