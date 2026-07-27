//! Service setup for macOS and Linux.
//!
//! On macOS, generates a launchd plist and loads it.
//! On Linux, generates a systemd unit and enables it.
//! The operator-facing experience is identical — the launcher handles the
//! platform differences internally.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use crate::{err, info, ok, warn};

/// The service name used for both launchd and systemd.
const SERVICE_NAME: &str = "openbox-sandbox";

/// Set up the service. Returns the plist/unit path on success.
pub fn setup(binary_path: &Path, bundle_dir: &Path, no_start: bool) -> Result<PathBuf, ExitCode> {
    if cfg!(target_os = "macos") {
        setup_launchd(binary_path, bundle_dir, no_start)
    } else if cfg!(target_os = "linux") {
        setup_systemd(binary_path, bundle_dir, no_start)
    } else {
        warn("service setup not supported on this platform");
        info("run the launcher directly: osb");
        Err(ExitCode::FAILURE)
    }
}

/// Generate and load a launchd plist on macOS.
fn setup_launchd(
    binary_path: &Path,
    bundle_dir: &Path,
    no_start: bool,
) -> Result<PathBuf, ExitCode> {
    let plist_dir = dirs_plist_dir();
    fs::create_dir_all(&plist_dir).map_err(|e| {
        err(&format!("cannot create plist directory: {e}"));
        ExitCode::FAILURE
    })?;

    let plist_path = plist_dir.join(format!("{SERVICE_NAME}.plist"));
    let log_path = PathBuf::from(format!("/tmp/{SERVICE_NAME}.log"));

    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{SERVICE_NAME}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log}</string>
    <key>StandardErrorPath</key>
    <string>{log}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>OPENBOX_BUNDLE_DIR</key>
        <string>{bundle}</string>
    </dict>
</dict>
</plist>"#,
        binary = binary_path.display(),
        log = log_path.display(),
        bundle = bundle_dir.display(),
    );

    fs::write(&plist_path, &plist).map_err(|e| {
        err(&format!("cannot write plist: {e}"));
        ExitCode::FAILURE
    })?;
    info(&format!("plist: {}", plist_path.display()));

    if !no_start {
        let _ = Command::new("launchctl")
            .args(["unload", plist_path.to_str().unwrap_or("")])
            .status();

        let status = Command::new("launchctl")
            .args(["load", plist_path.to_str().unwrap_or("")])
            .status();
        match status {
            Ok(s) if s.success() => {
                ok("service loaded");
                info(&format!("logs: tail -f {}", log_path.display()));
            }
            Ok(s) => {
                err(&format!(
                    "launchctl load failed (exit {})",
                    s.code().unwrap_or(-1)
                ));
                return Err(ExitCode::FAILURE);
            }
            Err(e) => {
                err(&format!("launchctl load failed: {e}"));
                return Err(ExitCode::FAILURE);
            }
        }
    } else {
        info(&format!(
            "to start: launchctl load {}",
            plist_path.display()
        ));
    }

    Ok(plist_path)
}

/// Generate and enable a systemd unit on Linux.
fn setup_systemd(
    binary_path: &Path,
    bundle_dir: &Path,
    no_start: bool,
) -> Result<PathBuf, ExitCode> {
    let unit_dir = PathBuf::from("/etc/systemd/system");
    let unit_path = unit_dir.join(format!("{SERVICE_NAME}.service"));

    let unit = format!(
        r#"[Unit]
Description=OpenBox Sandbox
After=network.target

[Service]
Type=simple
ExecStart={binary}
Environment=OPENBOX_BUNDLE_DIR={bundle}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
MemoryDenyWriteExecute=true
ReadWritePaths=/var/lib/openbox-sandbox

[Install]
WantedBy=multi-user.target
"#,
        binary = binary_path.display(),
        bundle = bundle_dir.display(),
    );

    let tmp_unit = PathBuf::from(format!("/tmp/{SERVICE_NAME}.service"));
    fs::write(&tmp_unit, &unit).map_err(|e| {
        err(&format!("cannot write unit file: {e}"));
        ExitCode::FAILURE
    })?;

    let status = Command::new("sudo")
        .args([
            "cp",
            tmp_unit.to_str().unwrap_or(""),
            unit_path.to_str().unwrap_or(""),
        ])
        .status();
    match status {
        Ok(s) if s.success() => {
            info(&format!("unit: {}", unit_path.display()));
        }
        Ok(s) => {
            err(&format!("sudo cp failed (exit {})", s.code().unwrap_or(-1)));
            info("ensure your user has passwordless sudo for systemctl operations");
            return Err(ExitCode::FAILURE);
        }
        Err(e) => {
            err(&format!("sudo cp failed: {e}"));
            return Err(ExitCode::FAILURE);
        }
    }

    let _ = Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .status();

    if !no_start {
        let status = Command::new("sudo")
            .args(["systemctl", "enable", "--now", SERVICE_NAME])
            .status();
        match status {
            Ok(s) if s.success() => {
                ok("service enabled and started");
                info(&format!("logs: journalctl -u {SERVICE_NAME} -f"));
            }
            Ok(s) => {
                err(&format!(
                    "systemctl enable failed (exit {})",
                    s.code().unwrap_or(-1)
                ));
                return Err(ExitCode::FAILURE);
            }
            Err(e) => {
                err(&format!("systemctl enable failed: {e}"));
                return Err(ExitCode::FAILURE);
            }
        }
    } else {
        info(&format!(
            "to start: sudo systemctl enable --now {SERVICE_NAME}"
        ));
    }

    Ok(unit_path)
}

/// Platform-appropriate plist directory.
fn dirs_plist_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join("Library/LaunchAgents")
    } else {
        PathBuf::from("/tmp")
    }
}
