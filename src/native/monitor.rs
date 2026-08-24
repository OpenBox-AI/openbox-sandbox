#[cfg(target_os = "macos")]
use std::collections::BTreeSet;
#[cfg(target_os = "macos")]
use std::process::Stdio;

#[cfg(target_os = "macos")]
use tokio::process::Command;

#[cfg(target_os = "macos")]
use crate::ViolationCategory;
use crate::ViolationEvidence;

/// Query the macOS unified sandbox violation store for the exact process that
/// `sandbox-exec` replaced. `log stream` was tested first, but on current macOS
/// it does not emit kernel-originated violation records to a redirected pipe;
/// the same records are immediately and reliably available through `log show`.
#[cfg(target_os = "macos")]
pub(super) async fn collect(process_id: u32, lookback_seconds: u64) -> Option<ViolationEvidence> {
    let marker = format!("({process_id})");
    let predicate = format!(
        "subsystem == \"com.apple.sandbox.reporting\" AND category == \"violation\" AND eventMessage CONTAINS \"{marker}\""
    );
    let output = Command::new("/usr/bin/log")
        .args([
            "show",
            "--style",
            "compact",
            "--last",
            &format!("{}s", lookback_seconds.max(1)),
            "--predicate",
            &predicate,
        ])
        .stdin(Stdio::null())
        .output()
        .await
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&output.stdout);
    let mut count = 0_u64;
    let mut categories = BTreeSet::new();
    for line in body.lines().filter(|line| {
        line.contains("[com.apple.sandbox.reporting:violation]")
            && line.contains(" deny(")
            && line.contains(&marker)
    }) {
        count = count.saturating_add(1);
        let category = if line.contains(" file-write") {
            ViolationCategory::DeniedFileWrite
        } else if line.contains(" file-read") {
            ViolationCategory::DeniedFileRead
        } else if line.contains(" network-") {
            ViolationCategory::DeniedNetwork
        } else if line.contains(" process-") {
            ViolationCategory::DeniedProcess
        } else {
            ViolationCategory::Other
        };
        categories.insert(category);
        eprintln!("native sandbox violation pid={process_id} category={category:?}");
    }
    (count != 0).then(|| ViolationEvidence::new(count, categories.into_iter().collect()))
}

#[cfg(not(target_os = "macos"))]
pub(super) async fn collect(_process_id: u32, _lookback_seconds: u64) -> Option<ViolationEvidence> {
    // bubblewrap has no unprivileged, per-process deny-event stream equivalent.
    None
}
