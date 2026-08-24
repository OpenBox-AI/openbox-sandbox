//! Embedded helper-script resolution for the standalone `obs` binary.
//!
//! `obs` ships as ONE artifact: the operational shell helpers
//! (`fetch-openshell-deps.sh`, `provision-local-sandbox.sh`) are embedded at
//! build time so a downloaded binary works with no source checkout and no
//! sibling files. Resolution order:
//!
//!   1. `OPENBOX_SOURCE_ROOT` env  -> <root>/packaging/launcher/scripts/<name>
//!   2. source-repo walk from cwd  -> <repo>/packaging/launcher/scripts/<name>
//!   3. next to the executable     -> <exe dir>/scripts/<name>
//!   4. embedded copy materialized to
//!      <XDG_DATA_HOME|~/.local/share>/openbox-sandbox/scripts/<name>
//!
//! Steps 1-3 keep developer checkouts authoritative (edits take effect
//! without a rebuild). Step 4 makes a downloaded binary fully standalone: the
//! script is written once and re-synced whenever its bytes differ from the
//! embedded version. Materialized copies are never updated from any other
//! source.

use std::env;
use std::fs;
use std::path::PathBuf;

const SCRIPTS: &[(&str, &str)] = &[
    (
        "fetch-openshell-deps.sh",
        include_str!("../scripts/fetch-openshell-deps.sh"),
    ),
    (
        "provision-local-sandbox.sh",
        include_str!("../scripts/provision-local-sandbox.sh"),
    ),
    (
        "provision-native.sh",
        include_str!("../scripts/provision-native.sh"),
    ),
];

/// Resolve a helper script path, materializing the embedded copy when no
/// authoritative location exists.
pub fn resolve(name: &str) -> Result<PathBuf, String> {
    // 1. Explicit source root.
    if let Some(root) = env::var_os("OPENBOX_SOURCE_ROOT") {
        let candidate = PathBuf::from(root)
            .join("packaging/launcher/scripts")
            .join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    // 2. Source-repo walk from the current directory.
    if let Ok(current) = env::current_dir() {
        for ancestor in current.ancestors() {
            if ancestor.join("Cargo.toml").is_file()
                && ancestor
                    .join("packaging/launcher/scripts/provision-local-sandbox.sh")
                    .is_file()
            {
                let candidate = ancestor.join("packaging/launcher/scripts").join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }

    // 3. Release layout: scripts shipped next to the executable.
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join("scripts").join(name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }

    // 4. Embedded fallback.
    let Some((_, bytes)) = SCRIPTS.iter().find(|(n, _)| *n == name) else {
        return Err(format!("no embedded script named {name}"));
    };
    let dir = materialize_dir()?;
    let path = dir.join(name);
    let needs_write = match fs::read(&path) {
        Ok(existing) => existing != bytes.as_bytes(),
        Err(_) => true,
    };
    if needs_write {
        fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create script dir {}: {e}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("cannot secure script dir {}: {e}", dir.display()))?;
        }
        let temp = dir.join(format!("{name}.tmp"));
        fs::write(&temp, bytes).map_err(|e| format!("cannot write embedded script {name}: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temp, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("cannot chmod embedded script {name}: {e}"))?;
        }
        fs::rename(&temp, &path)
            .map_err(|e| format!("cannot finalize embedded script {name}: {e}"))?;
    }
    Ok(path)
}

/// The private per-user directory holding materialized embedded scripts.
fn materialize_dir() -> Result<PathBuf, String> {
    let base = env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .ok_or_else(|| "cannot determine data directory (HOME unset)".to_string())?;
    Ok(base.join("openbox-sandbox/scripts"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn native_smoke_binds_linux_dynamic_loader_paths() {
        let script = SCRIPTS
            .iter()
            .find(|(name, _)| *name == "provision-native.sh")
            .map(|(_, body)| *body)
            .expect("native provision script is embedded");
        let smoke = script
            .split_once("native runner smoke: /bin/true")
            .expect("native smoke marker")
            .1
            .split_once("native sandbox smoke ready")
            .expect("native smoke completion marker")
            .0;

        assert!(smoke.contains("-D \"PROXY_ENDPOINT=localhost:1\""));
        assert!(smoke.contains("for path in /usr /bin /sbin /lib /lib64 /etc"));
        assert!(smoke.contains("bwrap \"${bwrap_args[@]}\""));
    }

    #[test]
    fn embedded_scripts_materialize_standalone() {
        let tmp = std::env::temp_dir().join(format!("obs-scripts-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        // Force standalone mode: no source root, cwd outside any repo.
        // (2021 edition: env mutation is unsafe.)
        unsafe {
            env::remove_var("OPENBOX_SOURCE_ROOT");
            env::remove_var("OPENBOX_PROJECT_ROOT");
            env::set_var("XDG_DATA_HOME", tmp.join("data"));
        }
        let original_cwd = env::current_dir().unwrap();
        env::set_current_dir(&tmp).unwrap();

        let fetch = resolve("fetch-openshell-deps.sh").expect("fetch resolves");
        let wizard = resolve("provision-local-sandbox.sh").expect("wizard resolves");
        env::set_current_dir(original_cwd).unwrap();

        assert!(fetch.is_file());
        assert!(wizard.is_file());
        let embedded_fetch = SCRIPTS
            .iter()
            .find(|(n, _)| *n == "fetch-openshell-deps.sh")
            .map(|(_, b)| b)
            .unwrap();
        assert_eq!(fs::read(&fetch).unwrap(), embedded_fetch.as_bytes());

        // Idempotent: a second resolve must not rewrite the materialized copy.
        let before = fs::metadata(&fetch).unwrap().modified().unwrap();
        resolve("fetch-openshell-deps.sh").unwrap();
        let after = fs::metadata(&fetch).unwrap().modified().unwrap();
        assert_eq!(before, after);

        let _ = fs::remove_dir_all(&tmp);
    }
}
