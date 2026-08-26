//! Fetch the pinned OpenShell release without materializing a shell script.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const DARWIN_GATEWAY_SHA256: &str =
    "5de3e08ad1bdb0cdd01373999f537edca3d8aca22ae1c29bc9926969fe401e45";
const DARWIN_CLI_SHA256: &str = "522c963f9515c7325b978e89022de76227ac245eefe1371292af1424434e2067";
const DARWIN_DRIVER_SHA256: &str =
    "c33a6f6ebd22c847fee764a0a15b1a577fb29f5624dfcc81c6a727f3eebc421b";

struct Asset<'a> {
    name: String,
    checksum_file: &'static str,
    fallback: &'a str,
}

pub fn fetch(out: &Path, version: &str) -> Result<(), String> {
    require_command(
        "curl",
        "error: curl is required to fetch OpenShell releases",
    )?;
    let triple = detect_triple()?;
    let base = format!("https://github.com/NVIDIA/OpenShell/releases/download/v{version}");
    crate::info(&format!(
        "fetching OpenShell v{version} for {triple} into {}",
        out.display()
    ));
    fs::create_dir_all(out.join("bin"))
        .and_then(|()| fs::create_dir_all(out.join("libexec")))
        .map_err(|error| format!("cannot create bundle {}: {error}", out.display()))?;

    let work = temporary_directory()?;
    let result = fetch_into(&work, out, &base, &triple);
    let _ = fs::remove_dir_all(&work);
    result?;

    crate::ok(&format!("OpenShell bundle ready: {}", out.display()));
    crate::info(&format!("gateway: {}/bin/openshell-gateway", out.display()));
    crate::info(&format!(
        "driver:  {}/libexec/openshell-driver-vm",
        out.display()
    ));
    crate::info(&format!("cli:     {}/bin/openshell", out.display()));
    Ok(())
}

fn fetch_into(work: &Path, out: &Path, base: &str, triple: &str) -> Result<(), String> {
    let musl_triple = triple
        .strip_suffix("-gnu")
        .map_or_else(|| triple.to_owned(), |prefix| format!("{prefix}-musl"));
    let assets = if triple.ends_with("-apple-darwin") {
        vec![
            Asset {
                name: format!("openshell-gateway-{triple}.tar.gz"),
                checksum_file: "openshell-gateway-checksums-sha256.txt",
                fallback: DARWIN_GATEWAY_SHA256,
            },
            Asset {
                name: format!("openshell-driver-vm-{triple}.tar.gz"),
                checksum_file: "openshell-checksums-sha256.txt",
                fallback: DARWIN_DRIVER_SHA256,
            },
            Asset {
                name: format!("openshell-{triple}.tar.gz"),
                checksum_file: "openshell-checksums-sha256.txt",
                fallback: DARWIN_CLI_SHA256,
            },
        ]
    } else if triple.ends_with("-unknown-linux-gnu") {
        vec![
            Asset {
                name: format!("openshell-gateway-{triple}.tar.gz"),
                checksum_file: "openshell-gateway-checksums-sha256.txt",
                fallback: "",
            },
            Asset {
                name: format!("openshell-driver-vm-{triple}.tar.gz"),
                checksum_file: "openshell-checksums-sha256.txt",
                fallback: "",
            },
            Asset {
                name: format!("openshell-{musl_triple}.tar.gz"),
                checksum_file: "openshell-checksums-sha256.txt",
                fallback: "",
            },
        ]
    } else if triple.ends_with("-unknown-linux-musl") {
        vec![
            Asset {
                name: format!("openshell-gateway-{triple}.tar.gz"),
                checksum_file: "openshell-gateway-checksums-sha256.txt",
                fallback: "",
            },
            Asset {
                name: format!("openshell-driver-vm-{triple}.tar.gz"),
                checksum_file: "openshell-checksums-sha256.txt",
                fallback: "",
            },
            Asset {
                name: format!("openshell-{triple}.tar.gz"),
                checksum_file: "openshell-checksums-sha256.txt",
                fallback: "",
            },
        ]
    } else {
        return Err(format!("unsupported triple: {triple} (set TARGET_TRIPLE=)"));
    };

    for asset in assets {
        verify_and_extract(work, base, &asset)?;
    }
    place(
        work,
        "openshell-gateway",
        &out.join("bin/openshell-gateway"),
    )?;
    place(
        work,
        "openshell-driver-vm",
        &out.join("libexec/openshell-driver-vm"),
    )?;
    place(work, "openshell", &out.join("bin/openshell"))?;
    Ok(())
}

fn detect_triple() -> Result<String, String> {
    if let Ok(value) = std::env::var("TARGET_TRIPLE") {
        if !value.is_empty() {
            return Ok(value);
        }
    }
    let arch = std::env::consts::ARCH;
    match std::env::consts::OS {
        "macos" => Ok(format!("{arch}-apple-darwin")),
        "linux" => Ok(format!("{arch}-unknown-linux-gnu")),
        other => Err(format!("unsupported os: {other}")),
    }
}

fn verify_and_extract(work: &Path, base: &str, asset: &Asset<'_>) -> Result<(), String> {
    let expected = checksum_for(base, &asset.name, asset.checksum_file, asset.fallback)?;
    let destination = work.join(&asset.name);
    crate::info(&format!("downloading {}", asset.name));
    curl_download(&format!("{base}/{}", asset.name), &destination)?;
    verify_download_checksum(&destination, &expected).map_err(|found| {
        format!(
            "error: sha256 mismatch for {}\n  expected {}\n  found    {}\nrefusing to extract — the release tarball is not the pinned one.",
            asset.name, expected, found
        )
    })?;
    crate::ok(&format!(
        "{} verified (sha256 {}…)",
        asset.name,
        &expected[..expected.len().min(12)]
    ));
    let status = Command::new("tar")
        .args([
            OsStr::new("-xzf"),
            destination.as_os_str(),
            OsStr::new("-C"),
        ])
        .arg(work)
        .status()
        .map_err(|error| format!("cannot run tar for {}: {error}", asset.name))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("tar exited {status} for {}", asset.name))
    }
}

fn checksum_for(
    base: &str,
    asset: &str,
    checksum_file: &str,
    fallback: &str,
) -> Result<String, String> {
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "--retry",
            "5",
            "--retry-delay",
            "2",
            "--retry-all-errors",
            &format!("{base}/{checksum_file}"),
        ])
        .output();
    if let Ok(output) = output {
        if output.status.success() {
            if let Some(checksum) = parse_checksum_file(&output.stdout, asset) {
                return Ok(checksum);
            }
        }
    }
    if !fallback.is_empty() {
        Ok(fallback.to_owned())
    } else {
        Err(format!(
            "error: {checksum_file} missing checksum for {asset}"
        ))
    }
}

fn parse_checksum_file(body: &[u8], asset: &str) -> Option<String> {
    String::from_utf8_lossy(body).lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let name = fields.next()?.trim_start_matches('*');
        (name == asset && digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .then(|| digest.to_owned())
    })
}

fn curl_download(url: &str, destination: &Path) -> Result<(), String> {
    let status = Command::new("curl")
        .args([
            "-fsSL",
            "--retry",
            "5",
            "--retry-delay",
            "2",
            "--retry-all-errors",
        ])
        .arg(url)
        .arg("-o")
        .arg(destination)
        .status()
        .map_err(|error| format!("cannot run curl for {url}: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("curl exited {status} while downloading {url}"))
    }
}

fn place(work: &Path, name: &str, destination: &Path) -> Result<(), String> {
    let Some(source) = find_named_file(work, name)? else {
        crate::warn(&format!(
            "{name} not found in extracted tarballs; {} will be absent",
            destination.display()
        ));
        return Ok(());
    };
    fs::copy(&source, destination).map_err(|error| {
        format!(
            "cannot install {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    chmod(destination, 0o755)?;
    crate::info(&format!("placed {name} -> {}", destination.display()));
    Ok(())
}

fn find_named_file(root: &Path, name: &str) -> Result<Option<PathBuf>, String> {
    for entry in
        fs::read_dir(root).map_err(|error| format!("cannot inspect {}: {error}", root.display()))?
    {
        let path = entry
            .map_err(|error| format!("cannot inspect {}: {error}", root.display()))?
            .path();
        if path.is_dir() {
            if let Some(found) = find_named_file(&path, name)? {
                return Ok(Some(found));
            }
        } else if path.file_name().is_some_and(|candidate| candidate == name)
            && is_executable(&path)
        {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

fn temporary_directory() -> Result<PathBuf, String> {
    let output = Command::new("mktemp")
        .arg("-d")
        .output()
        .map_err(|error| format!("cannot run mktemp: {error}"))?;
    if !output.status.success() {
        return Err(format!("mktemp exited {}", output.status));
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    if path.is_dir() {
        Ok(path)
    } else {
        Err("mktemp did not create a directory".to_owned())
    }
}

fn verify_download_checksum(path: &Path, expected: &str) -> Result<String, String> {
    let found = sha256_file(path).map_err(|error| error.to_string())?;
    if found.eq_ignore_ascii_case(expected) {
        Ok(found)
    } else {
        Err(found)
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let output = Command::new("openssl")
        .args([OsStr::new("dgst"), OsStr::new("-sha256"), path.as_os_str()])
        .output()
        .map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "cannot hash {}: openssl exited {}",
            path.display(),
            output.status
        ));
    }
    let digest = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next_back()
        .unwrap_or_default()
        .to_owned();
    if digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(digest)
    } else {
        Err(format!("cannot parse sha256 for {}", path.display()))
    }
}

fn require_command(name: &str, message: &str) -> Result<(), String> {
    if command_exists(name) {
        Ok(())
    } else {
        Err(message.to_owned())
    }
}

fn command_exists(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|path| {
            std::env::split_paths(&path).any(|directory| is_executable(&directory.join(name)))
        })
        .unwrap_or(false)
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn chmod(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("cannot chmod {}: {error}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

#[allow(dead_code)]
fn write_mode(path: &Path, body: &[u8], mode: u32) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    file.write_all(body)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    chmod(path, mode)
}

#[cfg(test)]
mod tests {
    use super::{parse_checksum_file, verify_download_checksum};

    #[test]
    fn checksum_file_resolution_is_asset_specific() {
        let body =
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  one.tar.gz\n\
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb *two.tar.gz\n";
        assert_eq!(
            parse_checksum_file(body, "two.tar.gz").as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
        assert_eq!(parse_checksum_file(body, "missing.tar.gz"), None);
    }

    #[test]
    fn downloaded_asset_checksum_is_verified_against_fixture() {
        let path = std::env::temp_dir().join(format!(
            "obs-openshell-checksum-fixture-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"fixture").unwrap();
        let expected = "f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d";
        assert!(verify_download_checksum(&path, expected).is_ok());
        assert_eq!(
            verify_download_checksum(
                &path,
                "0000000000000000000000000000000000000000000000000000000000000000"
            )
            .unwrap_err(),
            expected
        );
        std::fs::remove_file(path).unwrap();
    }
}
