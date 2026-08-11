use std::collections::HashSet;
use std::fs::File;
use std::io::Read as _;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use openbox_sandbox::{AssetBundleIdentity, CallerRole, PolicyIdentity};
use rustix::fs::{Mode, OFlags, open};
use rustix::process::geteuid;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// The selectable sandbox execution runtime.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeKind {
    /// The `OpenShell` gateway adapter (the default).
    #[default]
    Openshell,
    /// The Docker Sandboxes `sbx` CLI adapter.
    DockerSandboxes,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessConfig {
    pub bind_address: SocketAddr,
    pub server_certificate_path: PathBuf,
    pub server_private_key_path: PathBuf,
    pub client_ca_path: PathBuf,
    pub authorized_callers: Vec<AuthorizedCaller>,
    pub state_directory: PathBuf,
    pub asset_bundle: AssetBundleIdentity,
    #[serde(default)]
    pub runtime_kind: RuntimeKind,
    /// Required for `runtime_kind = "openshell"`; must be absent for
    /// `"docker-sandboxes"`.
    pub runtime_endpoint: Option<String>,
    /// Required for `runtime_kind = "openshell"`; must be absent for
    /// `"docker-sandboxes"`.
    pub runtime_mtls_directory: Option<PathBuf>,
    pub runtime_connect_timeout_ms: u64,
    pub runtime_poll_interval_ms: u64,
    pub reconcile_delete_deadline_ms: u64,
    pub reconcile_wait_deadline_ms: u64,
    pub maximum_connections: usize,
    pub drain_timeout_ms: u64,
    #[serde(default)]
    pub allow_degraded_landlock: bool,
    /// Required for `runtime_kind = "docker-sandboxes"`; must be absent for
    /// `"openshell"`.
    pub docker_sandboxes: Option<DockerSandboxesServiceConfig>,
}

/// The Docker Sandboxes runtime section of the service configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerSandboxesServiceConfig {
    /// The `sbx` binary: a bare name resolved from `PATH`, or an absolute
    /// owner-controlled path.
    pub sbx_binary: PathBuf,
    /// The host workspace mounted into every sandbox at its host path.
    pub workspace: PathBuf,
    /// Optional immutable template image pin. When set, every create request
    /// must carry exactly this template.
    #[serde(default)]
    pub template: Option<String>,
    /// Optional deployment-pinned policy identity attested at readiness.
    #[serde(default)]
    pub policy: Option<PolicyIdentity>,
    /// The per-execution profile.
    pub exec_profile: DockerExecProfile,
}

/// Per-execution parameters for the Docker Sandboxes runtime.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerExecProfile {
    /// The user (or `uid[:gid]`) passed to `sbx exec --user`; unset uses the
    /// sandbox image's default user.
    #[serde(default)]
    pub user: Option<String>,
    /// The working directory passed to `sbx exec --workdir`; defaults to
    /// `/sandbox`.
    #[serde(default)]
    pub workdir: Option<String>,
    /// Optional readiness probe argv executed once the sandbox is running;
    /// readiness is attested only after it exits zero.
    #[serde(default)]
    pub readiness_probe: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedCaller {
    pub certificate_sha256: String,
    pub role: AuthorizedRole,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorizedRole {
    Runtime,
    Administrator,
}

impl From<AuthorizedRole> for CallerRole {
    fn from(value: AuthorizedRole) -> Self {
        match value {
            AuthorizedRole::Runtime => Self::Runtime,
            AuthorizedRole::Administrator => Self::Administrator,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConfigError;

pub fn load(path: &Path) -> Result<ProcessConfig, ConfigError> {
    let file = open_owner_file(path, true)?;
    let metadata = file.metadata().map_err(|_| ConfigError)?;
    if metadata.len() == 0 || metadata.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError);
    }
    let mut body = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| ConfigError)?);
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|_| ConfigError)?;
    if u64::try_from(body.len()).map_err(|_| ConfigError)? != metadata.len() {
        return Err(ConfigError);
    }
    let strict: StrictJson = serde_json::from_slice(&body).map_err(|_| ConfigError)?;
    let config: ProcessConfig =
        serde_json::from_value(strict.into_value()).map_err(|_| ConfigError)?;
    validate(&config)?;
    Ok(config)
}

fn validate(config: &ProcessConfig) -> Result<(), ConfigError> {
    if !config.bind_address.ip().is_loopback()
        || config.bind_address.port() == 0
        || config.authorized_callers.is_empty()
        || config.authorized_callers.len() > 1024
        || config.maximum_connections == 0
        || config.maximum_connections > 65_536
        || [
            config.runtime_connect_timeout_ms,
            config.runtime_poll_interval_ms,
            config.reconcile_delete_deadline_ms,
            config.reconcile_wait_deadline_ms,
            config.drain_timeout_ms,
        ]
        .contains(&0)
        || config.runtime_connect_timeout_ms > 120_000
        || config.runtime_poll_interval_ms > 60_000
        || config.reconcile_delete_deadline_ms > 120_000
        || config.reconcile_wait_deadline_ms > 120_000
        || config.drain_timeout_ms > 120_000
    {
        return Err(ConfigError);
    }
    match config.runtime_kind {
        RuntimeKind::Openshell => {
            let endpoint = config.runtime_endpoint.as_deref().ok_or(ConfigError)?;
            let mtls_directory = config.runtime_mtls_directory.as_ref().ok_or(ConfigError)?;
            if !valid_loopback_https_endpoint(endpoint)
                || mtls_directory.as_os_str().is_empty()
                || config.docker_sandboxes.is_some()
            {
                return Err(ConfigError);
            }
            validate_owner_directory(mtls_directory)?;
        }
        RuntimeKind::DockerSandboxes => {
            if config.runtime_endpoint.is_some() || config.runtime_mtls_directory.is_some() {
                return Err(ConfigError);
            }
            let docker = config.docker_sandboxes.as_ref().ok_or(ConfigError)?;
            validate_docker_sandboxes(docker)?;
        }
    }
    validate_owner_file(&config.server_certificate_path, false)?;
    validate_owner_file(&config.server_private_key_path, true)?;
    validate_owner_file(&config.client_ca_path, false)?;
    validate_owner_directory(&config.state_directory)?;
    Ok(())
}

fn validate_docker_sandboxes(config: &DockerSandboxesServiceConfig) -> Result<(), ConfigError> {
    let binary = config.sbx_binary.as_os_str();
    if binary.is_empty() || binary.to_string_lossy().contains('\0') {
        return Err(ConfigError);
    }
    if config.sbx_binary.is_absolute() {
        validate_owner_file(&config.sbx_binary, false)?;
    } else if config
        .sbx_binary
        .to_string_lossy()
        .chars()
        .any(|character| character == '/' || character.is_whitespace())
    {
        return Err(ConfigError);
    }
    validate_workspace(&config.workspace)?;
    if config
        .template
        .as_ref()
        .is_some_and(|template| !immutable_image_reference(template))
    {
        return Err(ConfigError);
    }
    if config
        .exec_profile
        .readiness_probe
        .as_ref()
        .is_some_and(Vec::is_empty)
    {
        return Err(ConfigError);
    }
    if config
        .exec_profile
        .user
        .as_ref()
        .is_some_and(|user| !valid_exec_user(user))
    {
        return Err(ConfigError);
    }
    if config
        .exec_profile
        .workdir
        .as_ref()
        .is_some_and(|workdir| !workdir.starts_with('/') || workdir.contains('\0'))
    {
        return Err(ConfigError);
    }
    Ok(())
}

/// The workspace is the shared host mount; it must exist, be a directory,
/// and contain no symlink components. Ownership is intentionally not
/// required: the workload inside the sandbox is the reader/writer.
fn validate_workspace(path: &Path) -> Result<(), ConfigError> {
    reject_symlink_components(path)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ConfigError)?;
    if !metadata.is_dir() {
        return Err(ConfigError);
    }
    Ok(())
}

fn immutable_image_reference(image: &str) -> bool {
    let Some((repository, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    !repository.is_empty()
        && !image.chars().any(char::is_whitespace)
        && digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_exec_user(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 128
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-' | b':'))
}

fn valid_loopback_https_endpoint(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if authority.is_empty()
        || authority
            .chars()
            .any(|character| matches!(character, '/' | '?' | '#' | '@' | '\0'))
    {
        return false;
    }
    authority
        .parse::<SocketAddr>()
        .is_ok_and(|address| address.ip().is_loopback() && address.port() != 0)
}

fn validate_owner_file(path: &Path, private: bool) -> Result<(), ConfigError> {
    let _ = open_owner_file(path, private)?;
    Ok(())
}

fn open_owner_file(path: &Path, private: bool) -> Result<File, ConfigError> {
    reject_symlink_components(path)?;
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| ConfigError)?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| ConfigError)?;
    let mode = metadata.mode() & 0o777;
    if !metadata.is_file()
        || metadata.uid() != geteuid().as_raw()
        || (private && mode != 0o600)
        || (!private && mode & 0o022 != 0)
    {
        return Err(ConfigError);
    }
    Ok(file)
}

fn validate_owner_directory(path: &Path) -> Result<(), ConfigError> {
    reject_symlink_components(path)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ConfigError)?;
    if !metadata.is_dir()
        || metadata.uid() != geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(ConfigError);
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> Result<(), ConfigError> {
    if !path.is_absolute() {
        return Err(ConfigError);
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current).map_err(|_| ConfigError)?;
        if metadata.file_type().is_symlink() {
            return Err(ConfigError);
        }
    }
    Ok(())
}

#[derive(Debug)]
enum StrictJson {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Self>),
    Object(serde_json::Map<String, serde_json::Value>),
}

impl StrictJson {
    fn into_value(self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(value) => serde_json::Value::Bool(value),
            Self::Number(value) => serde_json::Value::Number(value),
            Self::String(value) => serde_json::Value::String(value),
            Self::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(Self::into_value).collect())
            }
            Self::Object(value) => serde_json::Value::Object(value),
        }
    }
}

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("strict JSON")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson::Null)
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJson::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJson::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJson::Number(value.into()))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(StrictJson::Number)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.contains('\0') {
            return Err(E::custom("NUL rejected"));
        }
        Ok(StrictJson::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJson>()? {
            values.push(value);
        }
        Ok(StrictJson::Array(values))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = HashSet::new();
        let mut values = serde_json::Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.contains('\0') || !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom("duplicate or invalid key"));
            }
            let value = map.next_value::<StrictJson>()?;
            values.insert(key, value.into_value());
        }
        Ok(StrictJson::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    fn write(path: &Path, body: &[u8], mode: u32) {
        std::fs::write(path, body).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn fixture(root: &Path) -> (PathBuf, serde_json::Value) {
        let tls = root.join("tls");
        let state = root.join("state");
        let runtime = root.join("runtime-mtls");
        for directory in [&tls, &state, &runtime] {
            std::fs::create_dir_all(directory).unwrap();
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let certificate = tls.join("server.crt");
        let private_key = tls.join("server.key");
        let client_ca = tls.join("client-ca.crt");
        write(&certificate, b"certificate", 0o644);
        write(&private_key, b"private-key", 0o600);
        write(&client_ca, b"client-ca", 0o644);
        let value = serde_json::json!({
            "bind_address": "127.0.0.1:17443",
            "server_certificate_path": certificate,
            "server_private_key_path": private_key,
            "client_ca_path": client_ca,
            "authorized_callers": [{
                "certificate_sha256": "a".repeat(64),
                "role": "runtime"
            }],
            "state_directory": state,
            "asset_bundle": {
                "runtime_contract_version": 1,
                "adapter_build_sha256": "b".repeat(64),
                "template": format!("registry.invalid/openbox@sha256:{}", "c".repeat(64)),
                "policy": {
                    "id": "deny-network",
                    "version": 1,
                    "sha256": "d".repeat(64)
                },
                "compatibility_id": "openshell-v1"
            },
            "runtime_endpoint": "https://127.0.0.1:17670",
            "runtime_mtls_directory": runtime,
            "runtime_connect_timeout_ms": 10000,
            "runtime_poll_interval_ms": 250,
            "reconcile_delete_deadline_ms": 60000,
            "reconcile_wait_deadline_ms": 60000,
            "maximum_connections": 64,
            "drain_timeout_ms": 30000
        });
        (root.join("service.json"), value)
    }

    #[test]
    fn strict_json_rejects_duplicate_keys_nonfinite_and_nul() {
        for body in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"a":NaN}"#.as_slice(),
            b"{\"a\":\"\\u0000\"}".as_slice(),
        ] {
            assert!(serde_json::from_slice::<StrictJson>(body).is_err());
        }
    }

    #[test]
    fn owner_controlled_config_loads_and_rejects_noncanonical_values() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (path, value) = fixture(&root);
        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o600);
        assert_eq!(load(&path).unwrap().maximum_connections, 64);

        let mut invalid = value.clone();
        invalid["maximum_connections"] = serde_json::Value::Bool(true);
        write(
            &path,
            serde_json::to_vec(&invalid).unwrap().as_slice(),
            0o600,
        );
        assert!(load(&path).is_err());

        let mut invalid = value.clone();
        invalid["bind_address"] = serde_json::Value::String("192.0.2.1:17443".to_owned());
        write(
            &path,
            serde_json::to_vec(&invalid).unwrap().as_slice(),
            0o600,
        );
        assert!(load(&path).is_err());

        let mut invalid = value.clone();
        invalid["runtime_endpoint"] =
            serde_json::Value::String("https://192.0.2.1:17670".to_owned());
        write(
            &path,
            serde_json::to_vec(&invalid).unwrap().as_slice(),
            0o600,
        );
        assert!(load(&path).is_err());

        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o644);
        assert!(load(&path).is_err());
    }

    #[test]
    fn degraded_landlock_defaults_off_and_parses_when_explicitly_set() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (path, mut value) = fixture(&root);
        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o600);
        assert!(!load(&path).unwrap().allow_degraded_landlock);

        value["allow_degraded_landlock"] = serde_json::Value::Bool(true);
        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o600);
        assert!(load(&path).unwrap().allow_degraded_landlock);
    }

    fn docker_fixture(root: &Path) -> (PathBuf, serde_json::Value) {
        let (path, mut value) = fixture(root);
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::set_permissions(&workspace, std::fs::Permissions::from_mode(0o700)).unwrap();
        let binary = root.join("sbx");
        write(&binary, b"#!/bin/sh\n", 0o755);
        if let serde_json::Value::Object(fields) = &mut value {
            fields.remove("runtime_endpoint");
            fields.remove("runtime_mtls_directory");
        }
        value["runtime_kind"] = serde_json::Value::String("docker-sandboxes".to_owned());
        value["docker_sandboxes"] = serde_json::json!({
            "sbx_binary": binary,
            "workspace": workspace,
            "template": format!("registry.invalid/openbox@sha256:{}", "c".repeat(64)),
            "policy": {
                "id": "deny-network",
                "version": 1,
                "sha256": "d".repeat(64)
            },
            "exec_profile": {
                "user": "sandbox",
                "workdir": "/sandbox",
                "readiness_probe": ["/bin/true"]
            }
        });
        (path, value)
    }

    #[test]
    fn docker_sandboxes_runtime_kind_loads_and_validates_its_section() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (path, value) = docker_fixture(&root);
        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o600);
        let config = load(&path).unwrap();
        assert_eq!(config.runtime_kind, RuntimeKind::DockerSandboxes);
        assert!(config.runtime_endpoint.is_none());
        assert!(config.runtime_mtls_directory.is_none());
        let docker = config.docker_sandboxes.as_ref().unwrap();
        assert_eq!(docker.exec_profile.user.as_deref(), Some("sandbox"));
        assert_eq!(docker.exec_profile.workdir.as_deref(), Some("/sandbox"));
        assert_eq!(
            docker.exec_profile.readiness_probe.as_deref(),
            Some(["/bin/true".to_owned()].as_slice())
        );
    }

    #[test]
    fn docker_sandboxes_kind_rejects_openshell_fields_and_bad_sections() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (path, value) = docker_fixture(&root);
        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o600);

        let mut with_openshell = value.clone();
        with_openshell["runtime_endpoint"] =
            serde_json::Value::String("https://127.0.0.1:17670".to_owned());
        with_openshell["runtime_mtls_directory"] =
            serde_json::Value::String(root.join("runtime-mtls").to_string_lossy().into_owned());
        write(
            &path,
            serde_json::to_vec(&with_openshell).unwrap().as_slice(),
            0o600,
        );
        assert!(load(&path).is_err());

        let mut no_section = value.clone();
        if let serde_json::Value::Object(fields) = &mut no_section {
            fields.remove("docker_sandboxes");
        }
        write(
            &path,
            serde_json::to_vec(&no_section).unwrap().as_slice(),
            0o600,
        );
        assert!(load(&path).is_err());

        let mut bad_probe = value.clone();
        bad_probe["docker_sandboxes"]["exec_profile"]["readiness_probe"] = serde_json::json!([]);
        write(
            &path,
            serde_json::to_vec(&bad_probe).unwrap().as_slice(),
            0o600,
        );
        assert!(load(&path).is_err());

        let mut bad_user = value.clone();
        bad_user["docker_sandboxes"]["exec_profile"]["user"] =
            serde_json::Value::String("sand box".to_owned());
        write(
            &path,
            serde_json::to_vec(&bad_user).unwrap().as_slice(),
            0o600,
        );
        assert!(load(&path).is_err());

        let mut bad_template = value.clone();
        bad_template["docker_sandboxes"]["template"] =
            serde_json::Value::String("registry.invalid/openbox:latest".to_owned());
        write(
            &path,
            serde_json::to_vec(&bad_template).unwrap().as_slice(),
            0o600,
        );
        assert!(load(&path).is_err());

        let mut missing_workspace = value.clone();
        missing_workspace["docker_sandboxes"]["workspace"] =
            serde_json::Value::String(root.join("absent-workspace").to_string_lossy().into_owned());
        write(
            &path,
            serde_json::to_vec(&missing_workspace).unwrap().as_slice(),
            0o600,
        );
        assert!(load(&path).is_err());

        let mut relative_binary = value.clone();
        relative_binary["docker_sandboxes"]["sbx_binary"] =
            serde_json::Value::String("tools/sbx".to_owned());
        write(
            &path,
            serde_json::to_vec(&relative_binary).unwrap().as_slice(),
            0o600,
        );
        assert!(load(&path).is_err());

        let mut bare_binary = value;
        bare_binary["docker_sandboxes"]["sbx_binary"] = serde_json::Value::String("sbx".to_owned());
        write(
            &path,
            serde_json::to_vec(&bare_binary).unwrap().as_slice(),
            0o600,
        );
        assert!(load(&path).is_ok());
    }

    #[test]
    fn openshell_kind_rejects_docker_section_and_defaults_to_openshell() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (path, mut value) = docker_fixture(&root);
        value["runtime_kind"] = serde_json::Value::String("openshell".to_owned());
        value["runtime_endpoint"] = serde_json::Value::String("https://127.0.0.1:17670".to_owned());
        value["runtime_mtls_directory"] =
            serde_json::Value::String(root.join("runtime-mtls").to_string_lossy().into_owned());
        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o600);
        assert!(load(&path).is_err());

        let (path, value) = fixture(&root);
        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o600);
        assert_eq!(load(&path).unwrap().runtime_kind, RuntimeKind::Openshell);
    }

    #[test]
    fn config_rejects_symlinks_and_nonprivate_directories() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (path, mut value) = fixture(&root);
        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o600);
        let linked = temporary.path().join("linked.json");
        std::os::unix::fs::symlink(&path, &linked).unwrap();
        assert!(load(&linked).is_err());

        let state = PathBuf::from(value["state_directory"].as_str().unwrap());
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(load(&path).is_err());
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();

        value["unexpected"] = serde_json::Value::Bool(true);
        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o600);
        assert!(load(&path).is_err());
    }
}
