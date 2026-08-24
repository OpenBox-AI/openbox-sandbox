use std::collections::HashSet;
use std::fs::File;
use std::io::Read as _;
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use openbox_sandbox::{AssetBundleIdentity, CallerRole, ProviderCapability, Sha256Digest};
use rustix::fs::{Mode, OFlags, open};
use rustix::process::geteuid;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

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
    pub provider: ProviderKind,
    pub provider_capability: ProviderCapability,
    #[serde(default)]
    pub runtime_endpoint: Option<String>,
    #[serde(default)]
    pub runtime_mtls_directory: Option<PathBuf>,
    #[serde(default)]
    pub runtime_connect_timeout_ms: Option<u64>,
    #[serde(default)]
    pub runtime_poll_interval_ms: Option<u64>,
    #[serde(default)]
    pub native_profile_path: Option<PathBuf>,
    #[serde(default)]
    pub native_profile_sha256: Option<Sha256Digest>,
    #[serde(default)]
    pub native_workspace_root: Option<PathBuf>,
    pub reconcile_delete_deadline_ms: u64,
    pub reconcile_wait_deadline_ms: u64,
    pub maximum_connections: usize,
    pub drain_timeout_ms: u64,
    #[serde(default)]
    pub allow_degraded_landlock: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum ProviderKind {
    #[serde(rename = "openshell")]
    OpenShell,
    #[serde(rename = "native")]
    Native,
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

#[allow(clippy::too_many_lines)]
fn validate(config: &ProcessConfig) -> Result<(), ConfigError> {
    if !config.bind_address.ip().is_loopback() {
        eprintln!("ERROR: config validation failed: bind_address is not loopback");
        return Err(ConfigError);
    }
    if config.bind_address.port() == 0 {
        eprintln!("ERROR: config validation failed: bind_address port is 0");
        return Err(ConfigError);
    }
    if config.authorized_callers.is_empty() {
        eprintln!("ERROR: config validation failed: authorized_callers is empty");
        return Err(ConfigError);
    }
    if config.authorized_callers.len() > 1024 {
        eprintln!("ERROR: config validation failed: authorized_callers exceeds 1024 entries");
        return Err(ConfigError);
    }
    if config.maximum_connections == 0 {
        eprintln!("ERROR: config validation failed: maximum_connections is 0");
        return Err(ConfigError);
    }
    if config.maximum_connections > 65_536 {
        eprintln!("ERROR: config validation failed: maximum_connections exceeds 65536");
        return Err(ConfigError);
    }
    match config.provider {
        ProviderKind::OpenShell => {
            if config.provider_capability != ProviderCapability::Attested
                || config.native_profile_path.is_some()
                || config.native_profile_sha256.is_some()
                || config.native_workspace_root.is_some()
            {
                eprintln!(
                    "ERROR: config validation failed: OpenShell capability/provider fields mismatch"
                );
                return Err(ConfigError);
            }
            let endpoint = config.runtime_endpoint.as_deref().ok_or(ConfigError)?;
            if !valid_loopback_https_endpoint(endpoint) {
                eprintln!(
                    "ERROR: config validation failed: runtime_endpoint is not a valid loopback HTTPS endpoint"
                );
                return Err(ConfigError);
            }
            let mtls = config
                .runtime_mtls_directory
                .as_deref()
                .ok_or(ConfigError)?;
            if mtls.as_os_str().is_empty() {
                eprintln!("ERROR: config validation failed: runtime_mtls_directory is empty");
                return Err(ConfigError);
            }
            if config
                .runtime_connect_timeout_ms
                .is_none_or(|value| value == 0 || value > 120_000)
            {
                eprintln!(
                    "ERROR: config validation failed: runtime_connect_timeout_ms is outside 1..=120000"
                );
                return Err(ConfigError);
            }
            if config
                .runtime_poll_interval_ms
                .is_none_or(|value| value == 0 || value > 60_000)
            {
                eprintln!(
                    "ERROR: config validation failed: runtime_poll_interval_ms is outside 1..=60000"
                );
                return Err(ConfigError);
            }
        }
        ProviderKind::Native => {
            if config.provider_capability != ProviderCapability::EnforcedLocally
                || config.runtime_endpoint.is_some()
                || config.runtime_mtls_directory.is_some()
                || config.runtime_connect_timeout_ms.is_some()
                || config.runtime_poll_interval_ms.is_some()
            {
                eprintln!(
                    "ERROR: config validation failed: native capability/provider fields mismatch"
                );
                return Err(ConfigError);
            }
            let profile = config.native_profile_path.as_deref().ok_or(ConfigError)?;
            let workspace = config.native_workspace_root.as_deref().ok_or(ConfigError)?;
            if config.native_profile_sha256.is_none() || workspace.as_os_str().is_empty() {
                eprintln!(
                    "ERROR: config validation failed: native profile pin or workspace is missing"
                );
                return Err(ConfigError);
            }
            validate_owner_file(profile, true).inspect_err(|_| {
                eprintln!("ERROR: config validation failed: native_profile_path validation failed");
            })?;
            validate_owner_directory(workspace).inspect_err(|_| {
                eprintln!(
                    "ERROR: config validation failed: native_workspace_root validation failed"
                );
            })?;
        }
    }
    if config.reconcile_delete_deadline_ms == 0 {
        eprintln!("ERROR: config validation failed: reconcile_delete_deadline_ms is 0");
        return Err(ConfigError);
    }
    if config.reconcile_delete_deadline_ms > 120_000 {
        eprintln!("ERROR: config validation failed: reconcile_delete_deadline_ms exceeds 120000");
        return Err(ConfigError);
    }
    if config.reconcile_wait_deadline_ms == 0 {
        eprintln!("ERROR: config validation failed: reconcile_wait_deadline_ms is 0");
        return Err(ConfigError);
    }
    if config.reconcile_wait_deadline_ms > 120_000 {
        eprintln!("ERROR: config validation failed: reconcile_wait_deadline_ms exceeds 120000");
        return Err(ConfigError);
    }
    if config.drain_timeout_ms == 0 {
        eprintln!("ERROR: config validation failed: drain_timeout_ms is 0");
        return Err(ConfigError);
    }
    if config.drain_timeout_ms > 120_000 {
        eprintln!("ERROR: config validation failed: drain_timeout_ms exceeds 120000");
        return Err(ConfigError);
    }
    validate_owner_file(&config.server_certificate_path, false).inspect_err(|_| {
        eprintln!("ERROR: config validation failed: server_certificate_path validation failed");
    })?;
    validate_owner_file(&config.server_private_key_path, true).inspect_err(|_| {
        eprintln!("ERROR: config validation failed: server_private_key_path validation failed");
    })?;
    validate_owner_file(&config.client_ca_path, false).inspect_err(|_| {
        eprintln!("ERROR: config validation failed: client_ca_path validation failed");
    })?;
    validate_owner_directory(&config.state_directory).inspect_err(|_| {
        eprintln!("ERROR: config validation failed: state_directory validation failed");
    })?;
    if let Some(runtime_mtls_directory) = &config.runtime_mtls_directory {
        validate_owner_directory(runtime_mtls_directory).inspect_err(|_| {
            eprintln!("ERROR: config validation failed: runtime_mtls_directory validation failed");
        })?;
    }
    Ok(())
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
            std::fs::create_dir(directory).unwrap();
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
            "provider": "openshell",
            "provider_capability": "attested",
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

    #[test]
    fn native_provider_requires_explicit_local_capability_and_pinned_profile() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let (path, mut value) = fixture(&root);
        let workspace = root.join("native-workspaces");
        let profile = root.join(if cfg!(target_os = "macos") {
            "policy.sb"
        } else {
            "policy.json"
        });
        let policy = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("deploy/policies/policy-deny-network.yaml");
        let profile_sha =
            openbox_sandbox::compile_native_policy(&policy, &profile, &workspace).unwrap();
        std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o600)).unwrap();
        value["provider"] = serde_json::Value::String("native".to_owned());
        value["provider_capability"] = serde_json::Value::String("enforced-locally".to_owned());
        value.as_object_mut().unwrap().remove("runtime_endpoint");
        value
            .as_object_mut()
            .unwrap()
            .remove("runtime_mtls_directory");
        value
            .as_object_mut()
            .unwrap()
            .remove("runtime_connect_timeout_ms");
        value
            .as_object_mut()
            .unwrap()
            .remove("runtime_poll_interval_ms");
        value["native_profile_path"] =
            serde_json::Value::String(profile.to_string_lossy().into_owned());
        value["native_profile_sha256"] = serde_json::Value::String(profile_sha);
        value["native_workspace_root"] =
            serde_json::Value::String(workspace.to_string_lossy().into_owned());
        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o600);
        assert_eq!(load(&path).unwrap().provider, ProviderKind::Native);

        value["provider_capability"] = serde_json::Value::String("attested".to_owned());
        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o600);
        assert!(load(&path).is_err());
        value.as_object_mut().unwrap().remove("provider_capability");
        write(&path, serde_json::to_vec(&value).unwrap().as_slice(), 0o600);
        assert!(load(&path).is_err());
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
