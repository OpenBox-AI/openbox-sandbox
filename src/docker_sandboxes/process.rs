//! `sbx` CLI argv construction and output classification.
//!
//! This module is the single place that knows the `sbx` command-line surface:
//! every subprocess argv is built here, and every non-zero stderr body is
//! classified here into stable hints. Nothing else in the adapter parses CLI
//! output, which keeps the CLI contract explicit and unit-testable.

use crate::runtime_contract::RequestOwnedId;

/// The minimum `sbx` CLI version accepted by this adapter build.
///
/// The validated contract baseline is the `sbx` version pair used by the
/// reference programmatic driver (`v0.31.3`); every command this adapter
/// invokes (`create --name/--template`, `ls --json`, `exec`, `rm --force`,
/// `version`) is present in that baseline.
pub const MIN_SUPPORTED_SBX_VERSION: (u32, u32, u32) = (0, 31, 3);

/// Builds `sbx version`.
pub fn build_version_args() -> Vec<String> {
    vec!["version".to_owned()]
}

/// Builds `sbx ls --json`.
pub fn build_list_args() -> Vec<String> {
    vec!["ls".to_owned(), "--json".to_owned()]
}

/// Builds the non-interactive create command for the `shell` agent.
///
/// The request-owned identifier becomes the sandbox name, the template image
/// is passed verbatim, and the configured workspace is mounted at its host
/// absolute path inside the sandbox. `--quiet` suppresses progress output so
/// automation never depends on its shape.
pub fn build_create_args(name: &str, image: &str, workspace: &str) -> Vec<String> {
    vec![
        "create".to_owned(),
        "--name".to_owned(),
        name.to_owned(),
        "--template".to_owned(),
        image.to_owned(),
        "--quiet".to_owned(),
        "shell".to_owned(),
        workspace.to_owned(),
    ]
}

/// Builds `sbx exec [--user USER] --workdir WORKDIR SANDBOX ARGV...`.
///
/// Flags precede the positional sandbox name so cobra never mistakes an argv
/// element for a flag, and argv is appended element-for-element without shell
/// quoting.
pub fn build_exec_args(
    name: &str,
    user: Option<&str>,
    workdir: &str,
    argv: &[String],
) -> Vec<String> {
    let mut command = vec!["exec".to_owned()];
    if let Some(user) = user {
        command.push("--user".to_owned());
        command.push(user.to_owned());
    }
    command.push("--workdir".to_owned());
    command.push(workdir.to_owned());
    command.push(name.to_owned());
    command.extend(argv.iter().cloned());
    command
}

/// Builds the confirmed-cleanup command `sbx rm --force SANDBOX`.
///
/// `--force` skips confirmation prompts and deletes sandboxes in use, which is
/// required for non-interactive cleanup.
pub fn build_remove_args(name: &str) -> Vec<String> {
    vec!["rm".to_owned(), "--force".to_owned(), name.to_owned()]
}

/// One sandbox row parsed from `sbx ls --json`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedSandbox {
    /// The sandbox name.
    pub name: String,
    /// The lowercased sandbox status.
    pub status: String,
}

/// Parses the tolerant `sbx ls --json` shape.
///
/// The reference programmatic driver accepts either a top-level array or an
/// object wrapping arrays under `sandboxes`, `items`, `data`, or `results`,
/// and per-item field variants for the name and status. This parser accepts
/// the same variants so `sbx` output renames do not break the adapter.
pub fn parse_sandbox_list(body: &str) -> Result<Vec<ListedSandbox>, ()> {
    let value = serde_json::from_str::<serde_json::Value>(body).map_err(|_| ())?;
    let items = match value {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(map) => ["sandboxes", "items", "data", "results"]
            .into_iter()
            .find_map(|key| match map.get(key) {
                Some(serde_json::Value::Array(items)) => Some(items.clone()),
                _ => None,
            })
            .ok_or(())?,
        _ => return Err(()),
    };
    let mut sandboxes = Vec::with_capacity(items.len());
    for item in items {
        let serde_json::Value::Object(fields) = item else {
            continue;
        };
        let Some(name) = first_string(&fields, &["name", "Name", "sandboxName", "sandbox_name"])
        else {
            continue;
        };
        let status = first_string(&fields, &["status", "state", "Status", "State"])
            .unwrap_or_default()
            .to_ascii_lowercase();
        sandboxes.push(ListedSandbox { name, status });
    }
    Ok(sandboxes)
}

fn first_string(
    fields: &serde_json::Map<String, serde_json::Value>,
    keys: &[&str],
) -> Option<String> {
    keys.iter().find_map(|key| match fields.get(*key) {
        Some(serde_json::Value::String(value)) => Some(value.clone()),
        _ => None,
    })
}

/// Parses the `sbx version` output into `(major, minor, patch)`.
///
/// Accepts the observed `sbx version: v0.38.0 <commit>` shape and any output
/// containing a `v<major>.<minor>.<patch>` token.
pub fn parse_sbx_version(output: &str) -> Option<(u32, u32, u32)> {
    output.split_whitespace().find_map(|token| {
        let token = token.strip_prefix('v')?;
        let mut parts = token.split('.');
        let major = parts.next()?.parse::<u32>().ok()?;
        let minor = parts.next()?.parse::<u32>().ok()?;
        let patch = parts.next()?.parse::<u32>().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some((major, minor, patch))
    })
}

/// Returns whether a parsed version meets the supported baseline.
pub fn supported_sbx_version(version: (u32, u32, u32)) -> bool {
    version >= MIN_SUPPORTED_SBX_VERSION
}

/// Classifies a non-zero `sbx` stderr body into stable hints.
///
/// Matching is deliberately conservative: only distinctive Docker Sandboxes
/// phrases are recognized, and every hint is consumed as a boolean so raw
/// stderr never leaves this module.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SbxStderrHints {
    /// The output indicates the Docker account is not authenticated.
    pub authentication: bool,
    /// The output indicates a sandbox is absent ("no such sandbox").
    pub absent: bool,
    /// The output loosely indicates absence ("not found").
    pub absent_loose: bool,
}

/// Classifies a non-zero `sbx` stderr body.
pub fn classify_stderr(stderr: &[u8]) -> SbxStderrHints {
    let text = String::from_utf8_lossy(stderr).to_ascii_lowercase();
    SbxStderrHints {
        authentication: [
            "sign in to docker",
            "not authenticated",
            "401 unauthorized",
            "no valid user session",
        ]
        .iter()
        .any(|marker| text.contains(marker)),
        absent: text.contains("no such sandbox"),
        absent_loose: ["no such sandbox", "not found"]
            .iter()
            .any(|marker| text.contains(marker)),
    }
}

/// Returns whether a request-owned identifier is usable as an `sbx` sandbox
/// name. The `sbx` name charset is letters, numbers, hyphens, periods, plus
/// signs and minus signs; `sbx-<15-hex>` always qualifies.
pub fn valid_sandbox_name(request_id: &RequestOwnedId) -> bool {
    request_id
        .as_str()
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'+'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argv_construction_matches_the_documented_cli_surface() {
        assert_eq!(build_version_args(), ["version"]);
        assert_eq!(build_list_args(), ["ls", "--json"]);
        assert_eq!(
            build_remove_args("sbx-000000000000000"),
            ["rm", "--force", "sbx-000000000000000"]
        );
        assert_eq!(
            build_create_args(
                "sbx-000000000000000",
                "example.invalid/proof@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "/workspace",
            ),
            [
                "create",
                "--name",
                "sbx-000000000000000",
                "--template",
                "example.invalid/proof@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--quiet",
                "shell",
                "/workspace",
            ]
        );
    }

    #[test]
    fn exec_argv_never_shell_quotes_and_flags_precede_the_name() {
        let argv = build_exec_args(
            "sbx-000000000000000",
            Some("sandbox"),
            "/sandbox",
            &[
                "/bin/proof".to_owned(),
                String::new(),
                "a b".to_owned(),
                "$HOME".to_owned(),
                "semi;colon".to_owned(),
                "--flag".to_owned(),
            ],
        );
        assert_eq!(
            argv,
            [
                "exec",
                "--user",
                "sandbox",
                "--workdir",
                "/sandbox",
                "sbx-000000000000000",
                "/bin/proof",
                "",
                "a b",
                "$HOME",
                "semi;colon",
                "--flag",
            ]
        );
    }

    #[test]
    fn exec_argv_omits_user_when_unset() {
        let argv = build_exec_args(
            "sbx-000000000000000",
            None,
            "/sandbox",
            &["true".to_owned()],
        );
        assert_eq!(
            argv,
            [
                "exec",
                "--workdir",
                "/sandbox",
                "sbx-000000000000000",
                "true"
            ]
        );
    }

    #[test]
    fn list_json_accepts_array_and_wrapper_shapes() {
        let array = r#"[{"name":"sbx-a","status":"running"},{"Name":"sbx-b","State":"Stopped"}]"#;
        assert_eq!(
            parse_sandbox_list(array).unwrap(),
            [
                ListedSandbox {
                    name: "sbx-a".to_owned(),
                    status: "running".to_owned(),
                },
                ListedSandbox {
                    name: "sbx-b".to_owned(),
                    status: "stopped".to_owned(),
                },
            ]
        );

        let wrapped = r#"{"sandboxes":[{"sandboxName":"sbx-c","status":"RUNNING"}],"unused":[]}"#;
        assert_eq!(
            parse_sandbox_list(wrapped).unwrap(),
            [ListedSandbox {
                name: "sbx-c".to_owned(),
                status: "running".to_owned(),
            }]
        );

        let nested = r#"{"items":[{"name":"sbx-d","status":"starting"}]}"#;
        assert_eq!(
            parse_sandbox_list(nested).unwrap(),
            [ListedSandbox {
                name: "sbx-d".to_owned(),
                status: "starting".to_owned(),
            }]
        );
    }

    #[test]
    fn list_json_ignores_unparseable_records_and_rejects_bad_documents() {
        assert_eq!(
            parse_sandbox_list(r#"[{"name":"sbx-a","status":"running"},{"status":"no-name"},42]"#)
                .unwrap(),
            [ListedSandbox {
                name: "sbx-a".to_owned(),
                status: "running".to_owned(),
            }]
        );
        assert!(parse_sandbox_list("not json").is_err());
        assert!(parse_sandbox_list(r#"{"sandboxes":"not-an-array"}"#).is_err());
        assert!(parse_sandbox_list(r#""a string""#).is_err());
    }

    #[test]
    fn version_parsing_accepts_observed_output_and_rejects_garbage() {
        assert_eq!(
            parse_sbx_version("sbx version: v0.38.0 c022b14634c4bea846ca12870d1d5e97d5868b54"),
            Some((0, 38, 0))
        );
        assert_eq!(parse_sbx_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_sbx_version(""), None);
        assert_eq!(parse_sbx_version("sbx version: 0.38.0"), None);
        assert_eq!(parse_sbx_version("v1.2"), None);
        assert_eq!(parse_sbx_version("v1.2.3.4"), None);
        assert_eq!(parse_sbx_version("vx.y.z"), None);
    }

    #[test]
    fn supported_version_boundary_is_inclusive() {
        assert!(supported_sbx_version((0, 31, 3)));
        assert!(supported_sbx_version((0, 38, 0)));
        assert!(supported_sbx_version((1, 0, 0)));
        assert!(!supported_sbx_version((0, 31, 2)));
        assert!(!supported_sbx_version((0, 30, 0)));
    }

    #[test]
    fn stderr_classification_recognizes_auth_and_absence_without_leaking_text() {
        let auth = classify_stderr(b"ERROR: 401 Unauthorized: user is not authenticated to Docker\nSign in with: sbx login");
        assert!(auth.authentication);
        assert!(!auth.absent);

        let missing = classify_stderr(b"no such sandbox: sbx-000000000000000");
        assert!(missing.absent);
        assert!(missing.absent_loose);

        let loose = classify_stderr(b"error: sandbox not found");
        assert!(!loose.absent);
        assert!(loose.absent_loose);

        let command_output = classify_stderr(b"sh: nonexistent-cmd: command not found");
        assert!(!command_output.absent);
        assert!(command_output.absent_loose);

        assert_eq!(classify_stderr(b""), SbxStderrHints::default());
    }

    #[test]
    fn request_owned_ids_are_valid_sandbox_names() {
        let id = RequestOwnedId::parse("sbx-000000000000000").unwrap();
        assert!(valid_sandbox_name(&id));
    }
}
