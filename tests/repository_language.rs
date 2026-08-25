//! Repository language gate.
//!
//! Runs with `cargo test`, so the rule is enforced by the normal suite instead
//! of a script someone has to remember.
//!
//! The forbidden terms are assembled from fragments so this file does not
//! itself trip the check it implements.

use std::fs;
use std::path::{Path, PathBuf};

/// Directories that never carry repository prose.
const SKIPPED_DIRECTORIES: &[&str] = &[".git", "target", "node_modules", "build"];

/// Extensions whose contents are not prose and may legitimately embed the
/// letters as binary noise.
const SKIPPED_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "ico", "pdf", "tar", "gz", "zip", "lock", "dat", "bin", "so",
    "dylib", "wasm",
];

/// The one sentence allowed to name the separate showcase repository.
fn allowed_boundary() -> String {
    format!(
        "Integration {short}/showcase material belongs exclusively to the separate \
         `OpenBox-AI/openbox-sandbox-{lower}` repository and is not a dependency.",
        short = short_term_mixed(),
        lower = short_term(),
    )
}

/// `p` + `o` + `c`, never written literally.
fn short_term() -> String {
    ['p', 'o', 'c'].iter().collect()
}

fn short_term_mixed() -> String {
    ['P', 'o', 'C'].iter().collect()
}

/// The long spelling, in the three separator forms the old pattern accepted.
fn long_terms() -> Vec<String> {
    let proof = "proof";
    let of = "of";
    let concept = "concept";
    [" ", "-", "_"]
        .iter()
        .map(|separator| format!("{proof}{separator}{of}{separator}{concept}"))
        .collect()
}

fn ground_terms() -> Vec<String> {
    let ground = "ground";
    let up = "up";
    [" ", "-", "_"]
        .iter()
        .map(|separator| format!("{ground}{separator}{up}"))
        .collect()
}

fn is_word_boundary(value: Option<char>) -> bool {
    value.is_none_or(|character| !character.is_alphanumeric() && character != '_')
}

/// Find the short term only as a standalone word, so `podcast` is not a match.
fn contains_short_term(haystack: &str) -> bool {
    let needle = short_term();
    let bytes: Vec<char> = haystack.chars().collect();
    let mut start = 0;
    while let Some(found) = haystack[start..].find(&needle) {
        let index = start + found;
        let before = haystack[..index].chars().next_back();
        let prefix_length = haystack[..index].chars().count();
        let mut after_index = prefix_length + needle.chars().count();
        // A trailing plural still counts as the same term.
        if bytes.get(after_index) == Some(&'s') {
            after_index += 1;
        }
        let after = bytes.get(after_index).copied();
        if is_word_boundary(before) && is_word_boundary(after) {
            return true;
        }
        start = index + needle.len();
    }
    false
}

fn violations(haystack: &str) -> bool {
    let lowered = haystack.to_lowercase();
    if contains_short_term(&lowered) {
        return true;
    }
    long_terms()
        .iter()
        .chain(ground_terms().iter())
        .any(|term| lowered.contains(term.as_str()))
}

fn collect(directory: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy().into_owned();
        if path.is_dir() {
            if !SKIPPED_DIRECTORIES.contains(&name.as_str()) {
                collect(&path, files);
            }
        } else {
            let skip = path
                .extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| SKIPPED_EXTENSIONS.contains(&value));
            if !skip {
                files.push(path);
            }
        }
    }
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn the_repository_avoids_the_forbidden_terms() {
    let root = repository_root();
    let readme = root.join("README.md");
    let mut files = Vec::new();
    collect(&root, &mut files);

    let mut findings = Vec::new();
    for path in files {
        let Ok(body) = fs::read_to_string(&path) else {
            continue;
        };
        for (number, line) in body.lines().enumerate() {
            if !violations(line) {
                continue;
            }
            // The README carries exactly one sentence naming the separate
            // showcase repository. Nothing else may.
            if path == readme && line.trim() == allowed_boundary() {
                continue;
            }
            findings.push(format!(
                "{}:{}",
                path.strip_prefix(&root).unwrap_or(&path).display(),
                number + 1
            ));
        }
    }
    assert!(
        findings.is_empty(),
        "forbidden repository language at: {}",
        findings.join(", ")
    );
}

#[test]
fn the_readme_keeps_the_boundary_sentence() {
    let readme = fs::read_to_string(repository_root().join("README.md")).expect("README.md");
    assert!(
        readme.contains(&allowed_boundary()),
        "the README must state the showcase repository boundary"
    );
}
