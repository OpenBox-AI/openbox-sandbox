//! The README may not promise commands the launcher does not have.
//!
//! The README advertised `obs install` for hours after that subcommand was
//! deleted. Nothing compared prose to the binary, so nothing caught it. This
//! test does, by parsing the launcher's own help text.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

/// Words that follow `obs ` in prose without naming a subcommand.
const NOT_SUBCOMMANDS: &[&str] = &["https", "launcher", "binary", "itself"];

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Subcommands the launcher declares, taken from its help text.
///
/// Parsing the source rather than running the binary keeps this test cheap and
/// avoids depending on a build artefact that may not exist yet.
fn declared_subcommands() -> BTreeSet<String> {
    let main = fs::read_to_string(repository_root().join("packaging/launcher/src/main.rs"))
        .expect("launcher main.rs must be readable");
    let mut found = BTreeSet::new();
    for line in main.lines() {
        let trimmed = line.trim_start();
        // Help lines look like: `  obs status                   Report ...`
        let Some(rest) = trimmed.strip_prefix("obs ") else {
            continue;
        };
        let Some(word) = rest.split_whitespace().next() else {
            continue;
        };
        if word
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '-')
            && !word.is_empty()
        {
            found.insert(word.to_owned());
        }
    }
    assert!(
        found.contains("provision") && found.contains("uninstall"),
        "help text parsing found no known subcommands: {found:?}"
    );
    found
}

/// Every `obs <word>` the README mentions, minus prose false positives.
fn readme_subcommands() -> BTreeSet<String> {
    let readme =
        fs::read_to_string(repository_root().join("README.md")).expect("README must be readable");
    let mut found = BTreeSet::new();
    for line in readme.lines() {
        let mut rest = line;
        while let Some(index) = rest.find("obs ") {
            let tail = &rest[index + 4..];
            let word: String = tail
                .chars()
                .take_while(|character| character.is_ascii_lowercase() || *character == '-')
                .collect();
            if !word.is_empty() && !NOT_SUBCOMMANDS.contains(&word.as_str()) {
                found.insert(word);
            }
            rest = &rest[index + 4..];
        }
    }
    found
}

#[test]
fn the_readme_only_promises_commands_the_launcher_has() {
    let declared = declared_subcommands();
    let promised = readme_subcommands();
    let missing: Vec<&String> = promised
        .iter()
        .filter(|name| !declared.contains(*name))
        .collect();
    assert!(
        missing.is_empty(),
        "README names commands the launcher does not have: {missing:?}. \
         Declared: {declared:?}"
    );
}

#[test]
fn the_readme_documents_the_commands_a_reader_needs() {
    let readme = readme_subcommands();
    for required in ["provision", "status", "uninstall"] {
        assert!(
            readme.contains(required),
            "the README should show `obs {required}`"
        );
    }
}
