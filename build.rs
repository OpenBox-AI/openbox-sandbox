use std::path::PathBuf;

const OPENSHELL_GIT_URL: &str = "https://github.com/NVIDIA/OpenShell.git";

/// Read the `OpenShell` revision from the dependency that cargo actually
/// resolves, so the pin has one source of truth.
///
/// This replaces three assertions that string-matched Cargo.toml, Cargo.lock
/// and the launcher against a constant duplicated here. A value that is read
/// cannot disagree with itself.
fn openshell_pin(manifest: &str) -> String {
    let marker = format!("git = \"{OPENSHELL_GIT_URL}\"");
    for line in manifest.lines() {
        if !line.contains(&marker) {
            continue;
        }
        if let Some(value) = line
            .split("rev = \"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
        {
            return value.to_owned();
        }
    }
    panic!("no OpenShell dependency with a rev in Cargo.toml");
}

fn main() {
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let manifest_path = root.join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", manifest_path.display());

    let manifest = std::fs::read_to_string(manifest_path).expect("Cargo.toml must be readable");
    let pin = openshell_pin(&manifest);
    println!("cargo:rustc-env=OPENBOX_OPENSHELL_SOURCE_PIN={pin}");
}
