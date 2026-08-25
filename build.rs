use std::path::PathBuf;

const OPENSHELL_SOURCE_PIN: &str = "f169084923503a02a94425857b938de2841cab0c";
const OPENSHELL_GIT_URL: &str = "https://github.com/NVIDIA/OpenShell.git";

fn main() {
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let manifest_path = root.join("Cargo.toml");
    let lock_path = root.join("Cargo.lock");
    let openshell_provision_path = root.join("packaging/launcher/src/openshell_provision.rs");
    for path in [&manifest_path, &lock_path, &openshell_provision_path] {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let manifest = std::fs::read_to_string(manifest_path).expect("Cargo.toml must be readable");
    let revision = format!("rev = \"{OPENSHELL_SOURCE_PIN}\"");
    assert_eq!(
        manifest.matches(&revision).count(),
        2,
        "both OpenShell Cargo dependencies must use the approved source pin"
    );

    let lock = std::fs::read_to_string(lock_path).expect("Cargo.lock must be readable");
    let source = format!(
        "source = \"git+{OPENSHELL_GIT_URL}?rev={OPENSHELL_SOURCE_PIN}#{OPENSHELL_SOURCE_PIN}\""
    );
    assert_eq!(
        lock.matches(&source).count(),
        2,
        "Cargo.lock must bind both OpenShell packages to the approved source pin"
    );

    let openshell_provision = std::fs::read_to_string(openshell_provision_path)
        .expect("OpenShell Rust provisioner must be readable");
    let expected_pin = format!("const OPENSHELL_SOURCE_PIN: &str = \"{OPENSHELL_SOURCE_PIN}\"");
    let expected_marker = format!(
        "const SOURCE_MARKER: &str = \"{}\"",
        &OPENSHELL_SOURCE_PIN[..8]
    );
    assert!(
        openshell_provision.contains(&expected_pin)
            && openshell_provision.contains(&expected_marker),
        "OpenShell source pin and marker must match the compiled adapter"
    );

    println!("cargo:rustc-env=OPENBOX_OPENSHELL_SOURCE_PIN={OPENSHELL_SOURCE_PIN}");
}
