use std::path::PathBuf;

const OPENSHELL_SOURCE_PIN: &str = "f169084923503a02a94425857b938de2841cab0c";
const OPENSHELL_GIT_URL: &str = "https://github.com/NVIDIA/OpenShell.git";

fn main() {
    let root = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let manifest_path = root.join("Cargo.toml");
    let lock_path = root.join("Cargo.lock");
    let installer_path = root.join("install.sh");
    let local_bootstrap_path = root.join("scripts/local-bootstrap.sh");
    for path in [
        &manifest_path,
        &lock_path,
        &installer_path,
        &local_bootstrap_path,
    ] {
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

    let installer = std::fs::read_to_string(installer_path).expect("install.sh must be readable");
    let installer_pin = format!("readonly OPENSHELL_SOURCE_PIN=\"{OPENSHELL_SOURCE_PIN}\"");
    assert!(
        installer.contains(&installer_pin),
        "installer OpenShell package pin must match the compiled adapter"
    );
    let local_bootstrap =
        std::fs::read_to_string(local_bootstrap_path).expect("local bootstrap must be readable");
    assert!(
        local_bootstrap.contains(&installer_pin),
        "local bootstrap OpenShell source pin must match the compiled adapter"
    );

    println!("cargo:rustc-env=OPENBOX_OPENSHELL_SOURCE_PIN={OPENSHELL_SOURCE_PIN}");
}
