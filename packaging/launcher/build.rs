fn main() {
    for name in &[
        "fetch-openshell-deps.sh",
        "provision-local-sandbox.sh",
    ] {
        println!("cargo:rerun-if-changed=scripts/{name}");
    }
}
