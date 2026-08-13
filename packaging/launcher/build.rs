fn main() {
    println!("cargo:rerun-if-env-changed=OPENBOX_CHANNEL");
}
