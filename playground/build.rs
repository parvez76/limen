// The playground reports the compiler version it was built from.
fn main() {
    let toml = std::fs::read_to_string("../Cargo.toml").expect("../Cargo.toml");
    let v = toml.lines().find_map(|l| l.strip_prefix("version = \"")).and_then(|r| r.strip_suffix('"')).expect("version");
    println!("cargo:rustc-env=LIMEN_VERSION={v}");
    println!("cargo:rerun-if-changed=../Cargo.toml");
}
