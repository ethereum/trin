use std::process::Command;
fn main() {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("Unable to get git hash");
    let git_hash = String::from_utf8(output.stdout)
        .expect("git rev-parse output must be a valid utf8 encoding");
    // Printing to stdout is how build scripts communicate with cargo
    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#outputs-of-the-build-script
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
}
