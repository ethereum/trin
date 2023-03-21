use std::env;
use std::process::Command;

fn main() {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .expect("Unable to get git hash");
    let output = String::from_utf8(output.stdout)
        .expect("git rev-parse output must be a valid utf8 encoding")
        .replace('\n', "");
    let git_hash = match output.len() {
        40 => output,
        _ => {
            // If the git hash is not 40 characters, then we are probably in a
            // docker build context, in which case we access the git hash via the
            // environment variable set in the Docker build command
            match env::var("GIT_HASH") {
                Ok(val) => match val.len() {
                    40 => val,
                    _ => "".to_string(),
                },
                Err(_) => "".to_string(),
            }
        }
    };
    // Printing to stdout is how build scripts communicate with cargo
    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#outputs-of-the-build-script
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
}
