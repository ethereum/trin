use std::{env, error::Error};

use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn Error>> {
    EmitBuilder::builder()
        .git_sha(true)
        .git_describe(false, true, None)
        .build_timestamp()
        .rustc_semver()
        .cargo_features()
        .cargo_target_triple()
        .emit_and_set()?;

    // Set short SHA
    let sha = env::var("VERGEN_GIT_SHA")?;
    let short_sha = &sha[0..7];
    println!("cargo:rustc-env=VERGEN_GIT_SHA_SHORT={short_sha}");

    // Trin's version is the same as the git tag.
    let git_describe = env::var("VERGEN_GIT_DESCRIBE")?;
    let trin_version = git_describe.split('-').collect::<Vec<&str>>()[0];
    println!("cargo:rustc-env=TRIN_VERSION={}", trin_version);

    let cargo_target_triple = env::var("VERGEN_CARGO_TARGET_TRIPLE")?;
    let target_triple = cargo_target_triple.split('-').collect::<Vec<&str>>();
    let build_architecture = target_triple[0];
    let build_operating_system = target_triple[2];

    // The operating system of the build, linux, macos, windows etc.
    println!("cargo:rustc-env=TRIN_BUILD_OPERATING_SYSTEM={build_operating_system}");

    // The architecture of the build, x86_64, aarch64, etc.
    println!("cargo:rustc-env=TRIN_BUILD_ARCHITECTURE={build_architecture}");

    println!(
        "cargo:rustc-env=TRIN_FULL_VERSION={}",
        format_args!(
            "{version}-{hash} {build_os}-{build_arch} rustc{rust_version}",
            version = trin_version,
            hash = short_sha,
            build_os = build_operating_system,
            build_arch = build_architecture,
            rust_version = env::var("VERGEN_RUSTC_SEMVER")?
        )
    );

    Ok(())
}
