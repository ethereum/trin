use std::error::Error;

use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn Error>> {
    EmitBuilder::builder()
        .git_sha(true)
        .git_describe(false, true, None)
        .build_timestamp()
        .rustc_semver()
        .cargo_features()
        .cargo_target_triple()
        .emit()?;
    Ok(())
}
