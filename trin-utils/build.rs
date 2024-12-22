use std::{fs::File, io::Write};

use shadow_rs::SdResult;

fn main() -> SdResult<()> {
    shadow_rs::new_hook(hook)?;

    Ok(())
}

fn hook(mut file: &File) -> SdResult<()> {
    let env_var_git_hash = std::env::var("GIT_HASH").unwrap_or_default();
    writeln!(file, "const ENV_GIT_HASH: &str = \"{}\";", env_var_git_hash)?;

    hook_method(file)?;

    Ok(())
}

fn hook_method(mut file: &File) -> SdResult<()> {
    let hook_fn = r#"
pub const fn short_commit() -> &'static str {
    if shadow_rs::str_get!(SHORT_COMMIT, 0).is_some() {
        return SHORT_COMMIT;
    }

    if shadow_rs::str_get!(ENV_GIT_HASH, 0).is_some() {
        ENV_GIT_HASH
    } else {
        "unknown"
    }
}"#;

    writeln!(file, "{}", hook_fn)?;
    Ok(())
}
