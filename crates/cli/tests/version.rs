//! End to end: `mozu --version`, which the release workflow checks against the tag (ADR 0025).

use std::error::Error;
use std::process::Command;

#[test]
fn version_names_the_tool_mozu() -> Result<(), Box<dyn Error>> {
    let out = Command::new(env!("CARGO_BIN_EXE_mozu"))
        .arg("--version")
        .output()?;
    assert!(out.status.success());
    assert_eq!(
        String::from_utf8(out.stdout)?,
        format!("mozu {}\n", env!("CARGO_PKG_VERSION"))
    );
    Ok(())
}
