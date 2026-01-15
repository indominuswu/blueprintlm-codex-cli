use codex_utils_cargo_bin::cargo_bin;
use pretty_assertions::assert_eq;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

const COMMANDS: &[&str] = &[
    "validate-tools",
    "subagent-sessions",
    "subagent-rollout-history",
    "rollout-add-subagent-session",
    "rollout-add-tool-items",
    "start-subagent-session",
    "get-rate-limits",
    "models",
    "ask",
];

fn blueprintlm_bin() -> PathBuf {
    match cargo_bin("blueprintlm-codex") {
        Ok(path) => path,
        Err(err) => panic!("failed to resolve blueprintlm-codex binary: {err}"),
    }
}

fn assert_help_exit_zero(bin: &Path, subcommand: &str) {
    let output = Command::new(bin)
        .arg(subcommand)
        .arg("--help")
        .output()
        .unwrap_or_else(|err| panic!("failed to run help for {subcommand}: {err}"));

    let status_code = output.status.code();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(
        status_code,
        Some(0),
        "help failed for {subcommand}: status={status_code:?} stdout={stdout} stderr={stderr}"
    );
}

#[test]
fn blueprintlm_commands_are_registered() {
    let bin = blueprintlm_bin();
    for &subcommand in COMMANDS {
        assert_help_exit_zero(bin.as_path(), subcommand);
    }
}
