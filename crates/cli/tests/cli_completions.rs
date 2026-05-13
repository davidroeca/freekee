//! Smoke tests for `freekee completions <SHELL>`. Each supported
//! shell must produce non-empty completion output on stdout.

#![allow(clippy::disallowed_methods, clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;

fn freekee() -> Command {
    Command::cargo_bin("freekee").expect("cargo bin freekee")
}

#[test]
fn completions_bash_emits_non_empty_script() {
    freekee()
        .arg("completions")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not())
        // The clap_complete bash backend names the function `_freekee`.
        .stdout(predicate::str::contains("_freekee"));
}

#[test]
fn completions_zsh_emits_non_empty_script() {
    freekee()
        .arg("completions")
        .arg("zsh")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not())
        .stdout(predicate::str::contains("#compdef freekee"));
}

#[test]
fn completions_fish_emits_non_empty_script() {
    freekee()
        .arg("completions")
        .arg("fish")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not())
        .stdout(predicate::str::contains("complete -c freekee"));
}

#[test]
fn completions_powershell_emits_non_empty_script() {
    freekee()
        .arg("completions")
        .arg("powershell")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not())
        .stdout(predicate::str::contains("freekee"));
}

#[test]
fn completions_elvish_emits_non_empty_script() {
    freekee()
        .arg("completions")
        .arg("elvish")
        .assert()
        .success()
        .stdout(predicate::str::is_empty().not())
        .stdout(predicate::str::contains("freekee"));
}

#[test]
fn completions_unknown_shell_rejected() {
    freekee()
        .arg("completions")
        .arg("nonshell")
        .assert()
        .failure();
}
