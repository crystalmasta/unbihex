#![cfg(not(any(target_os = "android", target_os = "ios")))]
#![allow(clippy::unwrap_used)]

use unbihex_client_core::{Client, ClientError};

#[test]
fn a_second_process_cannot_recover_the_live_profile() {
    const TEST_PROFILE: &str = "UNBIHEX_TEST_LOCKED_PROFILE";
    if let Some(dir) = std::env::var_os(TEST_PROFILE) {
        assert!(matches!(Client::open(dir), Err(ClientError::AlreadyRunning)));
        return;
    }

    let dir = std::env::temp_dir().join(format!("unbihex-lock-test-{}", uuid::Uuid::new_v4()));
    let owner = Client::open(&dir).unwrap();
    let journal = dir.join("proxy-journal.json");
    // A valid empty journal models a running session without touching network settings.
    std::fs::write(&journal, r#"{"undo":[],"proxy_backup":null}"#).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "a_second_process_cannot_recover_the_live_profile"])
        .env(TEST_PROFILE, &dir)
        .output()
        .unwrap();
    assert!(child.status.success(), "{}", String::from_utf8_lossy(&child.stdout));
    assert!(journal.exists(), "the second process consumed a live journal");

    drop(owner);
    let owner = Client::open(&dir).unwrap();
    assert!(!journal.exists(), "a new owner did not recover the journal");
    drop(owner);
    std::fs::remove_dir_all(dir).unwrap();
}
