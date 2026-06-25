#![cfg(feature = "server")]

use kettle::server::job::{JobRegistry, ServerJobState};

#[tokio::test]
async fn registry_one_shot_gate() {
    let reg = JobRegistry::new();
    let id1 = reg.try_register().expect("first registration must succeed");
    let second = reg.try_register();
    assert!(second.is_err(), "second registration must fail: {second:?}");
    let job = reg.get(&id1).expect("registered job must be retrievable");
    assert!(matches!(*job.state.lock().await, ServerJobState::Building));
}

#[tokio::test]
async fn registry_get_unknown_returns_none() {
    let reg = JobRegistry::new();
    assert!(reg.get("nope").is_none());
}
