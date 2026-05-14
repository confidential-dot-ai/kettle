#![cfg(feature = "server")]

use kettle::api::{BuildRequest, Event, BuildResult};
use kettle::server::runner::BuildRunner;
use kettle::server::job::JobRegistry;
use kettle::server::api::JobRunner;

#[tokio::test]
async fn runner_emits_complete_failed_on_empty_dir_project() {
    // Send a tarball containing only an empty directory.
    // The build pipeline cannot detect a toolchain, so it must fail and emit Complete{Failed}.
    let registry = JobRegistry::new();
    let runner = BuildRunner::new();

    let tar_bytes = make_empty_dir_targz();
    let req = BuildRequest {
        nonce: "00".into(),
        repo_url: None,
        repo_ref: None,
        source_data: Some(tar_bytes),
    };

    let id = registry.try_register_with_nonce(req.nonce.clone()).unwrap();
    runner.spawn(registry.clone(), id.clone(), req);

    let job = registry.get(&id).unwrap();
    for _ in 0..200 {
        if job.is_terminal().await { break; }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(job.is_terminal().await, "runner did not finish");
    let events = job.snapshot_events().await;
    let last = events.last().expect("at least one event");
    assert!(
        matches!(last, Event::Complete { result: BuildResult::Failed { .. } }),
        "expected failure complete event, got {last:?}"
    );
}

fn make_empty_dir_targz() -> Vec<u8> {
    use flate2::{Compression, write::GzEncoder};
    let mut gz = GzEncoder::new(Vec::new(), Compression::fast());
    {
        let mut tar = tar::Builder::new(&mut gz);
        let mut hdr = tar::Header::new_gnu();
        hdr.set_path("x/").unwrap();
        hdr.set_size(0);
        hdr.set_entry_type(tar::EntryType::Directory);
        hdr.set_cksum();
        tar.append(&hdr, std::io::empty()).unwrap();
        tar.finish().unwrap();
    }
    gz.finish().unwrap()
}
