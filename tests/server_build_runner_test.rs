#![cfg(feature = "server")]

use kettle::api::{BuildRequest, BuildResult, Event};
use kettle::server::api::JobRunner;
use kettle::server::job::JobRegistry;
use kettle::server::runner::BuildRunner;

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
        source_name: None,
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

#[tokio::test]
async fn runner_emits_build_event_during_pipeline() {
    // Build a minimal cargo project on disk (with .git), tarball it, submit it.
    // The cargo build itself will fail (no src/), but the runner should still
    // emit Event::Build before reaching T::run_build.
    fn have(cmd: &str) -> bool {
        std::process::Command::new(cmd)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
    if !have("cargo") || !have("rustc") || !have("git") {
        eprintln!("skipping: cargo/rustc/git not available");
        return;
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let project = tmp.path().join("proj");
    fs_err::create_dir_all(&project).unwrap();
    fs_err::write(
        project.join("Cargo.lock"),
        "# auto-generated\nversion = 4\n",
    )
    .unwrap();
    fs_err::write(
        project.join("Cargo.toml"),
        "[package]\nname = \"x\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
    )
    .unwrap();

    fn git(dir: &std::path::Path, args: &[&str]) {
        let out = std::process::Command::new("git")
            .args(args)
            .current_dir(dir)
            .output()
            .expect("git");
        assert!(
            out.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    git(&project, &["init", "-q"]);
    git(&project, &["config", "user.email", "t@example.com"]);
    git(&project, &["config", "user.name", "test"]);
    git(&project, &["add", "-A"]);
    git(&project, &["commit", "-q", "-m", "init"]);

    let mut tar_gz = Vec::new();
    {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let enc = GzEncoder::new(&mut tar_gz, Compression::fast());
        let mut builder = tar::Builder::new(enc);
        builder.append_dir_all("proj", &project).unwrap();
        builder.into_inner().unwrap().finish().unwrap();
    }

    let registry = JobRegistry::new();
    let runner = BuildRunner::new();

    let req = BuildRequest {
        nonce: "00".into(),
        repo_url: None,
        repo_ref: None,
        source_data: Some(tar_gz),
        source_name: None,
    };
    let id = registry
        .try_register_with_nonce(req.nonce.clone())
        .unwrap();
    runner.spawn(registry.clone(), id.clone(), req);

    let job = registry.get(&id).unwrap();
    for _ in 0..600 {
        if job.is_terminal().await {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let events = job.snapshot_events().await;
    assert!(
        events.iter().any(|e| matches!(e, Event::Build { .. })),
        "expected at least one Build event, got {events:?}"
    );
}

#[tokio::test]
async fn runner_streams_build_output_line_by_line() {
    use kettle::api::Event;

    fn have(cmd: &str) -> bool {
        std::process::Command::new("which").arg(cmd).output()
            .map(|o| o.status.success()).unwrap_or(false)
    }
    if !have("cargo") || !have("rustc") || !have("git") {
        eprintln!("skipping: cargo/rustc/git not available");
        return;
    }

    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path();
    fs_err::write(path.join("Cargo.toml"),
        b"[package]\nname = \"t\"\nversion = \"0.0.1\"\nedition = \"2024\"\n").unwrap();
    fs_err::write(path.join("Cargo.lock"), b"# auto\nversion = 4\n").unwrap();
    fs_err::create_dir_all(path.join("src")).unwrap();
    fs_err::write(path.join("src/main.rs"), b"fn main() { println!(\"hi\"); }").unwrap();
    let _ = std::process::Command::new("git").arg("init").arg(path).output();
    let _ = std::process::Command::new("git").arg("-C").arg(path).arg("add").arg(".").output();
    let _ = std::process::Command::new("git")
        .arg("-C").arg(path)
        .args(["-c","user.name=t","-c","user.email=t@t","commit","-m","x"])
        .output();

    // Tarball it.
    let mut tar_gz = Vec::new();
    {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        let enc = GzEncoder::new(&mut tar_gz, Compression::fast());
        let mut builder = tar::Builder::new(enc);
        builder.append_dir_all("proj", path).unwrap();
        builder.into_inner().unwrap().finish().unwrap();
    }

    let registry = JobRegistry::new();
    let runner = BuildRunner::new();
    let req = BuildRequest {
        nonce: "00".into(),
        repo_url: None, repo_ref: None,
        source_data: Some(tar_gz),
        source_name: None,
    };
    let id = registry.try_register_with_nonce(req.nonce.clone()).unwrap();
    runner.spawn(registry.clone(), id.clone(), req);

    let job = registry.get(&id).unwrap();
    for _ in 0..1200 {
        if job.is_terminal().await { break; }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let events = job.snapshot_events().await;
    let build_events: Vec<_> = events.iter()
        .filter(|e| matches!(e, Event::Build { .. }))
        .collect();
    assert!(
        build_events.len() > 2,
        "expected more than 2 Build events (start, end, and >=1 streamed line), got {}: {:?}",
        build_events.len(), build_events
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
