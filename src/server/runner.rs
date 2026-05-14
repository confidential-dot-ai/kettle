use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use tokio::sync::mpsc;

use crate::api::{BuildRequest, BuildResult, Event};
use crate::server::api::JobRunner;
use crate::server::job::{JobRegistry, ServerJob};
use crate::toolchain::EventSink;

pub struct BuildRunner;

impl BuildRunner {
    pub fn new() -> Arc<Self> { Arc::new(Self) }
}

impl JobRunner for BuildRunner {
    fn spawn(&self, registry: Arc<JobRegistry>, job_id: String, req: BuildRequest) {
        tokio::spawn(async move {
            let job = registry.get(&job_id).expect("job just registered");
            if let Err(err) = run_build(job.clone(), req).await {
                let err_msg = err.to_string();
                job.push_event(Event::Complete {
                    result: BuildResult::Failed {
                        error: err_msg.clone(),
                        error_type: "BuildFailed".into(),
                    },
                }).await;
                job.mark_failed(err_msg, "BuildFailed".into()).await;
            }
        });
    }
}

async fn run_build(job: Arc<ServerJob>, req: BuildRequest) -> Result<()> {
    let work_dir = tempfile::tempdir()?;
    let work_dir_path = work_dir.path().to_path_buf();

    let (tx, mut rx) = mpsc::channel(256);
    let sink = EventSink::channel(tx);

    // Forward events from sink → job.
    let job_for_fwd = job.clone();
    let fwd = tokio::spawn(async move {
        while let Some(e) = rx.recv().await {
            job_for_fwd.push_event(e).await;
        }
    });

    let project_dir = materialize_source(&req, &work_dir_path).await?;
    let nonce = req.nonce.clone();

    let sink_clone = sink.clone();
    let project_dir_clone = project_dir.clone();
    let _: () = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        #[cfg(feature = "attest")]
        {
            let args = crate::commands::attest::AttestArgs {
                path: project_dir_clone,
                nonce: Some(nonce),
            };
            futures::executor::block_on(
                crate::commands::attest::attest_with_sink(args, &sink_clone)
            )?;
        }
        #[cfg(not(feature = "attest"))]
        {
            let _ = nonce; // explicitly drop unused
            crate::commands::build::build_with_sink(&project_dir_clone, &sink_clone)?;
        }
        Ok(())
    }).await??;

    drop(sink); // close sender → forwarding task exits
    let _ = fwd.await;

    let kettle_build = project_dir.join("kettle-build");
    let tarball = tar_dir(&kettle_build)?;
    job.result.set(tarball).map_err(|_| anyhow::anyhow!("result already set"))?;

    job.push_event(Event::Complete { result: BuildResult::Ok }).await;
    job.mark_done().await;

    // keep work_dir alive until here
    drop(work_dir);
    Ok(())
}

async fn materialize_source(req: &BuildRequest, work_dir: &PathBuf) -> Result<PathBuf> {
    if let Some(data) = &req.source_data {
        unpack_source(data, work_dir)?;
    } else if let Some(url) = &req.repo_url {
        clone_repo(url, req.repo_ref.as_deref(), work_dir)?;
    } else {
        anyhow::bail!("no source");
    }
    find_project_dir(work_dir)
}

fn unpack_source(data: &[u8], work_dir: &PathBuf) -> Result<()> {
    if data.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        let reader = std::io::Cursor::new(data);
        let mut z = zip::ZipArchive::new(reader)?;
        z.extract(work_dir)?;
    } else if data.starts_with(&[0x1F, 0x8B]) {
        let gz = GzDecoder::new(std::io::Cursor::new(data));
        let mut archive = tar::Archive::new(gz);
        archive.unpack(work_dir)?;
    } else {
        anyhow::bail!("source_data is neither zip (PK) nor gzip (1f8b)");
    }
    Ok(())
}

fn clone_repo(url: &str, repo_ref: Option<&str>, work_dir: &PathBuf) -> Result<()> {
    let mut args = vec!["clone"];
    if let Some(r) = repo_ref {
        args.push("--revision");
        args.push(r);
    }
    args.extend(["--depth", "1", "--", url]);
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(work_dir)
        .output()?;
    if !out.status.success() {
        anyhow::bail!("git clone failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

fn find_project_dir(work_dir: &PathBuf) -> Result<PathBuf> {
    let entries: Vec<_> = std::fs::read_dir(work_dir)?
        .filter_map(|e| e.ok())
        .collect();
    if entries.len() == 1
        && entries[0].file_type().map(|t| t.is_dir()).unwrap_or(false)
    {
        return Ok(entries[0].path());
    }
    Ok(work_dir.clone())
}

fn tar_dir(dir: &PathBuf) -> Result<tempfile::TempPath> {
    let f = tempfile::NamedTempFile::new()?;
    {
        let enc = GzEncoder::new(f.as_file(), Compression::fast());
        let mut builder = tar::Builder::new(enc);
        builder.append_dir_all(".", dir)?;
        builder.into_inner()?.finish()?;
    }
    Ok(f.into_temp_path())
}
