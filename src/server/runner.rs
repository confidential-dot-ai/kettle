use std::path::{Path, PathBuf};
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

    // Inner async block so cleanup (drop(sink) + fwd.await) always runs,
    // whether the build succeeds or fails.
    let build_result: Result<()> = async {
        let project_dir = materialize_source(&req, &work_dir_path).await?;
        let nonce = req.nonce.clone();

        let sink_clone = sink.clone();
        let project_dir_clone = project_dir.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
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

        // Build success — produce tarball.
        let kettle_build = project_dir.join("kettle-build");
        anyhow::ensure!(kettle_build.is_dir(), "build did not produce kettle-build/");
        // Nest the build output under a directory named after the project that
        // was built and attested, so the downloaded tarball unpacks into its own
        // directory rather than scattering files into the current directory.
        let top_level =
            output_top_level(&project_dir, &work_dir_path, req.source_name.as_deref());
        let tarball = tar_dir(&kettle_build, &top_level)?;
        job.result.set(tarball).map_err(|_| anyhow::anyhow!("result already set"))?;
        Ok(())
    }.await;

    // ALWAYS drain the forwarder before returning so the outer spawn closure's
    // final Complete event is emitted strictly AFTER all build events.
    drop(sink); // close sender → forwarding task exits
    let _ = fwd.await;
    drop(work_dir);

    build_result?; // propagate any error to the outer spawn closure

    // Success: emit Complete{Ok} + mark_done AFTER forwarder has drained.
    job.push_event(Event::Complete { result: BuildResult::Ok }).await;
    job.mark_done().await;
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

/// Choose the directory name to nest the build output under inside the tarball.
///
/// When the source had a single top-level directory, `find_project_dir` descends
/// into it, so `project_dir` differs from `work_dir` and we use that directory's
/// name (e.g. the repo or folder name). Otherwise the source unpacked loose into
/// `work_dir`, so we fall back to the uploaded archive's name minus its
/// extension, and finally to a generic name.
fn output_top_level(project_dir: &Path, work_dir: &Path, source_name: Option<&str>) -> String {
    if project_dir != work_dir {
        if let Some(name) = project_dir.file_name().and_then(|n| n.to_str()) {
            return name.to_string();
        }
    }
    if let Some(name) = source_name {
        let stem = strip_archive_extension(name);
        if !stem.is_empty() {
            return stem.to_string();
        }
    }
    "kettle-build".to_string()
}

/// Strip a leading path and a trailing archive extension from a filename.
fn strip_archive_extension(name: &str) -> &str {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    for ext in [".tar.gz", ".tar.bz2", ".tar.xz", ".tgz", ".tbz2", ".txz", ".tar", ".zip"] {
        if let Some(stripped) = base.strip_suffix(ext) {
            return stripped;
        }
    }
    base
}

fn tar_dir(dir: &PathBuf, top_level: &str) -> Result<tempfile::TempPath> {
    let f = tempfile::NamedTempFile::new()?;
    {
        let enc = GzEncoder::new(f.as_file(), Compression::fast());
        let mut builder = tar::Builder::new(enc);
        builder.append_dir_all(top_level, dir)?;
        builder.into_inner()?.finish()?;
    }
    Ok(f.into_temp_path())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn tar_dir_nests_contents_under_top_level_directory() {
        let src = tempfile::tempdir().unwrap();
        fs_err::write(src.path().join("evidence.json"), b"{}").unwrap();
        fs_err::create_dir_all(src.path().join("artifacts")).unwrap();
        fs_err::write(src.path().join("artifacts/dist.tar.gz"), b"x").unwrap();

        let tarball = tar_dir(&src.path().to_path_buf(), "myproject").unwrap();

        let gz = GzDecoder::new(fs_err::File::open(&tarball).unwrap());
        let mut archive = tar::Archive::new(gz);
        let paths: BTreeSet<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();

        assert!(
            paths.iter().all(|p| p == "myproject" || p.starts_with("myproject/")),
            "every entry must live under myproject/, got {paths:?}"
        );
        assert!(
            paths.contains("myproject/evidence.json"),
            "evidence.json must be nested under the top-level dir, got {paths:?}"
        );
        assert!(
            paths.contains("myproject/artifacts/dist.tar.gz"),
            "nested artifacts must be preserved, got {paths:?}"
        );
    }

    #[test]
    fn output_top_level_prefers_single_top_level_directory() {
        let work = PathBuf::from("/tmp/work");
        let project = work.join("comp-graph");
        // A single top-level dir was found: use its name, ignore the archive name.
        assert_eq!(
            output_top_level(&project, &work, Some("upload.zip")),
            "comp-graph"
        );
    }

    #[test]
    fn output_top_level_falls_back_to_archive_name_without_extension() {
        let work = PathBuf::from("/tmp/work");
        // No single top-level dir: project_dir == work_dir, so use the archive name.
        assert_eq!(
            output_top_level(&work, &work, Some("my-project.tar.gz")),
            "my-project"
        );
        assert_eq!(output_top_level(&work, &work, Some("foo.zip")), "foo");
        assert_eq!(
            output_top_level(&work, &work, Some("/downloads/bar.tgz")),
            "bar"
        );
    }

    #[test]
    fn output_top_level_falls_back_to_generic_name() {
        let work = PathBuf::from("/tmp/work");
        assert_eq!(output_top_level(&work, &work, None), "kettle-build");
        // An archive name that is nothing but an extension yields no usable stem.
        assert_eq!(output_top_level(&work, &work, Some(".zip")), "kettle-build");
    }
}
