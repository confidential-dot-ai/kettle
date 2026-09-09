//! Build tools run untrusted repository code inside the attested VM. The
//! server holds the `sev-guest` group so it can open `/dev/sev-guest` and
//! produce SNP reports; a build that inherited that group could mint genuine
//! reports over attacker-chosen data. Every build child therefore drops its
//! supplementary groups and ambient capabilities before exec, and refuses to
//! start if it could still reach the device.

use std::io;
use std::process::{Child, Command};

/// Spawn `cmd` with the confinement applied. Use this for anything that
/// executes code from the repository being built.
pub(crate) fn spawn(cmd: &mut Command) -> io::Result<Child> {
    confine(cmd);
    cmd.spawn().map_err(explain)
}

#[cfg(target_os = "linux")]
fn confine(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: the closure runs between fork and exec and only issues raw
    // syscalls; it neither allocates nor takes locks.
    unsafe {
        cmd.pre_exec(|| {
            // Needs CAP_SETGID, which kettle-server's unit grants. The result
            // is deliberately ignored: the access check below is the invariant.
            libc::setgroups(0, std::ptr::null());
            // Ambient capabilities survive exec, so clear them or the child
            // could put the group straight back with the inherited CAP_SETGID.
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            );
            if libc::access(c"/dev/sev-guest".as_ptr(), libc::R_OK | libc::W_OK) == 0 {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
    }
}

#[cfg(not(target_os = "linux"))]
fn confine(_cmd: &mut Command) {}

fn explain(err: io::Error) -> io::Error {
    if err.kind() != io::ErrorKind::PermissionDenied {
        return err;
    }
    io::Error::new(
        err.kind(),
        format!(
            "{err}: the program is not executable, or the build could reach \
             /dev/sev-guest (kettle-server needs CAP_SETGID from its unit to \
             drop the sev-guest group before running build tools)"
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confined_child_runs_where_no_device_is_reachable() {
        // Hosts without /dev/sev-guest (every CI runner) must be unaffected;
        // hosts with the device but without CAP_SETGID must refuse instead.
        let mut cmd = Command::new("true");
        let status = spawn(&mut cmd).expect("spawn").wait().expect("wait");
        assert!(status.success());
    }
}
