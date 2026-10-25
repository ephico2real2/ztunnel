//! A live PID is an integer plus a held kernel process incarnation and cgroup.
//! Node root / CRI / SPIRE remain trusted. No mountinfo or selector fallback.
use crate::{identity::WorkloadPid, inpod::WorkloadUid};
use std::io;

pub(crate) trait BoundProcess: Send + Sync {
    fn validate(&self) -> io::Result<()>;
}
pub(crate) trait ProcessBinder: Send + Sync {
    fn bind(&self, process: &WorkloadPid, uid: &WorkloadUid) -> io::Result<Box<dyn BoundProcess>>;
}
pub(crate) struct KernelProcessBinder;

pub(crate) fn canonical_uid(uid: &str) -> bool {
    uid.len() == 36
        && uid.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Return the kernel Pod UID and verify the selected container ID beneath it.
/// Handles cgroupfs and systemd UUID rendering; ignores unrelated outer host
/// cgroups, but never accepts two different Pod UIDs or container IDs.
fn verify_cgroup(raw: &[u8], uid: &str, container: &str) -> io::Result<()> {
    if !canonical_uid(uid)
        || container.len() != 64
        || !container
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("canonical Pod UID and CRI container ID required"));
    }
    let text = std::str::from_utf8(raw).map_err(|_| invalid("non-UTF8 kernel cgroup"))?;
    let mut found = false;
    for line in text.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields
            .next()
            .ok_or_else(|| invalid("invalid kernel cgroup record"))?;
        let _controllers = fields
            .next()
            .ok_or_else(|| invalid("invalid kernel cgroup record"))?;
        let path = fields
            .next()
            .ok_or_else(|| invalid("invalid kernel cgroup record"))?;
        if hierarchy.is_empty()
            || !hierarchy.bytes().all(|b| b.is_ascii_digit())
            || !path.starts_with('/')
        {
            return Err(invalid("invalid kernel cgroup record"));
        }
        for (offset, _) in path.match_indices("pod") {
            if offset > 0 && !matches!(path.as_bytes()[offset - 1], b'/' | b'-' | b'.' | b':') {
                continue;
            }
            let start = offset + 3;
            let Some(candidate) = path.get(start..start + 36) else {
                continue;
            };
            let normalized = candidate.replace('_', "-");
            if !canonical_uid(&normalized) {
                continue;
            }
            let end = start + 36;
            if end < path.len() && !matches!(path.as_bytes()[end], b'/' | b'.' | b':') {
                continue;
            }
            if normalized != uid {
                return Err(invalid("kernel cgroup Pod UID mismatch or ambiguity"));
            }
            let suffix = &path[end..];
            let mut matched_container = false;
            for token in suffix.split(|c: char| !c.is_ascii_hexdigit()) {
                if token.len() == 64 {
                    if token != container {
                        return Err(invalid("kernel cgroup container ID mismatch or ambiguity"));
                    }
                    matched_container = true;
                }
            }
            if !matched_container {
                return Err(invalid(
                    "kernel cgroup does not bind selected CRI container",
                ));
            }
            found = true;
        }
    }
    if !found {
        return Err(invalid(
            "kernel cgroup has no exact Pod UID/container binding",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        ffi::CString,
        fs::File,
        io::Read,
        mem::MaybeUninit,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        os::unix::fs::MetadataExt,
    };
    const LIMIT: u64 = 64 * 1024;
    const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;

    fn open_at(parent: i32, name: &str, flags: i32) -> io::Result<OwnedFd> {
        let name = CString::new(name).map_err(|_| invalid("invalid procfs component"))?;
        // SAFETY: CString remains live, flags do not require a mode argument.
        let fd = unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: openat returned a fresh owned descriptor.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
    fn read_at(parent: i32, name: &str) -> io::Result<Vec<u8>> {
        let fd = open_at(parent, name, libc::O_RDONLY)?;
        let file = File::from(fd);
        if !file.metadata()?.is_file() {
            return Err(invalid("procfs entry is not regular"));
        }
        let mut raw = Vec::new();
        file.take(LIMIT + 1).read_to_end(&mut raw)?;
        if raw.len() > LIMIT as usize {
            return Err(invalid("bounded procfs entry exceeded"));
        }
        Ok(raw)
    }
    fn pidfd_alive(fd: i32) -> io::Result<()> {
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: valid pointer to one pollfd; zero timeout never blocks.
        let result = unsafe { libc::poll(&mut poll, 1, 0) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if result != 0 || poll.revents != 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "held workload process exited",
            ));
        }
        Ok(())
    }
    fn start_time(raw: &[u8], pid: i32) -> io::Result<u64> {
        let text = std::str::from_utf8(raw).map_err(|_| invalid("invalid proc stat"))?;
        if !text.starts_with(&format!("{pid} (")) {
            return Err(invalid("proc stat PID mismatch"));
        }
        let end = text
            .rfind(')')
            .ok_or_else(|| invalid("invalid proc stat comm"))?;
        let fields = text[end + 1..].split_whitespace().collect::<Vec<_>>();
        if fields.len() < 20 || matches!(fields[0], "Z" | "X" | "x") {
            return Err(invalid("workload process not live"));
        }
        let ticks = fields[19]
            .parse::<u64>()
            .map_err(|_| invalid("invalid process start time"))?;
        if ticks == 0 {
            return Err(invalid("invalid process start time"));
        }
        Ok(ticks)
    }
    struct KernelBoundProcess {
        pid: i32,
        pidfd: OwnedFd,
        proc_root: OwnedFd,
        proc_pid: OwnedFd,
        proc_device: u64,
        proc_inode: u64,
        start_time: u64,
        cgroup: Vec<u8>,
        uid: String,
        container: String,
    }
    impl KernelBoundProcess {
        fn capture(pid: i32, uid: String, container: String) -> io::Result<Self> {
            if pid <= 0 {
                return Err(invalid("positive workload PID required"));
            }
            // SAFETY: pidfd_open syscall accepts this PID and zero flags.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful syscall returns a fresh owned descriptor.
            let pidfd = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            pidfd_alive(pidfd.as_raw_fd())?;
            let proc_root = open_at(libc::AT_FDCWD, "/proc", libc::O_RDONLY | libc::O_DIRECTORY)?;
            let mut stat = MaybeUninit::<libc::statfs>::uninit();
            // SAFETY: valid fd and storage for statfs; read only on success.
            if unsafe { libc::fstatfs(proc_root.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful fstatfs initialized stat.
            if unsafe { stat.assume_init() }.f_type != PROC_SUPER_MAGIC {
                return Err(invalid("kernel procfs required"));
            }
            let proc_pid = open_at(
                proc_root.as_raw_fd(),
                &pid.to_string(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
            let meta = File::from(proc_pid.try_clone()?).metadata()?;
            let start_time = start_time(&read_at(proc_pid.as_raw_fd(), "stat")?, pid)?;
            let cgroup = read_at(proc_pid.as_raw_fd(), "cgroup")?;
            verify_cgroup(&cgroup, &uid, &container)?;
            let guard = Self {
                pid,
                pidfd,
                proc_root,
                proc_pid,
                proc_device: meta.dev(),
                proc_inode: meta.ino(),
                start_time,
                cgroup,
                uid,
                container,
            };
            guard.validate()?;
            Ok(guard)
        }
    }
    impl BoundProcess for KernelBoundProcess {
        fn validate(&self) -> io::Result<()> {
            pidfd_alive(self.pidfd.as_raw_fd())?;
            let current = open_at(
                self.proc_root.as_raw_fd(),
                &self.pid.to_string(),
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
            let meta = File::from(current).metadata()?;
            if meta.dev() != self.proc_device || meta.ino() != self.proc_inode {
                return Err(invalid("workload proc incarnation changed"));
            }
            if start_time(&read_at(self.proc_pid.as_raw_fd(), "stat")?, self.pid)?
                != self.start_time
            {
                return Err(invalid("workload process start time changed"));
            }
            let cgroup = read_at(self.proc_pid.as_raw_fd(), "cgroup")?;
            verify_cgroup(&cgroup, &self.uid, &self.container)?;
            if cgroup != self.cgroup {
                return Err(invalid("workload kernel cgroup changed"));
            }
            pidfd_alive(self.pidfd.as_raw_fd())
        }
    }
    impl ProcessBinder for KernelProcessBinder {
        fn bind(
            &self,
            process: &WorkloadPid,
            uid: &WorkloadUid,
        ) -> io::Result<Box<dyn BoundProcess>> {
            let container = process
                .container_id
                .as_ref()
                .ok_or_else(|| invalid("CRI container identity absent"))?;
            if process.sandbox_id.as_deref().is_none_or(str::is_empty) {
                return Err(invalid("CRI sandbox identity absent"));
            }
            Ok(Box::new(KernelBoundProcess::capture(
                process.pid,
                uid.clone().into_string(),
                container.clone(),
            )?))
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        #[test]
        fn real_held_pidfd_detects_owned_child_exit() {
            let mut child = OwnedChild(
                std::process::Command::new("/bin/sleep")
                    .arg("30")
                    .spawn()
                    .expect("owned child"),
            );
            let pid = child.0.id() as i32;
            // The low-level descriptor lifetime is real. This test does not
            // claim this non-Kubernetes child has a Pod UID cgroup.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            assert!(
                fd >= 0,
                "pidfd_open must be supported: {}",
                io::Error::last_os_error()
            );
            let held = unsafe { OwnedFd::from_raw_fd(fd as i32) };
            pidfd_alive(held.as_raw_fd()).unwrap();
            child.0.kill().unwrap();
            child.0.wait().unwrap();
            assert!(pidfd_alive(held.as_raw_fd()).is_err());
            let mut replacement = OwnedChild(
                std::process::Command::new("/bin/sleep")
                    .arg("30")
                    .spawn()
                    .unwrap(),
            );
            assert!(
                pidfd_alive(held.as_raw_fd()).is_err(),
                "replacement cannot revive old held incarnation"
            );
            replacement.0.kill().unwrap();
            replacement.0.wait().unwrap();
        }
        #[test]
        fn stat_comm_with_parentheses_and_spaces() {
            let raw = format!(
                "123 (name with ) parens) S {} 777 0",
                vec!["0"; 18].join(" ")
            );
            assert_eq!(start_time(raw.as_bytes(), 123).unwrap(), 777);
            assert!(start_time(raw.as_bytes(), 124).is_err());
        }
        #[test]
        fn real_wrong_or_unbound_process_fails_closed() {
            let process = WorkloadPid::new(std::process::id() as i32);
            assert!(
                KernelProcessBinder
                    .bind(
                        &process,
                        &WorkloadUid::new("11111111-2222-3333-4444-555555555555".into())
                    )
                    .is_err()
            );
            let bound =
                WorkloadPid::from_cri(std::process::id() as i32, "sandbox".into(), "a".repeat(64));
            assert!(
                KernelProcessBinder
                    .bind(
                        &bound,
                        &WorkloadUid::new("00000000-0000-0000-0000-000000000000".into())
                    )
                    .is_err()
            );
        }
    }
}
#[cfg(not(target_os = "linux"))]
impl ProcessBinder for KernelProcessBinder {
    fn bind(&self, _: &WorkloadPid, _: &WorkloadUid) -> io::Result<Box<dyn BoundProcess>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SPIRE delegated process binding requires Linux pidfd/procfs",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const UID: &str = "11111111-2222-3333-4444-555555555555";
    #[test]
    fn cgroupfs_systemd_and_nested_host_prefix() {
        for path in [
            format!("/kubepods/burstable/pod{UID}/{}", "a".repeat(64)),
            format!(
                "/kubepods.slice/kubepods-burstable-pod{}.slice/cri-containerd-{}.scope",
                UID.replace('-', "_"),
                "a".repeat(64)
            ),
            format!(
                "/docker/{}/kubepods/pod{UID}/{}",
                "b".repeat(64),
                "a".repeat(64)
            ),
        ] {
            verify_cgroup(format!("0::{path}\n").as_bytes(), UID, &"a".repeat(64)).unwrap();
        }
    }
    #[test]
    fn wrong_missing_ambiguous_and_substring_binding_rejected() {
        for raw in [
            "0::/\n".to_string(),
            format!("0::/kubepods/pod{UID}/{}\n", "b".repeat(64)),
            format!(
                "0::/kubepods/pod00000000-0000-0000-0000-000000000000/{}\n",
                "a".repeat(64)
            ),
            format!("0::/pod{UID}/{}/{}\n", "a".repeat(64), "b".repeat(64)),
            format!("0::/evilpod{UID}/{}\n", "a".repeat(64)),
            format!("0::/pod{UID}extra/{}\n", "a".repeat(64)),
        ] {
            assert!(
                verify_cgroup(raw.as_bytes(), UID, &"a".repeat(64)).is_err(),
                "{raw}"
            );
        }
        let raw = format!(
            "0::/pod{UID}/{}\n1:cpu:/pod00000000-0000-0000-0000-000000000000/{}\n",
            "a".repeat(64),
            "a".repeat(64)
        );
        assert!(verify_cgroup(raw.as_bytes(), UID, &"a".repeat(64)).is_err());
    }
}
