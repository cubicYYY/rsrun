//! Runtime core. The hot path is `create` → `start` → `delete`.
//!
//! Two-process model (default; one fork via clone3):
//!
//! ```text
//! parent                                                child
//!   │
//!   ├─ mkfifo, pre-open FIFO read-side (O_NONBLOCK)
//!   │  └─ fd inherits across clone3 (no CLOEXEC)
//!   ├─ clone3(all NS flags atomic) ──────────────────────►│
//!   │                                                    ├─ setns paths (if any)
//!   │                                                    ├─ mount(MS_PRIVATE) on /
//!   │                                                    ├─ exec mount plan
//!   │                                                    ├─ pivot_root into rootfs
//!   │                                                    ├─ sethostname / chdir
//!   │                                                    ├─ poll(POLLIN) on inherited FIFO fd
//!   │                                                    │  ◀── blocks until `start`
//!   │                                                    └─ apply caps/seccomp, execve
//!   ├─ write /run/rsrun/<id>/init.pid
//!   ├─ write state.json (status="created")
//!   └─ exit 0
//! ```
//!
//! Three-process model (only when joining an existing PID ns by path):
//!
//! ```text
//! parent          intermediate (child)        init (grandchild)
//!   │
//!   ├─ pipe2(relay)
//!   ├─ clone3 ─────►│
//!   │               ├─ setns(NEWPID, fd)
//!   │               ├─ fork() ──────────────────►│
//!   │               ├─ write(grandchild_pid) ───►│
//!   │               └─ _exit(0)                  │
//!   ├─ read init pid from relay                  │
//!   ├─ waitpid(intermediate)                     │
//!   ├─ write init.pid + state.json               ├─ (continues child_run as
//!   └─ exit 0                                    │   if it were the direct
//!                                                │   clone3 child)
//! ```
//!
//! Why the extra fork: setns(CLONE_NEWPID) only takes effect for the
//! caller's *future* children, not the caller itself. Same shape crun
//! uses (libcrun/linux.c, idx_pidns_to_join_immediately). Cost is paid
//! only on the rare PID-ns-join path; default `create` stays at one fork.
//!
//! Why the FIFO is pre-opened by the parent: under user-ns, the child's
//! mapped uid can't traverse /run/rsrun/<id>/ to open the FIFO itself
//! (the dir is owned by host root). Pre-opening sidesteps the issue and
//! also saves one open(2) on the hot path.

use crate::clone3::{clone3, CloneArgs};
use crate::plan::CompiledPlan;
use crate::spec::Spec;
use crate::state::{read_pid, write_state, ContainerPaths};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sys::signal::{kill, Signal};
use nix::sys::stat::Mode;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, execve, execvpe, mkfifo, pivot_root, sethostname, Pid};
use std::ffi::CString;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub fn cmd_create(id: &str, bundle: &Path, pid_file: Option<&Path>) -> std::io::Result<()> {
    cmd_create_with_ext(id, bundle, pid_file, crate::plan::ExtPlan::default())
}

/// Same as `cmd_create` but takes a pre-compiled `ExtPlan` (seccomp,
/// cgroup limits, hooks, device rules). The standalone `rsrun` CLI
/// builds this via `rsrun-ext`; the daemon `rsrund` passes
/// `ExtPlan::default()` so it doesn't link the heavy-side crate.
pub fn cmd_create_with_ext(
    id: &str,
    bundle: &Path,
    pid_file: Option<&Path>,
    ext: crate::plan::ExtPlan,
) -> std::io::Result<()> {
    cmd_create_full(
        id,
        bundle,
        pid_file,
        ext,
        None,
        crate::plan::CreateOpts::default(),
    )
}

/// Same as `cmd_create_with_ext` but with the `--console-socket` path
/// the engine passed plus `CreateOpts` for engine-compat flags
/// (`--preserve-fds`, `--no-pivot`). When the spec sets
/// `process.terminal = true` and a console socket is provided, the
/// runtime opens a PTY pair, sends the master fd to the engine via
/// SCM_RIGHTS, and dup2's the slave into the container's stdio.
pub fn cmd_create_full(
    id: &str,
    bundle: &Path,
    pid_file: Option<&Path>,
    ext: crate::plan::ExtPlan,
    console_socket: Option<&Path>,
    opts: crate::plan::CreateOpts,
) -> std::io::Result<()> {
    let bundle = bundle.canonicalize()?;
    let spec = Spec::from_bundle(&bundle)?;
    let mut plan = CompiledPlan::from_spec(&spec)?;
    plan.ext = ext;
    plan.console_socket = console_socket.map(|p| p.to_path_buf());
    plan.no_pivot = opts.no_pivot;

    // Validate (type, path) pairs for namespace joins before doing any
    // state-dir setup. The OCI spec requires the runtime to MUST error
    // when path's actual namespace type doesn't match the declared type.
    // We use ioctl(NS_GET_NSTYPE) on the path fd. Doing this in the
    // parent (not the child) is what propagates back as a non-zero
    // `rsrun create` exit code.
    const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
    for (kind, path) in &plan.join_namespaces {
        let nstype = match kind {
            crate::spec::NamespaceKind::Pid => libc::CLONE_NEWPID,
            crate::spec::NamespaceKind::Network => libc::CLONE_NEWNET,
            crate::spec::NamespaceKind::Mount => libc::CLONE_NEWNS,
            crate::spec::NamespaceKind::Ipc => libc::CLONE_NEWIPC,
            crate::spec::NamespaceKind::Uts => libc::CLONE_NEWUTS,
            crate::spec::NamespaceKind::Cgroup => libc::CLONE_NEWCGROUP,
            crate::spec::NamespaceKind::User => libc::CLONE_NEWUSER,
        };
        let p_c = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| std::io::Error::other("namespace path has interior NUL"))?;
        let fd = unsafe { libc::open(p_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let actual = unsafe { libc::ioctl(fd, NS_GET_NSTYPE) };
        unsafe { libc::close(fd) };
        if actual < 0 || actual as i32 != nstype {
            return Err(std::io::Error::other(format!(
                "namespace path {} does not match declared type {:?}",
                path.display(),
                kind
            )));
        }
    }

    let paths = ContainerPaths::for_id(id);
    if paths.root.exists() {
        return Err(std::io::Error::other(format!(
            "container {id} already exists"
        )));
    }
    paths.ensure()?;

    let fifo_path = paths.fifo();
    mkfifo(&fifo_path, Mode::S_IRUSR | Mode::S_IWUSR)?;
    std::fs::set_permissions(&fifo_path, std::fs::Permissions::from_mode(0o600))?;

    // Pre-build all CStrings the child needs. Allocator is forbidden after clone3.
    let rootfs_cstr = CString::new(plan.root_path.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::other("rootfs path contains NUL"))?;
    let fifo_cstr = CString::new(fifo_path.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::other("fifo path contains NUL"))?;
    // Pre-open the FIFO in the parent so the child inherits its fd. In
    // rootless mode the child runs under a mapped uid that has no
    // permission to traverse /run/rsrun/<id>/, so opening from the
    // child fails with EACCES. Pre-open dodges that, and saves the
    // child one open(2) on the hot path. Inherited fd is *not* CLOEXEC.
    let fifo_fd_inherited =
        unsafe { libc::open(fifo_cstr.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK) };
    if fifo_fd_inherited < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let err_path = paths.root.join("child.err");
    let err_cstr = CString::new(err_path.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::other("error path contains NUL"))?;
    let err_fd = unsafe {
        libc::open(
            err_cstr.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC,
            0o644,
        )
    };
    if err_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Rootless-only: a one-shot synchronization pipe so child can wait for
    // parent to write its uid_map/gid_map. In rootful mode we don't allocate
    // this pipe at all — `userns_sync_fd` stays -1 and the child never even
    // checks it (the wants_userns flag short-circuits the check).
    let mut userns_sync_pipe: [i32; 2] = [-1, -1];
    if plan.wants_userns {
        let rc = unsafe { libc::pipe2(userns_sync_pipe.as_mut_ptr(), libc::O_CLOEXEC) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let userns_read_fd = userns_sync_pipe[0];
    let userns_write_fd = userns_sync_pipe[1];

    // cgroup-v2 setup: create the directory, write all the limit knobs,
    // and stash the path for post-clone3 child-PID write. Empty if ext
    // produced no resource constraints (or rsrund called via cmd_create).
    if let Some(cgroup_dir) = plan.ext.cgroup_v2_path.as_deref() {
        // When --systemd-cgroup was passed, ask systemd to create a
        // transient .scope slice for the container. Falls back to
        // direct cgroupfs if systemd-run isn't available or fails.
        // Best-effort: if the slice already exists or creation
        // succeeded, we proceed; on failure we still mkdir the path
        // ourselves so the rest of the pipeline works.
        #[cfg(feature = "systemd-cgroup")]
        if std::env::var_os("RSRUN_SYSTEMD_CGROUP").is_some() {
            let _ = systemd_create_scope(id, cgroup_dir);
        }
        std::fs::create_dir_all(cgroup_dir)?;
        for (knob, content) in &plan.ext.cgroup_v2_writes {
            let path = cgroup_dir.join(knob);
            // Best-effort: not every controller is enabled on every host.
            // A failed write here would block container start, which is
            // worse than soft-failing on a missing knob.
            let _ = std::fs::write(&path, content);
        }
        // Attach the device cgroup BPF program (linux.resources.devices)
        // to the cgroup directory. The kernel ref-counts attached
        // programs through the cgroup, so dropping the OwnedFd here
        // does NOT detach — the program stays in force until the
        // cgroup is destroyed at delete time. Empty `device_cgroup_bpf`
        // means no rules in the spec; we skip the syscall pair entirely
        // and the cgroup-v2 default (allow everything writable from
        // parent) applies. Failures here block create — running with
        // device rules silently dropped is a security regression.
        if !plan.ext.device_cgroup_bpf.is_empty() {
            attach_device_cgroup_bpf(cgroup_dir, &plan.ext.device_cgroup_bpf)?;
        }
    }

    // OCI hook phase: createRuntime fires AFTER namespaces are created
    // but BEFORE the container process is exec'd. The conventional
    // window is between unshare and pivot_root; since rsrun creates
    // namespaces atomically via clone3, the closest equivalent is
    // right before the clone.
    run_hooks(&plan.ext.hooks.create_runtime, id)?;
    run_hooks(&plan.ext.hooks.prestart, id)?;

    // PTY allocation (when `process.terminal: true` and a console
    // socket is available). The slave fd is inherited by the child via
    // clone3; the master fd stays in the parent and is sent over the
    // console socket via SCM_RIGHTS after fork. Fast-path for the
    // no-terminal case: both fds stay -1 and no syscall happens.
    let mut pty_master_fd: i32 = -1;
    let mut pty_slave_fd: i32 = -1;
    if plan.terminal && plan.console_socket.is_some() {
        let res = nix::pty::openpty(None, None)?;
        use std::os::fd::IntoRawFd;
        pty_master_fd = res.master.into_raw_fd();
        pty_slave_fd = res.slave.into_raw_fd();
    }

    // PID-ns-by-path: setns(CLONE_NEWPID) only takes effect for the
    // calling task's *future* children. When the spec joins an existing
    // PID ns by path, the post-clone3 child must fork once more — the
    // grandchild becomes the real init, the intermediate exits. crun
    // does the same. Allocated only on this rare path; the hot create
    // path keeps `pid_relay_*` at -1 and never branches into pipe2.
    let needs_pid_join_fork = plan
        .join_namespaces
        .iter()
        .any(|(k, _)| matches!(k, crate::spec::NamespaceKind::Pid));
    let mut pid_relay_pipe: [i32; 2] = [-1, -1];
    if needs_pid_join_fork {
        if unsafe { libc::pipe2(pid_relay_pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let pid_relay_read = pid_relay_pipe[0];
    let pid_relay_write = pid_relay_pipe[1];

    // Idmapped mounts: for each `linux.mounts[].uidMappings` set,
    // spawn a helper task that creates a userns with that mapping.
    // The parent opens /proc/<helper>/ns/user and passes that fd into
    // the child; the child's mount loop calls mount_setattr(IDMAP).
    // Empty mappings → empty Vec → cost is one if-check.
    let idmap_userns_fds: Vec<i32> = spawn_idmap_helpers(&plan.mounts)?;

    // --preserve-fds: clear CLOEXEC on fds 3..=preserve_fds+2 so they
    // inherit through clone3+execve. fds 0/1/2 are the workload's
    // stdio (already non-CLOEXEC). containerd / podman pass extra
    // file descriptors after stdio; this is what `--preserve-fds`
    // reserves for them.
    if opts.preserve_fds > 0 {
        let last_fd = 2 + opts.preserve_fds as i32;
        for fd in 3..=last_fd {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags >= 0 {
                unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
            }
        }
    }

    // Build clone3 args.
    let mut args = CloneArgs {
        flags: plan.clone_flags.bits() as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..Default::default()
    };
    let pidfd: i32 = -1;
    args.pidfd = (&pidfd as *const i32) as u64;
    args.flags |= libc::CLONE_PIDFD as u64;

    // SAFETY: see child_run preconditions.
    let pid = unsafe { clone3(&args) };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }

    if pid == 0 {
        // Child path. Close the parent's write-side of the userns pipe.
        if userns_write_fd >= 0 {
            unsafe { libc::close(userns_write_fd) };
        }
        // Close the master end here in the child — only the parent
        // forwards it. -1 when no PTY was allocated.
        if pty_master_fd >= 0 {
            unsafe { libc::close(pty_master_fd) };
        }
        if pid_relay_read >= 0 {
            unsafe { libc::close(pid_relay_read) };
        }
        unsafe {
            child_run(
                &plan,
                &rootfs_cstr,
                fifo_fd_inherited,
                err_fd,
                userns_read_fd,
                pty_slave_fd,
                pid_relay_write,
                &idmap_userns_fds,
            );
        }
        unsafe { libc::_exit(127) }
    }

    // Parent: close idmap helper userns fds (the child has its own
    // copies via clone3 fd inheritance). The helper tasks themselves
    // are reaped by waitpid below or auto-reaped after exit signal.
    for &fd in &idmap_userns_fds {
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    // Parent path. Close our copy of the inherited FIFO fd; the child
    // owns it now.
    unsafe { libc::close(fifo_fd_inherited) };

    // Parent path. Close child's read-side of the userns pipe.
    if userns_read_fd >= 0 {
        unsafe { libc::close(userns_read_fd) };
    }
    if pid_relay_write >= 0 {
        unsafe { libc::close(pid_relay_write) };
    }

    // Parent's copy of the slave is unused — only the child holds it.
    if pty_slave_fd >= 0 {
        unsafe { libc::close(pty_slave_fd) };
    }

    // Forward the PTY master fd to the engine (Docker / containerd) over
    // the AF_UNIX socket it pre-bound and passed via --console-socket.
    // Once sent, the parent closes its copy; the engine drives the
    // master fd.
    if let Some(socket_path) = plan.console_socket.as_deref() {
        if pty_master_fd >= 0 {
            send_pty_master(socket_path, pty_master_fd)?;
            unsafe { libc::close(pty_master_fd) };
        }
    }

    // Rootless-only: write uid_map and gid_map for the child, then signal it.
    if plan.wants_userns {
        // setgroups must be set to "deny" before we can write a gid_map as a
        // non-root user. Required when there's only one gid mapping.
        let setgroups_path = format!("/proc/{}/setgroups", pid);
        let _ = std::fs::write(&setgroups_path, b"deny");

        let uid_map_path = format!("/proc/{}/uid_map", pid);
        std::fs::write(&uid_map_path, &plan.uid_map_data)
            .map_err(|e| std::io::Error::other(format!("write uid_map: {e}")))?;
        let gid_map_path = format!("/proc/{}/gid_map", pid);
        std::fs::write(&gid_map_path, &plan.gid_map_data)
            .map_err(|e| std::io::Error::other(format!("write gid_map: {e}")))?;

        // Tell child it can proceed.
        let one = b'1';
        let n = unsafe { libc::write(userns_write_fd, &one as *const u8 as *const _, 1) };
        unsafe { libc::close(userns_write_fd) };
        if n != 1 {
            return Err(std::io::Error::last_os_error());
        }
    }

    unsafe { libc::close(err_fd) };

    // PID-ns-by-path: the intermediate child has setns'd into the joined
    // PID ns and forked the real init, then writes the grandchild's
    // host-ns pid to the relay pipe and exits. We read the init pid
    // here, reap the intermediate, and use the grandchild pid as the
    // container's init for state.json / cgroup.procs / kill.
    let init_pid: i32 = if needs_pid_join_fork {
        let mut buf = [0u8; 4];
        let mut got = 0usize;
        while got < 4 {
            let n =
                unsafe { libc::read(pid_relay_read, buf.as_mut_ptr().add(got) as *mut _, 4 - got) };
            if n <= 0 {
                unsafe { libc::close(pid_relay_read) };
                return Err(std::io::Error::other(
                    "PID-ns join: failed to read init pid from intermediate",
                ));
            }
            got += n as usize;
        }
        unsafe { libc::close(pid_relay_read) };
        // Reap the intermediate so it doesn't linger as a zombie.
        let mut st = 0i32;
        unsafe { libc::waitpid(pid, &mut st, 0) };
        i32::from_ne_bytes(buf)
    } else {
        pid
    };

    // Move the (real) init into its cgroup-v2 group now that we know its PID.
    if let Some(cgroup_dir) = plan.ext.cgroup_v2_path.as_deref() {
        let procs = cgroup_dir.join("cgroup.procs");
        let _ = std::fs::write(&procs, init_pid.to_string());
    }

    // process.oomScoreAdj — written to /proc/<init>/oom_score_adj
    // *from the parent* now that we know the host-ns pid. We can't do
    // this in the child because PR_SET_DUMPABLE / userns mappings may
    // make the child unable to write its own oom_score_adj after the
    // user transition. Best-effort: a failed write doesn't abort
    // create (the kernel default of 0 is not security-sensitive).
    if let Some(adj) = plan.oom_score_adj {
        let path = format!("/proc/{init_pid}/oom_score_adj");
        let _ = std::fs::write(&path, adj.to_string());
    }

    std::fs::write(paths.pid_file(), init_pid.to_string())?;
    if let Some(pf) = pid_file {
        std::fs::write(pf, init_pid.to_string())?;
    }
    let pid = init_pid;
    // commHint is the basename of argv[0] truncated to 15 chars (kernel comm
    // limit). Used by `state` to detect pid reuse.
    let comm_hint = spec
        .args
        .first()
        .and_then(|s| std::path::Path::new(s).file_name().and_then(|n| n.to_str()));
    write_state(&paths, id, pid, &bundle, "created", comm_hint)?;

    // Persist hooks for `start` / `delete` to fire later. Skip writing
    // the file entirely when there are none — keeps the no-hooks path
    // free of an extra fs write.
    if !plan.ext.hooks.is_empty() {
        std::fs::write(
            paths.root.join("hooks.json"),
            serde_json::to_vec(&plan.ext.hooks.to_json())?,
        )?;
    }
    Ok(())
}

/// Load hooks persisted by `cmd_create`. Returns an empty `Hooks` if the
/// file isn't there — that's the common case.
fn load_hooks(paths: &ContainerPaths) -> crate::plan::Hooks {
    let path = paths.root.join("hooks.json");
    let Ok(bytes) = std::fs::read(&path) else {
        return crate::plan::Hooks::default();
    };
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return crate::plan::Hooks::default();
    };
    crate::plan::Hooks::from_json(&v)
}

/// Connect to the engine's AF_UNIX console socket and send the PTY
/// master fd via SCM_RIGHTS — the conventional `console.sock` protocol.
/// Payload is the path "/dev/ptmx" (any short non-empty bytes work;
/// engines just consume + drop it).
fn send_pty_master(socket_path: &Path, master_fd: i32) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path)?;
    let sock_fd = stream.as_raw_fd();

    let payload: &[u8] = b"/dev/ptmx";
    let iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut _,
        iov_len: payload.len(),
    };
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &iov as *const _ as *mut _;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut _;
    msg.msg_controllen = cmsg_buf.len();

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(std::io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg) as *mut i32;
        std::ptr::write_unaligned(data, master_fd);

        let n = libc::sendmsg(sock_fd, &msg, 0);
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Fork+exec each hook command in sequence. Failures are logged but
/// not fatal: OCI says runtime errors are reported as warnings unless
/// the hook explicitly fails. The container's `state.json` would be
/// piped to stdin for compliance — we write the minimal JSON `rsrun`
/// can construct from `id` alone.
fn run_hooks(hooks: &[crate::plan::HookCmd], id: &str) -> std::io::Result<()> {
    if hooks.is_empty() {
        return Ok(());
    }
    let state_json = format!(
        "{{\"ociVersion\":\"1.0.2\",\"id\":\"{id}\",\"status\":\"creating\",\"pid\":0,\"bundle\":\"\"}}"
    );
    for h in hooks {
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if pid == 0 {
            // Child: pipe state_json on stdin, exec the hook.
            let mut fds = [0i32; 2];
            if unsafe { libc::pipe(fds.as_mut_ptr()) } < 0 {
                unsafe { libc::_exit(64) };
            }
            unsafe {
                libc::dup2(fds[0], 0);
                libc::close(fds[0]);
                let _ = libc::write(fds[1], state_json.as_ptr() as _, state_json.len());
                libc::close(fds[1]);
            }
            let mut argv: Vec<*const libc::c_char> = h.args.iter().map(|c| c.as_ptr()).collect();
            argv.push(std::ptr::null());
            let mut envp: Vec<*const libc::c_char> = h.env.iter().map(|c| c.as_ptr()).collect();
            envp.push(std::ptr::null());
            unsafe {
                libc::execve(h.path.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
        }
        // Parent: wait, killing the hook if it exceeds its timeout.
        wait_hook_with_timeout(pid, h.timeout_ms)?;
    }
    Ok(())
}

/// Wait for `pid` to exit; if `timeout_ms` is set and the deadline
/// passes, send SIGKILL and reap. Implemented with `pidfd_open` + `poll`
/// so we don't disturb SIGCHLD or burn CPU. SIGKILL is unconditional —
/// the OCI spec calls hook timeout "implementation defined" but every
/// other runtime hard-kills.
fn wait_hook_with_timeout(pid: libc::pid_t, timeout_ms: Option<u64>) -> std::io::Result<()> {
    const SYS_PIDFD_OPEN: libc::c_long = 434;
    let mut status = 0i32;
    let Some(ms) = timeout_ms else {
        // No timeout: blocking wait with EINTR retry.
        loop {
            let r = unsafe { libc::waitpid(pid, &mut status, 0) };
            if r >= 0 {
                return Ok(());
            }
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
    };
    let pidfd = unsafe { libc::syscall(SYS_PIDFD_OPEN, pid, 0u32) } as i32;
    if pidfd < 0 {
        // Kernel < 5.3 or seccomp denied. Fall back to blocking wait —
        // honoring the timeout is best-effort on those hosts.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        return if r < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        };
    }
    let timeout = i32::try_from(ms.min(i32::MAX as u64)).unwrap_or(i32::MAX);
    let mut pfd = libc::pollfd {
        fd: pidfd,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = loop {
        let r = unsafe { libc::poll(&mut pfd, 1, timeout) };
        if r >= 0 {
            break r;
        }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        unsafe { libc::close(pidfd) };
        return Err(e);
    };
    unsafe { libc::close(pidfd) };
    if rc == 0 {
        // Timed out. SIGKILL and reap.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
        return Err(std::io::Error::other(format!(
            "hook exceeded {ms} ms timeout, killed"
        )));
    }
    let r = unsafe { libc::waitpid(pid, &mut status, 0) };
    if r < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Write a tiny diagnostic byte to a pre-opened error fd before exiting.
/// The fd is held open across pivot_root, so we can always write something.
/// Caller passes the fd; if 0 we just _exit.
unsafe fn child_die(err_fd: i32, code: i32, reason: &[u8]) -> ! {
    if err_fd > 0 {
        let prefix = b"rsrun-child: ";
        let _ = libc::write(err_fd, prefix.as_ptr() as *const _, prefix.len());
        let _ = libc::write(err_fd, reason.as_ptr() as *const _, reason.len());
        // Append errno
        let errno = *libc::__errno_location();
        let mut buf = [0u8; 32];
        let mut n = 0;
        let s = b" errno=";
        while n < s.len() {
            buf[n] = s[n];
            n += 1;
        }
        let mut e = errno;
        let mut digits = [0u8; 10];
        let mut d = 0;
        if e == 0 {
            digits[0] = b'0';
            d = 1;
        } else {
            while e > 0 && d < 10 {
                digits[d] = b'0' + (e % 10) as u8;
                e /= 10;
                d += 1;
            }
        }
        while d > 0 {
            d -= 1;
            buf[n] = digits[d];
            n += 1;
        }
        buf[n] = b'\n';
        n += 1;
        let _ = libc::write(err_fd, buf.as_ptr() as *const _, n);
    }
    libc::_exit(code);
}

/// Child code path. Runs in the new namespaces. Must not allocate, must
/// not panic. Ends with `execve` or `_exit(non-zero)`.
///
/// `userns_read_fd`: in rootless mode, fd to read 1 byte from once the parent
/// has written uid_map/gid_map. -1 in rootful mode (and unused — we check
/// `plan.wants_userns` instead, so the rootful path costs literally one
/// already-predicted branch).
unsafe fn child_run(
    plan: &CompiledPlan,
    rootfs: &CString,
    fifo_fd: i32,
    err_fd: i32,
    userns_read_fd: i32,
    pty_slave_fd: i32,
    pid_relay_write: i32,
    idmap_userns_fds: &[i32],
) -> ! {
    // Rootless: block until parent finishes uid_map / gid_map writes.
    // Rootful: this entire block is skipped (no syscalls).
    if plan.wants_userns {
        let mut byte = 0u8;
        loop {
            let n = libc::read(userns_read_fd, &mut byte as *mut u8 as *mut _, 1);
            if n == 1 {
                break;
            }
            if n == 0 {
                child_die(err_fd, 110, b"userns sync pipe closed before write");
            }
            let e = *libc::__errno_location();
            if e == libc::EINTR {
                continue;
            }
            child_die(err_fd, 110, b"read userns sync pipe failed");
        }
        libc::close(userns_read_fd);

        // After uid/gid mappings are installed, the kernel rewrites the
        // child's effective uid/gid to whatever the mappings say (typically
        // root inside the userns). We explicitly setresuid/setresgid to 0
        // so we get the full capability set inside the new userns.
        if libc::setresgid(0, 0, 0) < 0 {
            child_die(err_fd, 111, b"setresgid 0 failed");
        }
        if libc::setresuid(0, 0, 0) < 0 {
            child_die(err_fd, 111, b"setresuid 0 failed");
        }
    }

    // Join any pre-existing namespaces named via `linux.namespaces[].path`.
    // This is how rsrund hooks into pre-warmed namespace pools, and how
    // `--network=container:other` is implemented at the OCI layer. The
    // corresponding CLONE_NEW* flag was stripped from clone_flags so the
    // kernel didn't create a fresh one.
    // NS_GET_NSTYPE: ioctl on a /proc/<pid>/ns/<type> fd returns its
    // actual namespace type as a CLONE_NEW* constant. Used to reject
    // mismatched (type, path) pairs as the OCI spec requires.
    const NS_GET_NSTYPE: libc::c_ulong = 0xb703;
    let mut joined_pid_ns = false;
    for (kind, path) in &plan.join_namespaces {
        let path_c = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
            Ok(c) => c,
            Err(_) => child_die(err_fd, 112, b"namespace path has interior NUL"),
        };
        let fd = libc::open(path_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            child_die(err_fd, 112, b"open namespace path failed");
        }
        let nstype = match kind {
            crate::spec::NamespaceKind::Pid => libc::CLONE_NEWPID,
            crate::spec::NamespaceKind::Network => libc::CLONE_NEWNET,
            crate::spec::NamespaceKind::Mount => libc::CLONE_NEWNS,
            crate::spec::NamespaceKind::Ipc => libc::CLONE_NEWIPC,
            crate::spec::NamespaceKind::Uts => libc::CLONE_NEWUTS,
            crate::spec::NamespaceKind::Cgroup => libc::CLONE_NEWCGROUP,
            crate::spec::NamespaceKind::User => libc::CLONE_NEWUSER,
        };
        // Verify the path actually points to the declared type. The
        // kernel's setns() does not enforce this when called with a
        // matching nstype mask (it cross-checks but accepts any of the
        // listed flags). Compare ioctl(NS_GET_NSTYPE) against expected.
        let actual = libc::ioctl(fd, NS_GET_NSTYPE);
        if actual < 0 || actual as i32 != nstype {
            libc::close(fd);
            child_die(err_fd, 112, b"namespace path type mismatch");
        }
        if libc::setns(fd, nstype) != 0 {
            child_die(err_fd, 112, b"setns failed");
        }
        libc::close(fd);
        if matches!(kind, crate::spec::NamespaceKind::Pid) {
            joined_pid_ns = true;
        }
    }

    // setns(CLONE_NEWPID) is special: it only affects future children
    // of the calling task, not the task itself. Fork once here so the
    // grandchild becomes the real container init inside the joined PID
    // namespace. The intermediate (this process) writes the grandchild
    // pid back to the parent over the relay pipe, then exits. crun
    // does the same — see libcrun/linux.c:4863 (idx_pidns_to_join_immediately).
    if joined_pid_ns {
        let grand = libc::fork();
        if grand < 0 {
            child_die(err_fd, 119, b"fork after setns(NEWPID) failed");
        }
        if grand > 0 {
            // Intermediate: report grandchild pid (host ns) and exit.
            let bytes = (grand as i32).to_ne_bytes();
            let _ = libc::write(pid_relay_write, bytes.as_ptr() as *const _, bytes.len());
            libc::close(pid_relay_write);
            libc::_exit(0);
        }
        // Grandchild falls through and continues as the container init.
        libc::close(pid_relay_write);
    } else if pid_relay_write >= 0 {
        // Belt-and-suspenders: pipe was allocated but no PID-ns join
        // happened (shouldn't occur — parent only allocates when join
        // includes PID). Close to avoid hanging the parent's read.
        libc::close(pid_relay_write);
    }

    // FIFO synchronization: the FIFO fd was pre-opened by the parent
    // (O_RDONLY|O_NONBLOCK) and inherited across clone3 — the child
    // doesn't open it itself, which dodges the rootless permission
    // trap (state dir is owned by host root; under userns the child's
    // mapped uid can't traverse it). We poll(POLLIN) below to block
    // until `start` opens the write side and writes a byte.

    // 1. Make / private so our mount changes don't propagate back to the host.
    if let Err(_e) = mount(
        Option::<&str>::None,
        "/",
        Option::<&str>::None,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        Option::<&str>::None,
    ) {
        child_die(err_fd, 101, b"mount / private failed");
    }

    // 2. Bind the rootfs onto itself so we can pivot_root into it.
    let root_path = Path::new(std::str::from_utf8_unchecked(rootfs.as_bytes()));
    if mount(
        Some(root_path),
        root_path,
        Option::<&str>::None,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        Option::<&str>::None,
    )
    .is_err()
    {
        child_die(err_fd, 102, b"bind rootfs failed");
    }
    let mut mloop = 0u32;

    // 3. Execute the mount plan (proc, sys, dev, tmpfs, etc.) inside the new ns.
    for (idx, m) in plan.mounts.iter().enumerate() {
        mloop += 1;
        // mkdir target; we don't care if it exists
        let _ = std::fs::create_dir_all(&m.target);
        let src_str = m.source.to_str().unwrap_or("");
        let fstype_str = m.fstype.to_str().unwrap_or("");
        let data_str = m.data.as_ref().and_then(|c| c.to_str().ok());

        let src_opt = if src_str.is_empty() {
            None
        } else {
            Some(src_str)
        };
        let fstype_opt = if fstype_str.is_empty() || fstype_str == "none" {
            None
        } else {
            Some(fstype_str)
        };

        // Idmapped bind mount: bypass the regular mount() and use the
        // open_tree → mount_setattr(IDMAP) → move_mount triplet
        // instead. The kernel only accepts MOUNT_ATTR_IDMAP on a
        // freshly-detached mount tree; an already-attached bind would
        // be rejected. For non-idmap mounts we fall through to plain
        // mount(2) — the hot path is unchanged.
        if !m.idmap_uid.is_empty() && idx < idmap_userns_fds.len() && idmap_userns_fds[idx] >= 0 {
            if !apply_idmap_bind(&m.source, &m.target, idmap_userns_fds[idx]) {
                child_die(err_fd, 130, b"idmapped bind mount failed");
            }
            continue;
        }

        if mount(src_opt, &m.target, fstype_opt, m.flags, data_str).is_err() {
            // Continue on mount failure. Many spec mounts are non-essential
            // (cgroup-inside-container, /dev/mqueue on hosts that don't
            // support it). A future version will surface these as warnings.
        }
    }

    let _ = mloop; // suppress warning

    // 4. Switch root. Default path is pivot_root(2) — properly detaches
    // the host rootfs so a process inside can't escape via ../. The
    // --no-pivot fallback uses chroot(2) instead, required when
    // rootfs is on a tmpfs that can't host the put_old dir or when
    // the host rootfs is read-only. crun supports the same flag.
    if plan.no_pivot {
        let rootfs_c = std::ffi::CString::new(rootfs.as_bytes()).unwrap();
        if libc::chroot(rootfs_c.as_ptr()) != 0 {
            child_die(err_fd, 103, b"chroot failed");
        }
        if chdir("/").is_err() {
            child_die(err_fd, 104, b"chdir / failed");
        }
    } else {
        let put_old = root_path.join(".rsrun_old");
        let _ = std::fs::create_dir_all(&put_old);
        let pr_result = pivot_root(root_path, &put_old);
        if pr_result.is_err() {
            child_die(err_fd, 103, b"pivot_root failed");
        }
        if chdir("/").is_err() {
            child_die(err_fd, 104, b"chdir / failed");
        }
        // Detach the old root and remove the directory.
        if umount2("/.rsrun_old", MntFlags::MNT_DETACH).is_err() {
            child_die(err_fd, 105, b"umount old_root failed");
        }
        let _ = std::fs::remove_dir("/.rsrun_old");
    }

    // 4a. linux.rootfsPropagation: change `/`'s propagation mode after
    // pivot_root. By default rsrun set it MS_PRIVATE in step 1; this
    // overrides if the spec asked for shared/slave/etc. Skipped when
    // the spec didn't specify (flags == empty), so the no-feature path
    // pays nothing.
    if !plan.rootfs_propagation.is_empty() {
        let _ = mount(
            Option::<&str>::None,
            "/",
            Option::<&str>::None,
            plan.rootfs_propagation,
            Option::<&str>::None,
        );
    }

    // 5. Hostname (UTS namespace) — only if explicitly set in spec.
    if plan.set_hostname {
        let _ = sethostname(plan.hostname.to_str().unwrap_or(""));
    }

    // 5_pre. createContainer hooks — fire inside the container's mount
    // namespace, after pivot_root, while still root. Skipped when no
    // hooks are configured so the no-hooks path pays nothing.
    if !plan.ext.hooks.create_container.is_empty() {
        run_hooks_unsafe(&plan.ext.hooks.create_container, err_fd);
    }

    // 5a. Create OCI-default device nodes under /dev (mknod each).
    // mknod's mode argument is masked by the process umask (default 022),
    // which would turn 0666 into 0644. Set umask to 0 around the mknod
    // calls so the spec'd mode is preserved exactly.
    let prev_umask = libc::umask(0);
    for dev in &plan.default_devices {
        let dev_kind_flag = match dev.kind {
            'c' => libc::S_IFCHR,
            'b' => libc::S_IFBLK,
            _ => continue,
        };
        let mode = dev.mode | dev_kind_flag;
        let rdev = libc::makedev(dev.major as _, dev.minor as _);
        let r = libc::mknod(dev.path.as_ptr(), mode, rdev);
        if r < 0 {
            // Fallback: bind-mount host's same path.
            let _ = libc::open(dev.path.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644);
            let _ = mount(
                Some(std::str::from_utf8_unchecked(dev.path.as_bytes())),
                std::str::from_utf8_unchecked(dev.path.as_bytes()),
                Option::<&str>::None,
                MsFlags::MS_BIND,
                Option::<&str>::None,
            );
        } else {
            // mknod's behavior on the mode bits has historically been quirky;
            // chmod ensures we get exactly the requested mode regardless of
            // umask interactions.
            let _ = libc::chmod(dev.path.as_ptr(), dev.mode);
        }
    }
    libc::umask(prev_umask);

    // 5b. /dev symlinks: /dev/fd, /dev/stdin, /dev/stdout, /dev/stderr, /dev/ptmx
    for (target, link) in &plan.default_symlinks {
        let _ = libc::unlink(link.as_ptr());
        let _ = libc::symlink(target.as_ptr(), link.as_ptr());
    }

    // 5c. Masked paths: bind-mount /dev/null over each (or remount-tmpfs-ro for dirs).
    let null_src = b"/dev/null\0";
    for p in &plan.masked_paths {
        // Determine target type — if it's a directory, mount tmpfs ro on it;
        // if it's a regular file, bind-mount /dev/null. We try /dev/null first;
        // if that fails (target is a dir), fall back to tmpfs.
        let r = mount(
            Some(std::str::from_utf8_unchecked(
                &null_src[..null_src.len() - 1],
            )),
            std::str::from_utf8_unchecked(p.as_bytes()),
            Option::<&str>::None,
            MsFlags::MS_BIND,
            Option::<&str>::None,
        );
        if r.is_err() {
            // Try as tmpfs RDONLY
            let _ = mount(
                Some("tmpfs"),
                std::str::from_utf8_unchecked(p.as_bytes()),
                Some("tmpfs"),
                MsFlags::MS_RDONLY,
                Option::<&str>::None,
            );
        }
    }

    // 5d. Readonly paths: bind-mount each onto itself, then remount with MS_RDONLY.
    for p in &plan.readonly_paths {
        let path_str = std::str::from_utf8_unchecked(p.as_bytes());
        if mount(
            Some(path_str),
            path_str,
            Option::<&str>::None,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            Option::<&str>::None,
        )
        .is_ok()
        {
            let _ = mount(
                Option::<&str>::None,
                path_str,
                Option::<&str>::None,
                MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                Option::<&str>::None,
            );
        }
    }

    // 6. Optionally remount root readonly per spec.
    if plan.root_readonly {
        let _ = mount(
            Option::<&str>::None,
            "/",
            Option::<&str>::None,
            MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            Option::<&str>::None,
        );
    }

    // 6a. Apply linux.sysctl writes. /proc is mounted by step 3 (the
    // mount plan typically includes proc); we write each key. Failures
    // are non-fatal — many sysctls are namespaced but kernel-version
    // dependent. Empty list = the for loop is a no-op.
    #[cfg(feature = "sysctl")]
    for (path, value) in &plan.sysctls {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd >= 0 {
            let _ = libc::write(fd, value.as_ptr() as *const _, value.len());
            libc::close(fd);
        }
    }

    // 7. Chdir to spec.cwd inside the container.
    let cwd_str = plan.cwd.to_str().unwrap_or("/");
    let _ = chdir(cwd_str);

    // 8. Block on the FIFO until `start` writes. We use ppoll(POLLIN) which
    // waits for a real writer to send data (with NONBLOCK fd, plain read()
    // returns 0/EAGAIN immediately when no writer or no data). poll blocks
    // properly on a NONBLOCK fd until POLLIN is signaled.
    let mut byte = [0u8; 1];
    loop {
        let mut pfd = libc::pollfd {
            fd: fifo_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let pr = libc::poll(&mut pfd, 1, -1);
        if pr < 0 {
            let e = *libc::__errno_location();
            if e == libc::EINTR {
                continue;
            }
            child_die(err_fd, 107, b"poll fifo failed");
        }
        // Try to read; if it returns 0 (EOF), the writer closed without sending
        // data — treat as a signal to proceed.
        let n = libc::read(fifo_fd, byte.as_mut_ptr() as *mut _, 1);
        if n >= 0 {
            break;
        }
        let e = *libc::__errno_location();
        if e == libc::EINTR || e == libc::EAGAIN {
            continue;
        }
        child_die(err_fd, 107, b"read fifo failed");
    }
    libc::close(fifo_fd);

    // 8a. Apply rlimits via prlimit64 (post-FIFO so they don't affect setup).
    for (resource, rl) in &plan.rlimits {
        let _ = libc::prlimit64(
            0,
            *resource,
            rl as *const libc::rlimit64,
            std::ptr::null_mut(),
        );
    }

    // 8a. Set umask and supplementary groups (need root caps still).
    if !plan.user_additional_gids.is_empty() {
        let _ = libc::setgroups(
            plan.user_additional_gids.len(),
            plan.user_additional_gids.as_ptr(),
        );
    }
    if let Some(umask) = plan.user_umask {
        let _ = libc::umask(umask);
    }

    // 8b. Apply capability bounding set drops + capset BEFORE user transition,
    // because PR_CAPBSET_DROP requires effective CAP_SETPCAP, which we have
    // as root but lose after setresuid.
    if let Some(caps) = plan.caps {
        apply_capabilities(err_fd, &caps);
    }

    // 8c. Now transition to non-root user. PR_SET_KEEPCAPS preserves
    // permitted across setresuid; we set it right before setresuid.
    if plan.user_gid != 0 {
        if libc::setresgid(plan.user_gid, plan.user_gid, plan.user_gid) < 0 {
            child_die(err_fd, 109, b"setresgid failed");
        }
    }
    if plan.user_uid != 0 {
        if libc::prctl(libc::PR_SET_KEEPCAPS, 1u64, 0u64, 0u64, 0u64) < 0 {
            child_die(err_fd, 109, b"prctl SET_KEEPCAPS failed");
        }
        if libc::setresuid(plan.user_uid, plan.user_uid, plan.user_uid) < 0 {
            child_die(err_fd, 109, b"setresuid failed");
        }
        // After setresuid with KEEPCAPS, permitted is preserved but effective
        // and ambient are cleared. Re-apply effective via capset, and ambient
        // via prctl PR_CAP_AMBIENT_RAISE.
        if let Some(caps) = plan.caps {
            reapply_effective(err_fd, &caps);
            // Ambient: cleared by setresuid; re-raise.
            for cap in 0..64u32 {
                if (caps.ambient & (1u64 << cap)) != 0 {
                    let _ = libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_RAISE as u64,
                        cap as u64,
                        0u64,
                        0u64,
                    );
                }
            }
        }
    }

    // 8c. no_new_privs (PR_SET_NO_NEW_PRIVS) — required for exec to honor
    // capability/seccomp restrictions across boundary. Always set when a
    // seccomp filter is present, since `prctl(PR_SET_SECCOMP)` itself
    // requires either CAP_SYS_ADMIN or PR_SET_NO_NEW_PRIVS=1.
    let need_no_new_privs = plan.no_new_privileges || !plan.ext.seccomp_bpf.is_empty();
    if need_no_new_privs {
        let _ = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64);
    }

    // 8d. Install the seccomp filter (must be after caps + NNP, before exec).
    if !plan.ext.seccomp_bpf.is_empty() {
        #[repr(C)]
        struct sock_fprog {
            len: u16,
            filter: *const libc::sock_filter,
        }
        let fprog = sock_fprog {
            len: plan.ext.seccomp_bpf.len() as u16,
            filter: plan.ext.seccomp_bpf.as_ptr(),
        };
        let rc = libc::prctl(
            22,   /* PR_SET_SECCOMP */
            2u64, /* SECCOMP_MODE_FILTER */
            &fprog as *const sock_fprog as u64,
            0u64,
            0u64,
        );
        if rc != 0 {
            child_die(err_fd, 109, b"prctl PR_SET_SECCOMP failed");
        }
    }

    // 8d-tty. PTY: become session leader, claim the pty slave as
    // controlling tty, dup2 it onto stdin/stdout/stderr. We do this after
    // user transition + seccomp install so the workload sees the right
    // owning uid/gid on the tty (per `process.user`). When no PTY was
    // allocated, pty_slave_fd == -1 and the entire block is a no-op.
    if pty_slave_fd >= 0 {
        if libc::setsid() < 0 {
            child_die(err_fd, 116, b"setsid failed");
        }
        // TIOCSCTTY: claim the slave as controlling terminal of this
        // session. arg=0 means "fail if already controlling".
        if libc::ioctl(pty_slave_fd, libc::TIOCSCTTY, 0) < 0 {
            child_die(err_fd, 117, b"ioctl TIOCSCTTY failed");
        }
        // Replace stdio. dup2 is safe across fd-aliasing (same target).
        for newfd in 0..3 {
            if libc::dup2(pty_slave_fd, newfd) < 0 {
                child_die(err_fd, 118, b"dup2 pty slave failed");
            }
        }
        if pty_slave_fd > 2 {
            libc::close(pty_slave_fd);
        }
    }

    // 8e. startContainer hooks — fire inside the container's namespaces,
    // after all runtime configuration (caps, user transition, seccomp),
    // before exec. Hook subprocesses inherit the seccomp filter; hook
    // binaries must only use syscalls in the allowed set.
    if !plan.ext.hooks.start_container.is_empty() {
        run_hooks_unsafe(&plan.ext.hooks.start_container, err_fd);
    }

    // 8f. AppArmor / SELinux exec transitions. Both stage a label that
    // the kernel applies on the *next* execve in this task. AppArmor
    // wants "exec <profile>" (or "changeprofile <profile>"); SELinux
    // wants the raw context. Failures are fatal — silently running
    // unconfined would defeat the security policy the spec asked for.
    #[cfg(feature = "lsm")]
    {
        if let Some(profile) = plan.apparmor_profile.as_ref() {
            apply_apparmor(err_fd, profile);
        }
        if let Some(label) = plan.selinux_label.as_ref() {
            apply_selinux(err_fd, label);
        }
    }

    // 9. Final exec.
    let argv0 = match plan.argv.first() {
        Some(a) => a,
        None => child_die(err_fd, 108, b"empty argv"),
    };
    if argv0.as_bytes().contains(&b'/') {
        let _ = execve(argv0, &plan.argv, &plan.envp);
    } else {
        let _ = execvpe(argv0, &plan.argv, &plan.envp);
    }
    child_die(err_fd, 127, b"exec failed");
}

/// Child-context hook runner. Fork+exec each hook in sequence; on any
/// fork/wait error, write a diagnostic to err_fd and exit. Allocations
/// happen but the post-pivot_root child is in a known-good heap state
/// (we haven't done anything that would corrupt the allocator), so this
/// is safe.
unsafe fn run_hooks_unsafe(hooks: &[crate::plan::HookCmd], err_fd: i32) {
    for h in hooks {
        let pid = libc::fork();
        if pid < 0 {
            child_die(err_fd, 113, b"hook fork failed");
        }
        if pid == 0 {
            // Hook child. Don't try to pipe state JSON in this path — we'd
            // need a pipe2 + dup2; for v0 the hook reads its own context
            // from the bundle if it needs to. (Parent-side `run_hooks`
            // pipes state.json on stdin; in-container hooks see the
            // workload's stdin, which is the same fd inherited from
            // create.)
            let mut argv: Vec<*const libc::c_char> = h.args.iter().map(|c| c.as_ptr()).collect();
            argv.push(std::ptr::null());
            let mut envp: Vec<*const libc::c_char> = h.env.iter().map(|c| c.as_ptr()).collect();
            envp.push(std::ptr::null());
            libc::execve(h.path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(127);
        }
        let mut status = 0i32;
        // Optional pidfd-based timeout. timeout_ms == None means
        // "wait indefinitely" (the pre-timeout behavior).
        if let Some(ms) = h.timeout_ms {
            const SYS_PIDFD_OPEN: libc::c_long = 434;
            let pidfd = libc::syscall(SYS_PIDFD_OPEN, pid, 0u32) as i32;
            if pidfd >= 0 {
                let timeout = if ms > i32::MAX as u64 {
                    i32::MAX
                } else {
                    ms as i32
                };
                let mut pfd = libc::pollfd {
                    fd: pidfd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let mut rc;
                loop {
                    rc = libc::poll(&mut pfd, 1, timeout);
                    if rc >= 0 || *libc::__errno_location() != libc::EINTR {
                        break;
                    }
                }
                libc::close(pidfd);
                if rc == 0 {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, &mut status, 0);
                    child_die(err_fd, 116, b"hook timeout, killed");
                }
                if rc < 0 {
                    child_die(err_fd, 114, b"hook poll failed");
                }
            }
            // pidfd_open failed → fall through to blocking waitpid.
        }
        loop {
            let r = libc::waitpid(pid, &mut status, 0);
            if r >= 0 {
                break;
            }
            let e = *libc::__errno_location();
            if e == libc::EINTR {
                continue;
            }
            child_die(err_fd, 114, b"hook waitpid failed");
        }
        // Per OCI: hook failure aborts container start. We honor exit
        // status: nonzero from any hook → fail.
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) != 0 {
            child_die(err_fd, 115, b"hook exited nonzero");
        }
        if libc::WIFSIGNALED(status) {
            child_die(err_fd, 115, b"hook killed by signal");
        }
    }
}

/// Apply Linux capability sets via the capset(2) and prctl(2) syscalls.
/// We use capset(2) directly to avoid pulling in libcap. The kernel's
/// "v3" capability data structure is two u32 words per set.
unsafe fn apply_capabilities(err_fd: i32, caps: &crate::plan::CapBitmasks) {
    // First, drop everything from the bounding set that we don't want.
    // PR_CAPBSET_DROP requires CAP_SETPCAP.
    for cap in 0..64u32 {
        if (caps.bounding & (1u64 << cap)) == 0 {
            // Not in bounding -> drop. Ignore errors (cap may not exist on this kernel).
            let _ = libc::prctl(libc::PR_CAPBSET_DROP, cap as u64, 0u64, 0u64, 0u64);
        }
    }

    // Now set inheritable, permitted, effective via capset(2).
    // capability v3 header + 2-word datap (low / high 32 bits each set).
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
    let header = CapHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data: [CapData; 2] = [
        CapData {
            effective: caps.effective as u32,
            permitted: caps.permitted as u32,
            inheritable: caps.inheritable as u32,
        },
        CapData {
            effective: (caps.effective >> 32) as u32,
            permitted: (caps.permitted >> 32) as u32,
            inheritable: (caps.inheritable >> 32) as u32,
        },
    ];
    let rc = libc::syscall(libc::SYS_capset, &header as *const _, data.as_ptr());
    if rc < 0 {
        child_die(err_fd, 109, b"capset failed");
    }

    // Ambient caps: must be raised one at a time after caps are in
    // permitted+inheritable.
    for cap in 0..64u32 {
        if (caps.ambient & (1u64 << cap)) != 0 {
            let _ = libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_RAISE as u64,
                cap as u64,
                0u64,
                0u64,
            );
        }
    }
}

/// Re-apply effective+permitted+inheritable after setresuid with KEEPCAPS.
/// KEEPCAPS preserves permitted across the uid transition, but the kernel
/// resets effective to nothing. We call capset to restore effective from
/// permitted.
unsafe fn reapply_effective(err_fd: i32, caps: &crate::plan::CapBitmasks) {
    // First, query current capset to see what survived KEEPCAPS.
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
    let header = CapHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut got: [CapData; 2] = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    let rc = libc::syscall(libc::SYS_capget, &header as *const _, got.as_mut_ptr());
    if rc < 0 {
        child_die(err_fd, 109, b"capget after setresuid failed");
    }

    // Set effective = permitted ∩ requested-effective. permitted may have
    // been reduced by the kernel (e.g. file caps don't apply, etc.).
    let req_eff_lo = caps.effective as u32;
    let req_eff_hi = (caps.effective >> 32) as u32;
    let new_data: [CapData; 2] = [
        CapData {
            effective: got[0].permitted & req_eff_lo,
            permitted: got[0].permitted,
            inheritable: caps.inheritable as u32,
        },
        CapData {
            effective: got[1].permitted & req_eff_hi,
            permitted: got[1].permitted,
            inheritable: (caps.inheritable >> 32) as u32,
        },
    ];
    let rc = libc::syscall(libc::SYS_capset, &header as *const _, new_data.as_ptr());
    if rc < 0 {
        child_die(err_fd, 109, b"reapply effective caps failed");
    }
}

#[cfg(feature = "lsm")]
/// Stage an AppArmor profile transition for the next execve. We write
/// "exec <profile>" to /proc/self/attr/apparmor/exec (preferred,
/// AppArmor 4.x) or /proc/self/attr/exec (legacy fallback). The kernel
/// then transitions on execve. If AppArmor isn't loaded, both opens
/// return ENOENT and we treat that as a fatal misconfiguration —
/// silently running unconfined would defeat the policy.
unsafe fn apply_apparmor(err_fd: i32, profile: &CString) {
    // Build "exec <profile>\0" inline. Profile name length is bounded
    // by AppArmor (~128) so an on-stack buffer suffices.
    let prof_bytes = profile.as_bytes();
    let mut buf = [0u8; 256];
    let prefix = b"exec ";
    if prefix.len() + prof_bytes.len() > buf.len() {
        child_die(err_fd, 120, b"apparmor profile name too long");
    }
    let mut n = 0usize;
    for &b in prefix {
        buf[n] = b;
        n += 1;
    }
    for &b in prof_bytes {
        buf[n] = b;
        n += 1;
    }
    let primary = b"/proc/self/attr/apparmor/exec\0";
    let legacy = b"/proc/self/attr/exec\0";
    let mut fd = libc::open(
        primary.as_ptr() as *const libc::c_char,
        libc::O_WRONLY | libc::O_CLOEXEC,
    );
    if fd < 0 {
        fd = libc::open(
            legacy.as_ptr() as *const libc::c_char,
            libc::O_WRONLY | libc::O_CLOEXEC,
        );
    }
    if fd < 0 {
        child_die(
            err_fd,
            120,
            b"open apparmor attr failed (kernel module loaded?)",
        );
    }
    let w = libc::write(fd, buf.as_ptr() as *const _, n);
    libc::close(fd);
    if w < 0 || w as usize != n {
        child_die(err_fd, 120, b"write apparmor profile failed");
    }
}

#[cfg(feature = "lsm")]
/// Stage an SELinux exec context for the next execve. We write the
/// label (with a trailing newline, mirroring libselinux's setexeccon)
/// to /proc/self/attr/exec. ENOENT means SELinux isn't loaded — fatal
/// for the same reason as AppArmor above.
unsafe fn apply_selinux(err_fd: i32, label: &CString) {
    let lbl_bytes = label.as_bytes();
    let path = b"/proc/self/attr/exec\0";
    let fd = libc::open(
        path.as_ptr() as *const libc::c_char,
        libc::O_WRONLY | libc::O_CLOEXEC,
    );
    if fd < 0 {
        child_die(
            err_fd,
            121,
            b"open selinux attr failed (kernel module loaded?)",
        );
    }
    let w = libc::write(fd, lbl_bytes.as_ptr() as *const _, lbl_bytes.len());
    libc::close(fd);
    if w < 0 || w as usize != lbl_bytes.len() {
        child_die(err_fd, 121, b"write selinux label failed");
    }
}

/// For each mount in `plan.mounts` with non-empty idmap_uid/idmap_gid,
/// spawn a helper task that creates a fresh user namespace with that
/// mapping, and return its `/proc/<pid>/ns/user` fd. Mounts without
/// an idmap get fd = -1 (so the index lines up). The helper uses
/// pause(2) to keep its userns alive until after clone3 has returned;
/// once the parent closes the userns fd, the kernel reaps the helper.
///
/// Linux 5.12+ for `mount_setattr(MOUNT_ATTR_IDMAP)`; older kernels
/// will fail later in the child's apply_idmap call and that mount
/// just runs un-idmapped (best-effort, with a child.err message).
fn spawn_idmap_helpers(mounts: &[crate::plan::MountOp]) -> std::io::Result<Vec<i32>> {
    let mut fds = Vec::with_capacity(mounts.len());
    for m in mounts {
        if m.idmap_uid.is_empty() && m.idmap_gid.is_empty() {
            fds.push(-1);
            continue;
        }
        // Helper synchronizes via a one-shot pipe: helper writes 1
        // byte after its uid_map/gid_map are installed. Parent reads,
        // opens /proc/<helper>/ns/user, then leaves the helper to be
        // reaped (it's parked in pause()).
        let mut sync_pipe: [i32; 2] = [-1, -1];
        if unsafe { libc::pipe2(sync_pipe.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let helper_pid = unsafe { libc::fork() };
        if helper_pid < 0 {
            unsafe {
                libc::close(sync_pipe[0]);
                libc::close(sync_pipe[1]);
            }
            return Err(std::io::Error::last_os_error());
        }
        if helper_pid == 0 {
            // Helper child. Close read end, unshare userns, install
            // mappings, signal parent, pause forever.
            unsafe {
                libc::close(sync_pipe[0]);
                if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                    libc::_exit(1);
                }
                // setgroups must be "deny" before we can write a
                // single-line gid_map without being root in the parent
                // userns.
                let _ = std::fs::write("/proc/self/setgroups", b"deny");
                if !m.idmap_uid.is_empty() {
                    if std::fs::write("/proc/self/uid_map", &m.idmap_uid).is_err() {
                        libc::_exit(2);
                    }
                }
                if !m.idmap_gid.is_empty() {
                    if std::fs::write("/proc/self/gid_map", &m.idmap_gid).is_err() {
                        libc::_exit(3);
                    }
                }
                let one = b'1';
                let _ = libc::write(sync_pipe[1], &one as *const u8 as *const _, 1);
                libc::close(sync_pipe[1]);
                // Park forever; parent will close the userns fd to
                // release us, but we must keep the userns alive until
                // mount_setattr completes in the child.
                loop {
                    libc::pause();
                }
            }
        }
        // Parent path.
        unsafe { libc::close(sync_pipe[1]) };
        let mut byte = [0u8; 1];
        let n = unsafe { libc::read(sync_pipe[0], byte.as_mut_ptr() as *mut _, 1) };
        unsafe { libc::close(sync_pipe[0]) };
        if n != 1 {
            // Helper failed before signaling. Reap it and continue
            // with fd=-1 (mount will run un-idmapped).
            let mut st = 0i32;
            unsafe { libc::waitpid(helper_pid, &mut st, 0) };
            fds.push(-1);
            continue;
        }
        let path = format!("/proc/{helper_pid}/ns/user");
        let path_c = std::ffi::CString::new(path).unwrap();
        let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        // Don't kill the helper — `mount_setattr` needs a live
        // reference to the userns. The helper exits naturally when
        // the parent process group is cleaned up, or it's reparented
        // to init. The userns stays alive as long as the open fd
        // exists; closing the fd in the parent (after clone3 inherits
        // it into the child) lets the kernel reclaim the userns when
        // the child closes its copy too.
        if fd < 0 {
            // Reap the helper; we won't be using it.
            unsafe { libc::kill(helper_pid, libc::SIGKILL) };
            let mut st = 0i32;
            unsafe { libc::waitpid(helper_pid, &mut st, 0) };
            fds.push(-1);
            continue;
        }
        // SIGKILL the helper task itself — we have its userns fd, the
        // helper PID's existence is no longer needed (the userns is
        // ref-counted via the fd). This keeps the process table tidy.
        unsafe {
            libc::kill(helper_pid, libc::SIGKILL);
            let mut st = 0i32;
            libc::waitpid(helper_pid, &mut st, 0);
        }
        fds.push(fd);
    }
    Ok(fds)
}

/// Apply `mount_setattr(MOUNT_ATTR_IDMAP)` to a freshly-bound mount.
/// We use the simpler `mount_setattr(2)` directly rather than the
/// `open_tree` + detached-mount dance — for a direct bind mount we
/// can attach the attr to the path. Failures are non-fatal: write a
/// diagnostic and let the mount run un-idmapped.
/// Build an idmapped bind mount from `source` to `target` using the
/// `open_tree` + `mount_setattr(IDMAP)` + `move_mount` triplet. The
/// kernel only accepts `MOUNT_ATTR_IDMAP` on a freshly-detached mount
/// (i.e. one created via `open_tree(OPEN_TREE_CLONE)`), so we bypass
/// the regular bind-mount syscall and synthesize the same effect from
/// these three.
///
/// Returns false on any kernel error; caller writes a diagnostic to
/// the err_fd.
unsafe fn apply_idmap_bind(
    source: &std::ffi::CStr,
    target: &std::path::Path,
    userns_fd: i32,
) -> bool {
    // Linux syscall numbers are stable across arches for these.
    const SYS_OPEN_TREE: i64 = 428;
    const SYS_MOUNT_SETATTR: i64 = 442;
    const SYS_MOVE_MOUNT: i64 = 429;
    // open_tree flags: OPEN_TREE_CLONE makes a detached *new* mount
    // tree from the source, OPEN_TREE_CLOEXEC sets close-on-exec.
    // AT_RECURSIVE makes it a recursive bind (matches how spec
    // `rbind` works); we always include it because OCI bind mounts
    // are conceptually rbinds for non-empty source dirs.
    const OPEN_TREE_CLONE: u32 = 1;
    const OPEN_TREE_CLOEXEC: u32 = libc::O_CLOEXEC as u32;
    const AT_RECURSIVE: u32 = 0x8000;
    const AT_EMPTY_PATH: u32 = 0x1000;
    const MOVE_MOUNT_F_EMPTY_PATH: u32 = 0x00000004;
    const MOUNT_ATTR_IDMAP: u64 = 0x00100000;

    #[repr(C)]
    struct MountAttr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }

    let target_c = match std::ffi::CString::new(target.as_os_str().as_encoded_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };

    // 1. Detach a clone of the source mount tree.
    let tree_fd = libc::syscall(
        SYS_OPEN_TREE,
        libc::AT_FDCWD,
        source.as_ptr(),
        OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC | AT_RECURSIVE,
    ) as i32;
    if tree_fd < 0 {
        return false;
    }

    // 2. Apply MOUNT_ATTR_IDMAP referencing our pre-built userns fd.
    let attr = MountAttr {
        attr_set: MOUNT_ATTR_IDMAP,
        attr_clr: 0,
        propagation: 0,
        userns_fd: userns_fd as u64,
    };
    let empty = b"\0";
    let rc = libc::syscall(
        SYS_MOUNT_SETATTR,
        tree_fd,
        empty.as_ptr() as *const libc::c_char,
        AT_EMPTY_PATH | AT_RECURSIVE,
        &attr as *const MountAttr,
        std::mem::size_of::<MountAttr>(),
    );
    if rc != 0 {
        libc::close(tree_fd);
        return false;
    }

    // 3. Move the detached idmapped tree onto the spec target.
    let rc = libc::syscall(
        SYS_MOVE_MOUNT,
        tree_fd,
        empty.as_ptr() as *const libc::c_char,
        libc::AT_FDCWD,
        target_c.as_ptr(),
        MOVE_MOUNT_F_EMPTY_PATH,
    );
    libc::close(tree_fd);
    rc == 0
}

/// Load the device cgroup eBPF program and attach it to the cgroup-v2
/// directory at `cgroup_dir`. Pure syscall glue — the program bytes
/// were emitted by `rsrun-ext::devices`. Two `bpf(2)` calls on the
/// success path; one `setrlimit` retry only on kernels < 5.11 where
/// memlock accounting is required. The returned program fd is dropped
/// here: the kernel ref-counts attached programs through the cgroup,
/// so the program stays in force until the cgroup itself is removed
/// at `delete` time.
fn attach_device_cgroup_bpf(cgroup_dir: &Path, prog_bytes: &[u8]) -> std::io::Result<()> {
    if prog_bytes.len() % 8 != 0 {
        return Err(std::io::Error::other(
            "device cgroup BPF program length not 8-byte aligned",
        ));
    }
    let insn_cnt = (prog_bytes.len() / 8) as u32;

    // The kernel BPF_PROG_LOAD path of `union bpf_attr` (see
    // <linux/bpf.h>). Field order and sizes are ABI; the kernel rejects
    // calls with `size > sizeof(struct bpf_attr)` if the extra bytes
    // are non-zero (E2BIG). We match exactly the kernel layout up to
    // `fd_array`. Padding before `fd_array` is the kernel's `:32; pad`.
    #[repr(C)]
    struct LoadAttr {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
        prog_name: [u8; 16],
        prog_ifindex: u32,
        expected_attach_type: u32,
        prog_btf_fd: u32,
        func_info_rec_size: u32,
        func_info: u64,
        func_info_cnt: u32,
        line_info_rec_size: u32,
        line_info: u64,
        line_info_cnt: u32,
        attach_btf_id: u32,
        attach_prog_fd: u32,
        _pad32: u32,
        fd_array: u64,
    }
    #[repr(C)]
    struct AttachAttr {
        target_fd: u32,
        attach_bpf_fd: u32,
        attach_type: u32,
        attach_flags: u32,
        replace_bpf_fd: u32,
        _pad: [u32; 3],
    }
    const BPF_PROG_LOAD: u32 = 5;
    const BPF_PROG_ATTACH: u32 = 8;
    // bpf_prog_type enum value for BPF_PROG_TYPE_CGROUP_DEVICE.
    const BPF_PROG_TYPE_CGROUP_DEVICE: u32 = 15;
    // bpf_attach_type enum value for BPF_CGROUP_DEVICE.
    const BPF_CGROUP_DEVICE_ATTACH: u32 = 6;

    let license = b"GPL\0";
    let load = |attr_ptr: *mut LoadAttr| -> i64 {
        unsafe {
            libc::syscall(
                libc::SYS_bpf,
                BPF_PROG_LOAD,
                attr_ptr,
                std::mem::size_of::<LoadAttr>(),
            )
        }
    };
    let mut attr = LoadAttr {
        prog_type: BPF_PROG_TYPE_CGROUP_DEVICE,
        insn_cnt,
        insns: prog_bytes.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: 0,
        log_size: 0,
        log_buf: 0,
        kern_version: 0,
        prog_flags: 0,
        prog_name: [0; 16],
        prog_ifindex: 0,
        expected_attach_type: 0,
        prog_btf_fd: 0,
        func_info_rec_size: 0,
        func_info: 0,
        func_info_cnt: 0,
        line_info_rec_size: 0,
        line_info: 0,
        line_info_cnt: 0,
        attach_btf_id: 0,
        attach_prog_fd: 0,
        _pad32: 0,
        fd_array: 0,
    };
    let mut prog_fd = load(&mut attr);
    if prog_fd < 0 {
        // Capture verifier log on EINVAL to make the failure debuggable.
        let e0 = std::io::Error::last_os_error();
        if e0.raw_os_error() == Some(libc::EINVAL) {
            let mut log = vec![0u8; 16 * 1024];
            attr.log_level = 1;
            attr.log_size = log.len() as u32;
            attr.log_buf = log.as_mut_ptr() as u64;
            let _ = load(&mut attr);
            let len = log.iter().position(|&b| b == 0).unwrap_or(log.len());
            let s = String::from_utf8_lossy(&log[..len]);
            return Err(std::io::Error::other(format!(
                "BPF verifier rejected device program (EINVAL):\n{s}"
            )));
        }
        // EPERM on kernel < 5.11 means RLIMIT_MEMLOCK exhausted. Bump
        // and retry once. On kernel ≥ 5.11 BPF accounts via memcg, so
        // memlock is irrelevant and this retry is harmless.
        let rl = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        unsafe {
            libc::setrlimit(libc::RLIMIT_MEMLOCK, &rl);
        }
        prog_fd = load(&mut attr);
        if prog_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let prog_fd = prog_fd as i32;

    let cgroup_cstr = CString::new(cgroup_dir.as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::other("cgroup path NUL"))?;
    let cgroup_fd = unsafe {
        libc::open(
            cgroup_cstr.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if cgroup_fd < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(prog_fd) };
        return Err(e);
    }
    // BPF_F_ALLOW_MULTI: allow our program to coexist with cgroup
    // device programs already attached to ancestor cgroups (systemd
    // attaches one at every service slice). Without this flag the
    // kernel returns EINVAL on attach to a non-root cgroup whose
    // ancestors already have a device program.
    const BPF_F_ALLOW_MULTI: u32 = 1 << 1;
    let attach = AttachAttr {
        target_fd: cgroup_fd as u32,
        attach_bpf_fd: prog_fd as u32,
        attach_type: BPF_CGROUP_DEVICE_ATTACH,
        attach_flags: BPF_F_ALLOW_MULTI,
        replace_bpf_fd: 0,
        _pad: [0; 3],
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_PROG_ATTACH,
            &attach as *const _,
            std::mem::size_of::<AttachAttr>(),
        )
    };
    let attach_err = if rc < 0 {
        Some(std::io::Error::last_os_error())
    } else {
        None
    };
    unsafe {
        libc::close(cgroup_fd);
        // Once attached, the kernel keeps the program alive via the
        // cgroup. Closing prog_fd here releases our userland reference
        // but does NOT detach.
        libc::close(prog_fd);
    }
    if let Some(e) = attach_err {
        return Err(std::io::Error::other(format!(
            "BPF_PROG_ATTACH (cgroup={}): {e}",
            cgroup_dir.display()
        )));
    }
    Ok(())
}

#[cfg(feature = "systemd-cgroup")]
/// systemd cgroup driver. Calls `systemd-run --scope` to create a
/// transient `.scope` unit whose cgroup is the one rsrun will use.
/// systemd then owns the slice and shows it in `systemctl status`,
/// which is what containerd / podman expect when their cgroup driver
/// is set to systemd.
///
/// Best-effort: failure is logged via stderr (caught by --log) but
/// doesn't abort `create`. The runtime falls back to plain cgroupfs.
/// Trade-off vs. crun's full D-Bus marshaller: one extra fork+exec on
/// `create` (only when `--systemd-cgroup` is set, so default rsrun is
/// untouched), no zbus dependency, ~25 LOC instead of ~400.
fn systemd_create_scope(id: &str, cgroup_dir: &std::path::Path) -> std::io::Result<()> {
    // We point systemd-run at the cgroup path we'd create anyway.
    // --slice picks the slice name (rsrun-<id>.slice); --scope makes
    // it transient. --no-block returns once D-Bus accepts; we don't
    // need to wait for the started unit (we'll never use it).
    let scope_name = format!("rsrun-{id}.scope");
    let status = std::process::Command::new("systemd-run")
        .args([
            "--no-block",
            "--scope",
            "--unit",
            &scope_name,
            "--description",
            "rsrun container",
            "--slice",
            "rsrun.slice",
            "true",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(_) => {
            // Non-zero exit: systemd-run might have rejected us (already
            // exists, dbus down, etc.). Continue with cgroupfs fallback.
            let _ = cgroup_dir;
            Err(std::io::Error::other("systemd-run rejected"))
        }
        Err(e) => Err(e),
    }
}

#[cfg(feature = "stats")]
/// `rsrun events <id> [--stats]` — emit a single JSON line of cgroup-v2
/// metrics (when --stats) or stream them every second (default).
/// Mirror of crun's `events`. Used by `docker stats`.
pub fn cmd_events(id: &str, stats_only: bool) -> std::io::Result<()> {
    let cgroup_dir = std::path::PathBuf::from(format!("/sys/fs/cgroup/rsrun-{id}"));
    if !cgroup_dir.exists() {
        return Err(std::io::Error::other(format!(
            "container {id} has no cgroup"
        )));
    }
    if stats_only {
        let line = render_stats_json(id, &cgroup_dir);
        println!("{line}");
        return Ok(());
    }
    loop {
        let line = render_stats_json(id, &cgroup_dir);
        println!("{line}");
        std::io::Write::flush(&mut std::io::stdout())?;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[cfg(feature = "stats")]
/// `rsrun stats <id>` — alias for `events --stats`. Bare convenience
/// when the user just wants a single snapshot.
pub fn cmd_stats(id: &str) -> std::io::Result<()> {
    cmd_events(id, true)
}

#[cfg(feature = "stats")]
fn render_stats_json(id: &str, cgroup_dir: &std::path::Path) -> String {
    let read_u64 = |p: &str| -> u64 {
        std::fs::read_to_string(cgroup_dir.join(p))
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    let memory_current = read_u64("memory.current");
    let pids_current = read_u64("pids.current");
    // cpu.stat is "usage_usec N\nuser_usec N\n..." — pull usage_usec.
    let cpu_usage_usec = std::fs::read_to_string(cgroup_dir.join("cpu.stat"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("usage_usec ").and_then(|n| n.parse().ok()))
        })
        .unwrap_or(0u64);
    serde_json::json!({
        "type": "stats",
        "id": id,
        "data": {
            "cpu": { "usage": { "total": cpu_usage_usec * 1000 } },
            "memory": { "usage": { "usage": memory_current } },
            "pids": { "current": pids_current },
        }
    })
    .to_string()
}

#[cfg(feature = "update")]
/// `rsrun update <id> [--resources <path>]` — re-write cgroup-v2
/// resource knobs of a running container. Reads either a JSON file
/// (matching OCI's `linux.resources` shape) or stdin. Best-effort:
/// each knob is written independently; a failed write doesn't roll
/// back the others. Both crun and youki implement this.
pub fn cmd_update(id: &str, resources_path: Option<&Path>) -> std::io::Result<()> {
    let bytes = if let Some(p) = resources_path {
        std::fs::read(p)?
    } else {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)?;
        buf
    };
    let resources: serde_json::Value = serde_json::from_slice(&bytes)?;
    let writes = compile_resources_to_writes(&resources);
    let cgroup_dir = std::path::PathBuf::from(format!("/sys/fs/cgroup/rsrun-{id}"));
    if !cgroup_dir.exists() {
        return Err(std::io::Error::other(format!(
            "container {id} has no cgroup"
        )));
    }
    for (knob, value) in &writes {
        let _ = std::fs::write(cgroup_dir.join(knob), value);
    }
    Ok(())
}

#[cfg(feature = "update")]
/// Stripped-down mirror of `rsrun-ext::cgroup::compile_writes`. Only
/// the v2 knobs that map 1:1 from OCI fields. Kept here so core can
/// implement `update` without depending on rsrun-ext.
fn compile_resources_to_writes(r: &serde_json::Value) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    let push_int = |out: &mut Vec<(String, Vec<u8>)>, knob: &str, n: i64| {
        let s = if n < 0 {
            "max\n".to_string()
        } else {
            format!("{n}\n")
        };
        out.push((knob.to_string(), s.into_bytes()));
    };
    if let Some(memory) = r.get("memory") {
        if let Some(n) = memory.get("limit").and_then(|x| x.as_i64()) {
            push_int(&mut out, "memory.max", n);
        }
        if let Some(n) = memory.get("swap").and_then(|x| x.as_i64()) {
            let mem = memory.get("limit").and_then(|x| x.as_i64()).unwrap_or(0);
            let swap_only = if mem > 0 && n >= mem { n - mem } else { n };
            push_int(&mut out, "memory.swap.max", swap_only);
        }
    }
    if let Some(cpu) = r.get("cpu") {
        let quota = cpu.get("quota").and_then(|x| x.as_i64());
        let period = cpu.get("period").and_then(|x| x.as_u64());
        if quota.is_some() || period.is_some() {
            let q = match quota {
                Some(n) if n < 0 => "max".to_string(),
                Some(n) => n.to_string(),
                None => "max".to_string(),
            };
            let p = period.unwrap_or(100_000);
            out.push(("cpu.max".to_string(), format!("{q} {p}\n").into_bytes()));
        }
        if let Some(shares) = cpu.get("shares").and_then(|x| x.as_u64()) {
            // OCI shares 2..262144 → cgroup-v2 weight 1..10000.
            let weight = ((shares - 2) * 9999 / 262142) + 1;
            out.push(("cpu.weight".to_string(), format!("{weight}\n").into_bytes()));
        }
    }
    if let Some(pids) = r.get("pids") {
        if let Some(n) = pids.get("limit").and_then(|x| x.as_i64()) {
            push_int(&mut out, "pids.max", n);
        }
    }
    out
}

/// `rsrun pause <id>` — freeze the container by writing 1 to
/// `cgroup.freeze` in the container's cgroup-v2 directory. Mirror of
/// `cmd_resume`. Both crun and youki implement this. cgroup v1's
/// freezer controller is *not* used here (rsrun is v2-only).
#[cfg(feature = "pause")]
pub fn cmd_pause(id: &str) -> std::io::Result<()> {
    set_freeze(id, true)?;
    update_status(id, "paused")
}

/// `rsrun resume <id>` — unfreeze.
#[cfg(feature = "pause")]
pub fn cmd_resume(id: &str) -> std::io::Result<()> {
    set_freeze(id, false)?;
    update_status(id, "running")
}

#[cfg(feature = "pause")]
fn set_freeze(id: &str, freeze: bool) -> std::io::Result<()> {
    let cgroup_dir = std::path::PathBuf::from(format!("/sys/fs/cgroup/rsrun-{id}"));
    if !cgroup_dir.exists() {
        return Err(std::io::Error::other(format!(
            "container {id} has no cgroup (was it created without resources?)"
        )));
    }
    std::fs::write(
        cgroup_dir.join("cgroup.freeze"),
        if freeze { b"1" } else { b"0" },
    )
}

#[cfg(feature = "pause")]
fn update_status(id: &str, status: &str) -> std::io::Result<()> {
    let paths = ContainerPaths::for_id(id);
    let bytes = std::fs::read(paths.state_file())?;
    let mut v: serde_json::Value = serde_json::from_slice(&bytes)?;
    v["status"] = serde_json::Value::String(status.to_string());
    std::fs::write(paths.state_file(), serde_json::to_vec(&v)?)
}

pub fn cmd_start(id: &str) -> std::io::Result<()> {
    let paths = ContainerPaths::for_id(id);
    if !paths.root.exists() {
        return Err(std::io::Error::other(format!(
            "container {id} does not exist"
        )));
    }
    let pid = read_pid(&paths)?;

    // Open the FIFO write-side. The init process is blocked in read on the
    // other end; this unblocks it.
    let mut f = std::fs::OpenOptions::new().write(true).open(paths.fifo())?;
    f.write_all(b"S")?;
    drop(f);

    let bundle = read_bundle(&paths)?;
    let comm_hint = read_comm_hint(&paths);
    write_state(&paths, id, pid, &bundle, "running", comm_hint.as_deref())?;

    // poststart fires after the workload is running. OCI says errors
    // here are logged-and-warning, not fatal.
    let hooks = load_hooks(&paths);
    if !hooks.poststart.is_empty() {
        let _ = run_hooks(&hooks.poststart, id);
    }
    Ok(())
}

pub fn cmd_delete(id: &str, force: bool) -> std::io::Result<()> {
    let paths = ContainerPaths::for_id(id);
    if !paths.root.exists() {
        // delete -f against a missing container should succeed
        if force {
            return Ok(());
        }
        return Err(std::io::Error::other(format!(
            "container {id} does not exist"
        )));
    }

    // OCI: `delete` without -f MUST fail if container is not stopped.
    if !force {
        if let Ok(bytes) = std::fs::read(paths.state_file()) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                let status = v
                    .get("status")
                    .and_then(|s| s.as_str())
                    .unwrap_or("created");
                let pid = v.get("pid").and_then(|p| p.as_i64()).unwrap_or(0) as i32;
                let comm = v.get("commHint").and_then(|s| s.as_str());
                if status != "stopped" && pid > 0 && is_init_alive(pid, comm) {
                    return Err(std::io::Error::other(format!(
                        "cannot delete container {id} in state {status}; use --force"
                    )));
                }
            }
        }
    }

    if let Ok(pid) = read_pid(&paths) {
        let pid = Pid::from_raw(pid);
        if force {
            let _ = kill(pid, Signal::SIGKILL);
        }
        // Reap. If the workload already exited, this returns ECHILD which
        // is fine (the previous owner of the pid waited or the kernel
        // auto-reaped because we lost track after parent exit).
        let _ = waitpid(pid, None);
        // If we couldn't wait (e.g. not our child after parent exited),
        // poll /proc/<pid> until it disappears. Bounded to ~1s.
        for _ in 0..200 {
            if !std::path::Path::new(&format!("/proc/{}", pid.as_raw())).exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    // poststop fires after the container has stopped, before its state
    // dir is destroyed (so the hook can still read state files).
    let hooks = load_hooks(&paths);
    if !hooks.poststop.is_empty() {
        let _ = run_hooks(&hooks.poststop, id);
    }

    paths.destroy()?;
    Ok(())
}

pub fn cmd_state(id: &str) -> std::io::Result<()> {
    let paths = ContainerPaths::for_id(id);
    if !paths.root.exists() {
        return Err(std::io::Error::other(format!(
            "container {id} does not exist"
        )));
    }
    let bytes = std::fs::read(paths.state_file())?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let status = value
        .get("status")
        .and_then(|s| s.as_str())
        .unwrap_or("created")
        .to_string();
    let pid = value.get("pid").and_then(|p| p.as_i64()).unwrap_or(0) as i32;

    // Once we've already recorded "stopped" we never go back. Otherwise check
    // whether the recorded init pid is still alive via /proc/<pid>/comm. We
    // verify the comm matches the workload's argv[0] basename (recorded at
    // create time) so a recycled pid for a different process doesn't fool us.
    if status != "stopped" && pid > 0 {
        let alive = is_init_alive(pid, value.get("commHint").and_then(|s| s.as_str()));
        if !alive {
            value["status"] = serde_json::Value::String("stopped".to_string());
            // Persist the stopped status so subsequent state queries return it
            // immediately and aren't fooled by a pid reused by an unrelated
            // process.
            let persisted = serde_json::to_vec(&value)?;
            let _ = std::fs::write(paths.state_file(), &persisted);
        }
    }
    let out = serde_json::to_vec(&value)?;
    std::io::stdout().write_all(&out)?;
    std::io::stdout().write_all(b"\n")?;
    Ok(())
}

/// Returns true iff /proc/<pid> exists. We previously also checked comm
/// against a hint, but the comm transitions (rsrun → workload) at execve, so
/// a fixed expected value is wrong. Pid reuse by an unrelated process within
/// a short window is theoretically possible but rare in practice.
fn is_init_alive(pid: i32, _comm_hint: Option<&str>) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

fn read_comm_hint(paths: &ContainerPaths) -> Option<String> {
    let bytes = std::fs::read(paths.state_file()).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("commHint").and_then(|s| s.as_str()).map(String::from)
}

fn read_bundle(paths: &ContainerPaths) -> std::io::Result<PathBuf> {
    let bytes = std::fs::read(paths.state_file())?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)?;
    Ok(PathBuf::from(
        v.get("bundle")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string(),
    ))
}

/// `kill <id> <signal>` — used by some test harnesses.
pub fn cmd_kill(id: &str, signal: &str) -> std::io::Result<()> {
    let paths = ContainerPaths::for_id(id);
    let pid = Pid::from_raw(read_pid(&paths)?);
    let sig = parse_signal(signal)?;
    kill(pid, sig)?;
    Ok(())
}

fn parse_signal(s: &str) -> std::io::Result<Signal> {
    let upper = s.to_ascii_uppercase();
    let bare = upper.strip_prefix("SIG").unwrap_or(&upper);
    Ok(match bare {
        "TERM" => Signal::SIGTERM,
        "KILL" => Signal::SIGKILL,
        "INT" => Signal::SIGINT,
        "HUP" => Signal::SIGHUP,
        "QUIT" => Signal::SIGQUIT,
        "USR1" => Signal::SIGUSR1,
        "USR2" => Signal::SIGUSR2,
        n => match n.parse::<i32>() {
            Ok(num) => {
                Signal::try_from(num).map_err(|_| std::io::Error::other("bad signal number"))?
            }
            Err(_) => return Err(std::io::Error::other(format!("unknown signal: {s}"))),
        },
    })
}

/// Helper used by `_exit`-only child paths to assert nothing further runs.
#[allow(dead_code)]
fn unreachable() -> ! {
    unsafe { libc::_exit(255) }
}

/// CVE-2019-5736 mitigation: set our process to non-dumpable via
/// `prctl(PR_SET_DUMPABLE, 0)`. The kernel then makes `/proc/<pid>/*`
/// files owned by root:root of the initial user namespace, *not* by the
/// container's mapped root. A container process running as
/// namespaced-root but with host UID != 0 cannot open
/// `/proc/<rsrun_pid>/exe` for write — the kernel's `may_open()` check
/// rejects with EACCES.
///
/// Cost: one `prctl` syscall (sub-microsecond, unmeasurable in benches).
///
/// Limitation: only protects against attackers in a separate user
/// namespace. A container running in the host user namespace (uid 0
/// matches) wouldn't be blocked — but in that scenario you've already
/// given root to the workload and CVE-2019-5736 isn't your biggest
/// problem. For the standard rootless / userns-mapped configuration,
/// this is sufficient.
fn set_undumpable() {
    unsafe {
        let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0u64, 0u64, 0u64, 0u64);
    }
}

/// `rsrun exec <id>` — read the container's init pid, setns into each of
/// its namespaces, fork (required for PID-namespace entry), and execve the
/// process described by process.json.
///
/// CVE-2019-5736: this is the *only* verb that places an rsrun-derived
/// process inside the container's PID namespace, where a malicious peer
/// in the container could open `/proc/<pid>/exe` and write through it to
/// our host binary. Before doing the setns work, mark this process
/// non-dumpable so /proc/<pid>/exe is unreadable by the container.
/// create/start/delete are immune to the attack by construction.
pub fn cmd_exec(
    id: &str,
    process_json: &Path,
    pid_file: Option<&Path>,
    detach: bool,
) -> std::io::Result<()> {
    cmd_exec_full(id, process_json, pid_file, detach, None)
}

/// Same as `cmd_exec` plus a `--console-socket` path. When the
/// `process.json` sets `terminal: true` and a console socket is
/// available, the parent allocates a PTY pair, forwards the master
/// fd to the engine via SCM_RIGHTS, and the exec'd child gets the
/// slave dup'd onto stdio. Mirror of `cmd_create_full`'s TTY logic;
/// reuses `send_pty_master`. `docker exec -it` needs this.
pub fn cmd_exec_full(
    id: &str,
    process_json: &Path,
    pid_file: Option<&Path>,
    detach: bool,
    console_socket: Option<&Path>,
) -> std::io::Result<()> {
    // CVE-2019-5736 mitigation: prctl(PR_SET_DUMPABLE, 0).
    set_undumpable();

    let paths = ContainerPaths::for_id(id);
    if !paths.root.exists() {
        return Err(std::io::Error::other(format!(
            "container {id} does not exist (root={})",
            paths.root.display()
        )));
    }
    let init_pid = read_pid(&paths)?;
    let ns_dir = format!("/proc/{}/ns", init_pid);
    if !std::path::Path::new(&ns_dir).exists() {
        return Err(std::io::Error::other(format!(
            "container {id} init pid {init_pid} is no longer alive"
        )));
    }

    let pj = parse_exec_process(process_json)?;

    // PTY allocation, when the spec sets terminal:true AND the engine
    // gave us a console socket. Both fds stay -1 otherwise.
    let mut pty_master_fd: i32 = -1;
    let mut pty_slave_fd: i32 = -1;
    if pj.terminal && console_socket.is_some() {
        let res = nix::pty::openpty(None, None)?;
        use std::os::fd::IntoRawFd;
        pty_master_fd = res.master.into_raw_fd();
        pty_slave_fd = res.slave.into_raw_fd();
    }

    // Open ns fds in a fixed order. PID namespace must be entered before
    // we fork (kernel requirement: setns(NEWPID) only takes effect on the
    // *next* fork in this process).
    let ns_types = ["user", "ipc", "uts", "net", "pid", "cgroup", "mnt"];
    let mut ns_fds: Vec<i32> = Vec::new();
    for ns in &ns_types {
        let p = format!("{}/{}", ns_dir, ns);
        let cs = CString::new(p).unwrap();
        let fd = unsafe { libc::open(cs.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd >= 0 {
            ns_fds.push(fd);
        }
    }
    for fd in &ns_fds {
        let _ = unsafe { libc::setns(*fd, 0) };
    }
    for fd in &ns_fds {
        unsafe { libc::close(*fd) };
    }

    // Fork to enter the PID namespace.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid > 0 {
        // Parent: hand the PTY master to the engine, close the slave.
        if pty_slave_fd >= 0 {
            unsafe { libc::close(pty_slave_fd) };
        }
        if let (Some(socket), true) = (console_socket, pty_master_fd >= 0) {
            send_pty_master(socket, pty_master_fd)?;
            unsafe { libc::close(pty_master_fd) };
        }
        if let Some(pf) = pid_file {
            std::fs::write(pf, pid.to_string())?;
        }
        if detach {
            return Ok(());
        }
        let mut status: i32 = 0;
        unsafe { libc::waitpid(pid, &mut status, 0) };
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            128 + libc::WTERMSIG(status)
        };
        return if exit_code == 0 {
            Ok(())
        } else {
            Err(std::io::Error::other(format!("exec: exit {exit_code}")))
        };
    }

    // Child path. Apply OCI process fields in the same order as create's
    // child_run (groups → caps → user transition → NNP → LSM staging).
    // On failure we _exit(non-zero) so the parent's waitpid surfaces it.
    unsafe {
        // Close the parent's master end (we kept it for sending). Slave
        // becomes our controlling terminal + stdio.
        if pty_master_fd >= 0 {
            libc::close(pty_master_fd);
        }
        if pty_slave_fd >= 0 {
            if libc::setsid() < 0 {
                libc::_exit(116);
            }
            if libc::ioctl(pty_slave_fd, libc::TIOCSCTTY, 0) < 0 {
                libc::_exit(117);
            }
            for newfd in 0..3 {
                if libc::dup2(pty_slave_fd, newfd) < 0 {
                    libc::_exit(118);
                }
            }
            if pty_slave_fd > 2 {
                libc::close(pty_slave_fd);
            }
        }
        if let Err(code) = exec_apply(&pj) {
            libc::_exit(code);
        }
        let cwd_c = CString::new(pj.cwd.as_str()).unwrap();
        let _ = libc::chdir(cwd_c.as_ptr());

        let argv0 = CString::new(pj.args[0].as_str()).unwrap();
        let argv: Vec<CString> = pj
            .args
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();
        let envp: Vec<CString> = pj
            .env
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap())
            .collect();
        let argv_p: Vec<*const libc::c_char> = argv
            .iter()
            .map(|c| c.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        let envp_p: Vec<*const libc::c_char> = envp
            .iter()
            .map(|c| c.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        if pj.args[0].contains('/') {
            libc::execve(argv0.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr());
        } else {
            libc::execvpe(argv0.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr());
        }
        libc::_exit(127);
    }
}

/// `process.json` fields rsrun honors on `exec`. Mirrors the create-time
/// process block. Anything not listed here is ignored.
struct ExecProcess {
    args: Vec<String>,
    env: Vec<String>,
    cwd: String,
    uid: u32,
    gid: u32,
    additional_gids: Vec<u32>,
    no_new_privileges: bool,
    capabilities: Option<crate::plan::CapBitmasks>,
    apparmor_profile: Option<CString>,
    selinux_label: Option<CString>,
    terminal: bool,
}

fn parse_exec_process(path: &Path) -> std::io::Result<ExecProcess> {
    let bytes = std::fs::read(path).map_err(|e| {
        std::io::Error::other(format!(
            "exec: read process.json from {}: {e}",
            path.display()
        ))
    })?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)?;
    let args: Vec<String> = v
        .get("args")
        .and_then(|a| a.as_array())
        .ok_or_else(|| std::io::Error::other("process.json: missing args"))?
        .iter()
        .filter_map(|x| x.as_str().map(String::from))
        .collect();
    if args.is_empty() {
        return Err(std::io::Error::other("process.json: empty args"));
    }
    let env = v
        .get("env")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let cwd = v
        .get("cwd")
        .and_then(|s| s.as_str())
        .unwrap_or("/")
        .to_string();
    let user = v.get("user");
    let uid = user
        .and_then(|u| u.get("uid"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0) as u32;
    let gid = user
        .and_then(|u| u.get("gid"))
        .and_then(|x| x.as_u64())
        .unwrap_or(0) as u32;
    let additional_gids = user
        .and_then(|u| u.get("additionalGids"))
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_u64().map(|n| n as u32))
                .collect()
        })
        .unwrap_or_default();
    let no_new_privileges = v
        .get("noNewPrivileges")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let capabilities = v.get("capabilities").map(|c| {
        let get = |key: &str| -> u64 {
            c.get(key)
                .and_then(|a| a.as_array())
                .map(|a| {
                    a.iter().fold(0u64, |m, x| {
                        x.as_str()
                            .and_then(crate::plan::cap_bit_for_name)
                            .map(|b| m | (1u64 << b))
                            .unwrap_or(m)
                    })
                })
                .unwrap_or(0)
        };
        crate::plan::CapBitmasks {
            bounding: get("bounding"),
            effective: get("effective"),
            permitted: get("permitted"),
            inheritable: get("inheritable"),
            ambient: get("ambient"),
        }
    });
    let apparmor_profile = v
        .get("apparmorProfile")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .and_then(|s| CString::new(s).ok());
    let selinux_label = v
        .get("selinuxLabel")
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .and_then(|s| CString::new(s).ok());

    let terminal = v.get("terminal").and_then(|x| x.as_bool()).unwrap_or(false);
    Ok(ExecProcess {
        args,
        env,
        cwd,
        uid,
        gid,
        additional_gids,
        no_new_privileges,
        capabilities,
        apparmor_profile,
        selinux_label,
        terminal,
    })
}

/// Apply OCI process fields to the current task in the order required
/// by the kernel: groups → caps → user transition → NNP → LSM staging.
/// On any kernel error returns Err(exit_code) so the caller can `_exit`
/// — this runs in a forked child whose parent waitpid()s for us.
unsafe fn exec_apply(pj: &ExecProcess) -> Result<(), i32> {
    if !pj.additional_gids.is_empty() {
        let _ = libc::setgroups(pj.additional_gids.len(), pj.additional_gids.as_ptr());
    }
    // Caps must be set BEFORE user transition; PR_CAPBSET_DROP needs
    // CAP_SETPCAP which we lose after setresuid to non-root.
    if let Some(caps) = pj.capabilities {
        apply_capabilities(2, &caps);
    }
    if pj.gid != 0 && libc::setresgid(pj.gid, pj.gid, pj.gid) < 0 {
        return Err(101);
    }
    if pj.uid != 0 {
        if libc::prctl(libc::PR_SET_KEEPCAPS, 1u64, 0u64, 0u64, 0u64) < 0 {
            return Err(102);
        }
        if libc::setresuid(pj.uid, pj.uid, pj.uid) < 0 {
            return Err(103);
        }
        if let Some(caps) = pj.capabilities {
            reapply_effective(2, &caps);
            for cap in 0..64u32 {
                if (caps.ambient & (1u64 << cap)) != 0 {
                    let _ = libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        libc::PR_CAP_AMBIENT_RAISE as u64,
                        cap as u64,
                        0u64,
                        0u64,
                    );
                }
            }
        }
    }
    if pj.no_new_privileges {
        let _ = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64);
    }
    if let Some(profile) = pj.apparmor_profile.as_ref() {
        apply_apparmor(2, profile);
    }
    if let Some(label) = pj.selinux_label.as_ref() {
        apply_selinux(2, label);
    }
    Ok(())
}

/// `rsrun list` — list known containers in /run/rsrun. Used by Docker for
/// orphan recovery on daemon restart (rare).
pub fn cmd_list() -> std::io::Result<()> {
    let root = ContainerPaths::for_id("dummy")
        .root
        .parent()
        .unwrap()
        .to_path_buf();
    if !root.exists() {
        // Output empty TAB-separated table
        println!("ID\tPID\tSTATUS\tBUNDLE\tCREATED\tOWNER");
        return Ok(());
    }
    println!("ID\tPID\tSTATUS\tBUNDLE\tCREATED\tOWNER");
    for entry in std::fs::read_dir(&root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        let state_path = entry.path().join("state.json");
        if let Ok(bytes) = std::fs::read(&state_path) {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                let pid = v.get("pid").and_then(|p| p.as_i64()).unwrap_or(0);
                let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("");
                let bundle = v.get("bundle").and_then(|s| s.as_str()).unwrap_or("");
                println!("{}\t{}\t{}\t{}\t\t", name, pid, status, bundle);
            }
        }
    }
    Ok(())
}
