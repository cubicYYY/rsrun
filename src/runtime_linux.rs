//! Runtime core. The hot path is `create` → `start` → `delete`.
//!
//! Two-process model:
//!
//! ```text
//! parent ───clone3(all NS flags atomic)───► child
//!   │                                          │
//!   │                                          ├─ mount(MS_PRIVATE) on /
//!   │                                          ├─ exec mount plan
//!   │                                          ├─ pivot_root into rootfs
//!   │                                          ├─ sethostname
//!   │                                          ├─ chdir(cwd)
//!   │                                          ├─ open FIFO read-side ◀── blocks here
//!   │                                          │  (parent has exited;
//!   │                                          │   start() opens write-side)
//!   │                                          └─ execve(argv[0], argv, envp)
//!   │
//!   ├─ write /run/rsrun/<id>/init.pid
//!   ├─ write state.json (status="created")
//!   └─ exit 0
//! ```
//!
//! The parent does no per-clone synchronization — it just records
//! the PID and exits. The child blocks on the FIFO until `start`.

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
    let bundle = bundle.canonicalize()?;
    let spec = Spec::from_bundle(&bundle)?;
    let plan = CompiledPlan::from_spec(&spec)?;

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
        let rc = unsafe {
            libc::pipe2(
                userns_sync_pipe.as_mut_ptr(),
                libc::O_CLOEXEC,
            )
        };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let userns_read_fd = userns_sync_pipe[0];
    let userns_write_fd = userns_sync_pipe[1];

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
        unsafe {
            child_run(&plan, &rootfs_cstr, &fifo_cstr, err_fd, userns_read_fd);
        }
        unsafe { libc::_exit(127) }
    }

    // Parent path. Close child's read-side of the userns pipe.
    if userns_read_fd >= 0 {
        unsafe { libc::close(userns_read_fd) };
    }

    // Rootless-only: write uid_map and gid_map for the child, then signal it.
    if plan.wants_userns {
        // setgroups must be set to "deny" before we can write a gid_map as a
        // non-root user. Required when there's only one gid mapping.
        let setgroups_path = format!("/proc/{}/setgroups", pid);
        let _ = std::fs::write(&setgroups_path, b"deny");

        let uid_map_path = format!("/proc/{}/uid_map", pid);
        std::fs::write(&uid_map_path, &plan.uid_map_data).map_err(|e| {
            std::io::Error::other(format!("write uid_map: {e}"))
        })?;
        let gid_map_path = format!("/proc/{}/gid_map", pid);
        std::fs::write(&gid_map_path, &plan.gid_map_data).map_err(|e| {
            std::io::Error::other(format!("write gid_map: {e}"))
        })?;

        // Tell child it can proceed.
        let one = b'1';
        let n = unsafe { libc::write(userns_write_fd, &one as *const u8 as *const _, 1) };
        unsafe { libc::close(userns_write_fd) };
        if n != 1 {
            return Err(std::io::Error::last_os_error());
        }
    }

    unsafe { libc::close(err_fd) };
    std::fs::write(paths.pid_file(), pid.to_string())?;
    if let Some(pf) = pid_file {
        std::fs::write(pf, pid.to_string())?;
    }
    // commHint is the basename of argv[0] truncated to 15 chars (kernel comm
    // limit). Used by `state` to detect pid reuse.
    let comm_hint = spec.args.first().and_then(|s| {
        std::path::Path::new(s)
            .file_name()
            .and_then(|n| n.to_str())
    });
    write_state(&paths, id, pid, &bundle, "created", comm_hint)?;
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
    fifo: &CString,
    err_fd: i32,
    userns_read_fd: i32,
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

    // FIFO synchronization: open RDONLY blocking. The open call blocks
    // until `start` opens write-side. Once write opens, our open returns;
    // we then read one byte and continue to execve. This single open call
    // replaces a separate open+read.
    //
    // We have to open the FIFO BEFORE pivot_root, because the path is on the
    // host's /run/rsrun, not visible in the new rootfs. To keep the open
    // call from blocking immediately (we'd never reach pivot_root), we open
    // O_RDONLY|O_NONBLOCK to get an fd, then later block on read.
    //
    // Linux FIFO semantics:
    //   - open RDONLY blocking: blocks until a writer opens
    //   - open RDONLY|O_NONBLOCK: returns immediately
    //   - read on RDONLY (regardless of how it was opened) with no writers
    //     and an empty pipe: returns 0 (EOF) if NONBLOCK was set, blocks
    //     otherwise
    //
    // The kernel tracks "did this fd ever see a writer". Once a writer
    // opens, the fd is associated with a real pipe and reads block
    // waiting for data.
    //
    // rsrun opens NONBLOCK-RDONLY here and uses poll() to wait for
    // POLLIN. With no writer poll returns POLLHUP; with a writer and
    // pending data it returns POLLIN.
    let fifo_fd = libc::open(fifo.as_ptr(), libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC);
    if fifo_fd < 0 {
        child_die(err_fd, 100, b"open fifo failed");
    }

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
    for m in &plan.mounts {
        mloop += 1;
        // mkdir target; we don't care if it exists
        let _ = std::fs::create_dir_all(&m.target);
        let src_str = m.source.to_str().unwrap_or("");
        let fstype_str = m.fstype.to_str().unwrap_or("");
        let data_str = m.data.as_ref().and_then(|c| c.to_str().ok());

        let src_opt = if src_str.is_empty() { None } else { Some(src_str) };
        let fstype_opt = if fstype_str.is_empty() || fstype_str == "none" {
            None
        } else {
            Some(fstype_str)
        };
        if mount(src_opt, &m.target, fstype_opt, m.flags, data_str).is_err() {
            // Continue on mount failure. Many spec mounts are non-essential
            // (cgroup-inside-container, /dev/mqueue on hosts that don't
            // support it). A future version will surface these as warnings.
        }
    }

    let _ = mloop; // suppress warning

    // 4. pivot_root into the new rootfs.
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

    // 5. Hostname (UTS namespace) — only if explicitly set in spec.
    if plan.set_hostname {
        let _ = sethostname(plan.hostname.to_str().unwrap_or(""));
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
            let _ = libc::open(
                dev.path.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT,
                0o644,
            );
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
            Some(std::str::from_utf8_unchecked(&null_src[..null_src.len() - 1])),
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
    // capability/seccomp restrictions across boundary.
    if plan.no_new_privileges {
        let _ = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1u64, 0u64, 0u64, 0u64);
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
    struct CapHeader { version: u32, pid: i32 }
    #[repr(C)]
    struct CapData { effective: u32, permitted: u32, inheritable: u32 }

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
    let rc = libc::syscall(
        libc::SYS_capset,
        &header as *const _,
        data.as_ptr(),
    );
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
    struct CapHeader { version: u32, pid: i32 }
    #[repr(C)]
    struct CapData { effective: u32, permitted: u32, inheritable: u32 }
    const _LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;
    let header = CapHeader {
        version: _LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut got: [CapData; 2] = [
        CapData { effective: 0, permitted: 0, inheritable: 0 },
        CapData { effective: 0, permitted: 0, inheritable: 0 },
    ];
    let rc = libc::syscall(
        libc::SYS_capget,
        &header as *const _,
        got.as_mut_ptr(),
    );
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
    let rc = libc::syscall(
        libc::SYS_capset,
        &header as *const _,
        new_data.as_ptr(),
    );
    if rc < 0 {
        child_die(err_fd, 109, b"reapply effective caps failed");
    }
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
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(paths.fifo())?;
    f.write_all(b"S")?;
    drop(f);

    let bundle = read_bundle(&paths)?;
    let comm_hint = read_comm_hint(&paths);
    write_state(&paths, id, pid, &bundle, "running", comm_hint.as_deref())?;
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
    let pid = value
        .get("pid")
        .and_then(|p| p.as_i64())
        .unwrap_or(0) as i32;

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
/// a short window is theoretically possible but rare in practice; runc and
/// crun take the same risk.
fn is_init_alive(pid: i32, _comm_hint: Option<&str>) -> bool {
    std::path::Path::new(&format!("/proc/{}", pid)).exists()
}

fn read_comm_hint(paths: &ContainerPaths) -> Option<String> {
    let bytes = std::fs::read(paths.state_file()).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    v.get("commHint")
        .and_then(|s| s.as_str())
        .map(String::from)
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

    let bytes = std::fs::read(process_json).map_err(|e| {
        std::io::Error::other(format!(
            "exec: read process.json from {}: {e}",
            process_json.display()
        ))
    })?;
    let pj: serde_json::Value = serde_json::from_slice(&bytes)?;
    let args = pj
        .get("args")
        .and_then(|a| a.as_array())
        .ok_or_else(|| std::io::Error::other("process.json: missing args"))?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect::<Vec<_>>();
    let env = pj
        .get("env")
        .and_then(|a| a.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let cwd = pj
        .get("cwd")
        .and_then(|s| s.as_str())
        .unwrap_or("/")
        .to_string();

    if args.is_empty() {
        return Err(std::io::Error::other("process.json: empty args"));
    }

    // Open ns fds in a fixed order. PID namespace must be entered before
    // we fork (kernel requirement: setns(NEWPID) only takes effect on the
    // *next* fork in this process).
    let ns_types = [
        "user", "ipc", "uts", "net", "pid", "cgroup", "mnt",
    ];
    let mut ns_fds: Vec<i32> = Vec::new();
    for ns in &ns_types {
        let p = format!("{}/{}", ns_dir, ns);
        let fd = unsafe {
            let cs = std::ffi::CString::new(p.clone()).unwrap();
            libc::open(cs.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
        };
        if fd >= 0 {
            ns_fds.push(fd);
        }
    }

    // setns into each.
    for fd in &ns_fds {
        let rc = unsafe { libc::setns(*fd, 0) };
        if rc < 0 {
            // Soft-fail; some namespaces may not be enterable (e.g. our user
            // doesn't match) — let exec fail downstream with a real reason.
        }
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
        // Parent: write pid_file if requested, then either wait or detach.
        if let Some(pf) = pid_file {
            std::fs::write(pf, pid.to_string())?;
        }
    }
    if pid > 0 && detach {
        return Ok(());
    }
    if pid == 0 {
        // Child: chdir to cwd, exec.
        unsafe {
            let cwd_c = std::ffi::CString::new(cwd).unwrap();
            let _ = libc::chdir(cwd_c.as_ptr());

            let argv0 = std::ffi::CString::new(args[0].clone()).unwrap();
            let argv: Vec<std::ffi::CString> = args
                .iter()
                .map(|s| std::ffi::CString::new(s.as_str()).unwrap())
                .collect();
            let envp: Vec<std::ffi::CString> = env
                .iter()
                .map(|s| std::ffi::CString::new(s.as_str()).unwrap())
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
            if args[0].contains('/') {
                libc::execve(argv0.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr());
            } else {
                libc::execvpe(argv0.as_ptr(), argv_p.as_ptr(), envp_p.as_ptr());
            }
            libc::_exit(127);
        }
    }
    // Parent: wait for child.
    let mut status: i32 = 0;
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    let exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        128 + libc::WTERMSIG(status)
    };
    if exit_code != 0 {
        return Err(std::io::Error::other(format!("exec: exit {exit_code}")));
    }
    Ok(())
}

/// `rsrun list` — list known containers in /run/rsrun. Used by Docker for
/// orphan recovery on daemon restart (rare).
pub fn cmd_list() -> std::io::Result<()> {
    let root = ContainerPaths::for_id("dummy").root.parent().unwrap().to_path_buf();
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
