//! CompiledPlan — the runtime-ready, decision-free representation of a Spec.
//!
//! The point of compiling: the hot path (clone3 → mount → pivot_root → exec)
//! does no JSON parsing, no string searching, no decision logic. Just
//! syscalls with pre-computed args.
//!
//! Linux-only: the plan holds `nix::mount::MsFlags`, `nix::sched::CloneFlags`,
//! and `libc::rlimit64` — none of which exist on macOS. This module is only
//! declared on Linux (see `mod plan;` cfg-gate in `main.rs`); on non-Linux
//! the runtime stub doesn't need any of it.

use crate::spec::{NamespaceKind, RLimitKind, Spec};
use nix::sched::CloneFlags;
use std::ffi::CString;
use std::path::PathBuf;

pub struct CompiledPlan {
    /// All namespace flags OR'd into one value, ready for `clone3`.
    /// In rootless mode this includes CLONE_NEWUSER.
    pub clone_flags: CloneFlags,
    /// Whether the spec requested a user namespace. The hot path checks this
    /// once; rootful mode pays a single predicted-not-taken branch.
    pub wants_userns: bool,
    /// Rootless: uid_map and gid_map line buffers, pre-formatted at compile
    /// time. Each line is "container host size\n". For rootful these are
    /// empty Vecs and never touched.
    pub uid_map_data: Vec<u8>,
    pub gid_map_data: Vec<u8>,
    /// Whether the spec set hostname (empty string is treated as unset).
    pub set_hostname: bool,
    /// Resource limits to apply via prlimit64. Compiled to (resource, soft, hard).
    pub rlimits: Vec<(libc::__rlimit_resource_t, libc::rlimit64)>,
    /// Capability bitmasks. `None` means leave inherited (no change).
    pub caps: Option<CapBitmasks>,
    pub no_new_privileges: bool,
    /// Default device nodes (mknod) to create under /dev. Pre-resolved.
    pub default_devices: Vec<DefaultDevice>,
    /// Default symlinks to create under /dev: (target, link).
    pub default_symlinks: Vec<(CString, CString)>,
    /// Masked and readonly paths.
    pub masked_paths: Vec<CString>,
    pub readonly_paths: Vec<CString>,
    pub user_uid: u32,
    pub user_gid: u32,
    pub user_additional_gids: Vec<u32>,
    pub user_umask: Option<u32>,
    /// Hostname to set inside the UTS namespace.
    pub hostname: CString,
    /// Resolved absolute path to rootfs.
    pub root_path: PathBuf,
    pub root_readonly: bool,
    /// Mounts to perform inside the new mount namespace, in order.
    pub mounts: Vec<MountOp>,
    /// argv as null-terminated CStrings (first is the program path).
    pub argv: Vec<CString>,
    /// envp as null-terminated CStrings.
    pub envp: Vec<CString>,
    /// Working directory inside the container.
    pub cwd: CString,
}

pub struct MountOp {
    pub source: CString,
    pub target: PathBuf,
    pub fstype: CString,
    pub flags: nix::mount::MsFlags,
    pub data: Option<CString>,
}

/// Six capability sets we'll set inside the container. Each is a u64 bitmask
/// of capability indices (0..63). 64-bit covers Linux's full cap range.
#[derive(Default, Clone, Copy)]
pub struct CapBitmasks {
    pub bounding: u64,
    pub effective: u64,
    pub permitted: u64,
    pub inheritable: u64,
    pub ambient: u64,
}

#[derive(Clone)]
pub struct DefaultDevice {
    pub path: CString,
    pub mode: u32,    // file mode (e.g. 0o666)
    pub kind: char,   // 'c' for char device
    pub major: u32,
    pub minor: u32,
}

impl CompiledPlan {
    pub fn from_spec(spec: &Spec) -> std::io::Result<Self> {
        let mut clone_flags = CloneFlags::empty();
        let mut wants_userns = false;
        for ns in &spec.namespaces {
            match ns {
                NamespaceKind::Pid => clone_flags |= CloneFlags::CLONE_NEWPID,
                NamespaceKind::Network => clone_flags |= CloneFlags::CLONE_NEWNET,
                NamespaceKind::Mount => clone_flags |= CloneFlags::CLONE_NEWNS,
                NamespaceKind::Ipc => clone_flags |= CloneFlags::CLONE_NEWIPC,
                NamespaceKind::Uts => clone_flags |= CloneFlags::CLONE_NEWUTS,
                NamespaceKind::Cgroup => clone_flags |= CloneFlags::CLONE_NEWCGROUP,
                NamespaceKind::User => {
                    wants_userns = true;
                    clone_flags |= CloneFlags::CLONE_NEWUSER;
                }
            }
        }

        // Pre-format the uid_map / gid_map line buffers at compile time so the
        // hot path just does a single write() per file. Empty when rootful.
        let uid_map_data = if wants_userns {
            format_id_map(&spec.uid_mappings)
        } else {
            Vec::new()
        };
        let gid_map_data = if wants_userns {
            format_id_map(&spec.gid_mappings)
        } else {
            Vec::new()
        };

        let mounts = spec
            .mounts
            .iter()
            .map(|m| compile_mount(m, &spec.root_path))
            .collect::<std::io::Result<Vec<_>>>()?;

        let argv = spec
            .args
            .iter()
            .map(|s| cstr(s))
            .collect::<std::io::Result<Vec<_>>>()?;
        let envp = spec
            .env
            .iter()
            .map(|s| cstr(s))
            .collect::<std::io::Result<Vec<_>>>()?;

        // Compile rlimits to (resource, rlimit64) pairs. Allocator-free hot
        // path: at apply time we just iterate and call prlimit64.
        let mut rlimit_pairs = Vec::with_capacity(spec.rlimits.len());
        for r in &spec.rlimits {
            let resource = match r.kind {
                RLimitKind::Cpu => libc::RLIMIT_CPU,
                RLimitKind::Fsize => libc::RLIMIT_FSIZE,
                RLimitKind::Data => libc::RLIMIT_DATA,
                RLimitKind::Stack => libc::RLIMIT_STACK,
                RLimitKind::Core => libc::RLIMIT_CORE,
                RLimitKind::Rss => libc::RLIMIT_RSS,
                RLimitKind::Nproc => libc::RLIMIT_NPROC,
                RLimitKind::Nofile => libc::RLIMIT_NOFILE,
                RLimitKind::Memlock => libc::RLIMIT_MEMLOCK,
                RLimitKind::As => libc::RLIMIT_AS,
                RLimitKind::Locks => libc::RLIMIT_LOCKS,
                RLimitKind::Sigpending => libc::RLIMIT_SIGPENDING,
                RLimitKind::Msgqueue => libc::RLIMIT_MSGQUEUE,
                RLimitKind::Nice => libc::RLIMIT_NICE,
                RLimitKind::Rtprio => libc::RLIMIT_RTPRIO,
                RLimitKind::Rttime => libc::RLIMIT_RTTIME,
            };
            rlimit_pairs.push((
                resource,
                libc::rlimit64 {
                    rlim_cur: r.soft,
                    rlim_max: r.hard,
                },
            ));
        }

        let caps = spec.capabilities.as_ref().map(|c| CapBitmasks {
            bounding: cap_mask(&c.bounding),
            effective: cap_mask(&c.effective),
            permitted: cap_mask(&c.permitted),
            inheritable: cap_mask(&c.inheritable),
            ambient: cap_mask(&c.ambient),
        });

        let default_devices = vec![
            DefaultDevice { path: cstr("/dev/null")?,    mode: 0o666, kind: 'c', major: 1, minor: 3 },
            DefaultDevice { path: cstr("/dev/zero")?,    mode: 0o666, kind: 'c', major: 1, minor: 5 },
            DefaultDevice { path: cstr("/dev/full")?,    mode: 0o666, kind: 'c', major: 1, minor: 7 },
            DefaultDevice { path: cstr("/dev/random")?,  mode: 0o666, kind: 'c', major: 1, minor: 8 },
            DefaultDevice { path: cstr("/dev/urandom")?, mode: 0o666, kind: 'c', major: 1, minor: 9 },
            DefaultDevice { path: cstr("/dev/tty")?,     mode: 0o666, kind: 'c', major: 5, minor: 0 },
        ];
        let default_symlinks = vec![
            (cstr("/proc/self/fd")?,  cstr("/dev/fd")?),
            (cstr("/proc/self/fd/0")?, cstr("/dev/stdin")?),
            (cstr("/proc/self/fd/1")?, cstr("/dev/stdout")?),
            (cstr("/proc/self/fd/2")?, cstr("/dev/stderr")?),
            (cstr("pts/ptmx")?,       cstr("/dev/ptmx")?),
        ];

        let masked_paths = spec
            .masked_paths
            .iter()
            .map(|s| cstr(s))
            .collect::<std::io::Result<Vec<_>>>()?;
        let readonly_paths = spec
            .readonly_paths
            .iter()
            .map(|s| cstr(s))
            .collect::<std::io::Result<Vec<_>>>()?;

        Ok(Self {
            clone_flags,
            wants_userns,
            uid_map_data,
            gid_map_data,
            hostname: cstr(&spec.hostname)?,
            set_hostname: !spec.hostname.is_empty(),
            root_path: spec.root_path.clone(),
            root_readonly: spec.root_readonly,
            mounts,
            argv,
            envp,
            cwd: cstr(&spec.cwd)?,
            rlimits: rlimit_pairs,
            caps,
            no_new_privileges: spec.no_new_privileges,
            default_devices,
            default_symlinks,
            masked_paths,
            readonly_paths,
            user_uid: spec.user_uid,
            user_gid: spec.user_gid,
            user_additional_gids: spec.user_additional_gids.clone(),
            user_umask: spec.user_umask,
        })
    }
}

/// Convert a list of OCI cap names (e.g. "CAP_NET_RAW") to a bitmask.
fn cap_mask(names: &[String]) -> u64 {
    let mut mask = 0u64;
    for n in names {
        if let Some(bit) = cap_bit(n) {
            mask |= 1u64 << bit;
        }
    }
    mask
}

/// Linux cap bit numbers per <linux/capability.h>.
fn cap_bit(name: &str) -> Option<u32> {
    let s = name.strip_prefix("CAP_").unwrap_or(name);
    Some(match s {
        "CHOWN" => 0,
        "DAC_OVERRIDE" => 1,
        "DAC_READ_SEARCH" => 2,
        "FOWNER" => 3,
        "FSETID" => 4,
        "KILL" => 5,
        "SETGID" => 6,
        "SETUID" => 7,
        "SETPCAP" => 8,
        "LINUX_IMMUTABLE" => 9,
        "NET_BIND_SERVICE" => 10,
        "NET_BROADCAST" => 11,
        "NET_ADMIN" => 12,
        "NET_RAW" => 13,
        "IPC_LOCK" => 14,
        "IPC_OWNER" => 15,
        "SYS_MODULE" => 16,
        "SYS_RAWIO" => 17,
        "SYS_CHROOT" => 18,
        "SYS_PTRACE" => 19,
        "SYS_PACCT" => 20,
        "SYS_ADMIN" => 21,
        "SYS_BOOT" => 22,
        "SYS_NICE" => 23,
        "SYS_RESOURCE" => 24,
        "SYS_TIME" => 25,
        "SYS_TTY_CONFIG" => 26,
        "MKNOD" => 27,
        "LEASE" => 28,
        "AUDIT_WRITE" => 29,
        "AUDIT_CONTROL" => 30,
        "SETFCAP" => 31,
        "MAC_OVERRIDE" => 32,
        "MAC_ADMIN" => 33,
        "SYSLOG" => 34,
        "WAKE_ALARM" => 35,
        "BLOCK_SUSPEND" => 36,
        "AUDIT_READ" => 37,
        "PERFMON" => 38,
        "BPF" => 39,
        "CHECKPOINT_RESTORE" => 40,
        _ => return None,
    })
}

/// Format an OCI uidMappings/gidMappings array into the kernel's
/// /proc/<pid>/uid_map line format: "container host size\n" per line.
fn format_id_map(mappings: &[crate::spec::IdMapping]) -> Vec<u8> {
    let mut out = Vec::with_capacity(mappings.len() * 32);
    for m in mappings {
        use std::io::Write as _;
        let _ = writeln!(out, "{} {} {}", m.container_id, m.host_id, m.size);
    }
    out
}

fn compile_mount(m: &crate::spec::MountSpec, root: &std::path::Path) -> std::io::Result<MountOp> {
    use nix::mount::MsFlags;
    let mut flags = MsFlags::empty();
    let mut data_parts = Vec::new();
    for opt in &m.options {
        match opt.as_str() {
            "ro" => flags |= MsFlags::MS_RDONLY,
            "rw" => {} // default
            "nosuid" => flags |= MsFlags::MS_NOSUID,
            "nodev" => flags |= MsFlags::MS_NODEV,
            "noexec" => flags |= MsFlags::MS_NOEXEC,
            "relatime" => flags |= MsFlags::MS_RELATIME,
            "noatime" => flags |= MsFlags::MS_NOATIME,
            "strictatime" => flags |= MsFlags::MS_STRICTATIME,
            "bind" => flags |= MsFlags::MS_BIND,
            "rbind" => flags |= MsFlags::MS_BIND | MsFlags::MS_REC,
            "private" => flags |= MsFlags::MS_PRIVATE,
            "rprivate" => flags |= MsFlags::MS_PRIVATE | MsFlags::MS_REC,
            "shared" => flags |= MsFlags::MS_SHARED,
            "rshared" => flags |= MsFlags::MS_SHARED | MsFlags::MS_REC,
            "slave" => flags |= MsFlags::MS_SLAVE,
            "rslave" => flags |= MsFlags::MS_SLAVE | MsFlags::MS_REC,
            other => data_parts.push(other.to_string()),
        }
    }
    let data = if data_parts.is_empty() {
        None
    } else {
        Some(cstr(&data_parts.join(","))?)
    };

    // Destination is interpreted relative to the new rootfs, but at mount
    // time we're still in the host mount-ns and pivot_root hasn't happened.
    // We mount at <rootfs>/<destination> and pivot_root will see the right
    // tree.
    let dst_rel = m.destination.trim_start_matches('/');
    let target = root.join(dst_rel);

    Ok(MountOp {
        source: cstr(&m.source)?,
        target,
        fstype: cstr(&m.fstype)?,
        flags,
        data,
    })
}

fn cstr(s: &str) -> std::io::Result<CString> {
    CString::new(s).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "string contains NUL byte")
    })
}
