//! Minimal OCI spec subset.
//!
//! Parses just the fields rsrun acts on. Unknown fields are ignored.

use serde_json::Value;
use std::path::PathBuf;

/// What we extract from `config.json`. Everything else is dropped at parse time.
#[derive(Debug, Clone)]
pub struct Spec {
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: String,
    pub terminal: bool,
    pub root_path: PathBuf,
    pub root_readonly: bool,
    pub hostname: String,
    pub namespaces: Vec<NamespaceEntry>,
    pub mounts: Vec<MountSpec>,
    /// Rootless: uid mappings (containerID, hostID, size) tuples.
    /// Empty when not running rootless.
    pub uid_mappings: Vec<IdMapping>,
    pub gid_mappings: Vec<IdMapping>,
    /// process.rlimits: list of resource limits to apply.
    pub rlimits: Vec<RLimit>,
    /// process.capabilities: separate sets. None means "leave inherited".
    pub capabilities: Option<Capabilities>,
    /// process.noNewPrivileges: set PR_SET_NO_NEW_PRIVS before exec.
    pub no_new_privileges: bool,
    /// process.apparmorProfile: profile name to transition into at exec.
    /// None / empty = no transition.
    pub apparmor_profile: Option<String>,
    /// process.selinuxLabel: SELinux exec context. None / empty = no
    /// transition.
    pub selinux_label: Option<String>,
    /// linux.sysctl: key→value pairs written to /proc/sys/<key> inside
    /// the container's namespaces (only namespaced sysctls are
    /// allowed by the kernel). Keys use dot notation
    /// (e.g. "net.ipv4.ip_forward"); we translate to slash paths.
    pub sysctls: Vec<(String, String)>,
    /// linux.rootfsPropagation: one of "shared", "slave", "private",
    /// "unbindable" (or recursive `r*` variants). Applied to `/` after
    /// pivot_root. None = leave at MS_PRIVATE (rsrun's default).
    pub rootfs_propagation: Option<String>,
    /// process.oomScoreAdj: -1000..=1000. Written to
    /// /proc/<init>/oom_score_adj from the parent after clone3.
    pub oom_score_adj: Option<i32>,
    /// linux.maskedPaths: bind-mount /dev/null over each (file) or
    /// remount tmpfs RDONLY over each (dir).
    pub masked_paths: Vec<String>,
    /// linux.readonlyPaths: bind-mount each onto itself with MS_RDONLY.
    pub readonly_paths: Vec<String>,
    pub user_uid: u32,
    pub user_gid: u32,
    pub user_additional_gids: Vec<u32>,
    pub user_umask: Option<u32>,
    /// Raw parsed config.json. Kept so ext can parse seccomp, cgroup
    /// resources, hooks, and devices without re-reading the file.
    pub raw: Value,
    /// Bundle directory (the `-b` argument to `rsrun create`). Hook
    /// commands and seccomp profile paths may be resolved relative
    /// to this.
    pub bundle: PathBuf,
}

#[derive(Debug, Clone, Copy)]
pub struct RLimit {
    pub kind: RLimitKind,
    pub soft: u64,
    pub hard: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RLimitKind {
    Cpu,
    Fsize,
    Data,
    Stack,
    Core,
    Rss,
    Nproc,
    Nofile,
    Memlock,
    As,
    Locks,
    Sigpending,
    Msgqueue,
    Nice,
    Rtprio,
    Rttime,
}

#[derive(Debug, Clone)]
pub struct Capabilities {
    pub bounding: Vec<String>,
    pub effective: Vec<String>,
    pub permitted: Vec<String>,
    pub inheritable: Vec<String>,
    pub ambient: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct IdMapping {
    pub container_id: u32,
    pub host_id: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceKind {
    Pid,
    Network,
    Mount,
    Ipc,
    Uts,
    User,
    Cgroup,
}

/// A namespace declaration. `path = None` means create a fresh namespace
/// (the standard case); `path = Some(p)` means setns(2) into the
/// pre-existing namespace at that path. The latter is what the daemon
/// uses for pre-warmed namespace pools.
#[derive(Debug, Clone)]
pub struct NamespaceEntry {
    pub kind: NamespaceKind,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct MountSpec {
    pub destination: String,
    pub source: String,
    pub fstype: String,
    pub options: Vec<String>,
    /// `linux.mounts[].uidMappings` and `gidMappings` — the OCI
    /// idmapped-mount feature. Empty = no idmap. When set, the
    /// runtime spawns a helper task with these mappings, opens its
    /// user-ns fd, and applies `mount_setattr(MOUNT_ATTR_IDMAP)` to
    /// the mount post-bind. Linux 5.12+.
    pub uid_mappings: Vec<IdMapping>,
    pub gid_mappings: Vec<IdMapping>,
}

impl Spec {
    pub fn from_bundle(bundle: &std::path::Path) -> std::io::Result<Self> {
        let path = bundle.join("config.json");
        let bytes = std::fs::read(&path)?;
        let v: Value = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Self::from_value(v, bundle)
    }

    /// Test-friendly variant that takes a parsed JSON value directly,
    /// without reading from disk. Used by unit tests; production callers
    /// go through `from_bundle`.
    pub fn from_value(v: Value, bundle: &std::path::Path) -> std::io::Result<Self> {
        let process = v.get("process").ok_or_else(missing("process"))?;
        let args = string_array(process.get("args").ok_or_else(missing("process.args"))?);
        let env = process.get("env").map(string_array).unwrap_or_default();
        let cwd = process
            .get("cwd")
            .and_then(Value::as_str)
            .unwrap_or("/")
            .to_string();
        let terminal = process
            .get("terminal")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let no_new_privileges = process
            .get("noNewPrivileges")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let oom_score_adj = process
            .get("oomScoreAdj")
            .and_then(Value::as_i64)
            .map(|n| n as i32);
        let apparmor_profile = process
            .get("apparmorProfile")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from);
        let selinux_label = process
            .get("selinuxLabel")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from);

        let mut rlimits = Vec::new();
        if let Some(arr) = process.get("rlimits").and_then(Value::as_array) {
            for r in arr {
                if let Some(rl) = parse_rlimit(r) {
                    rlimits.push(rl);
                }
            }
        }

        let capabilities = process.get("capabilities").map(parse_capabilities);

        let user = process.get("user");
        let user_uid = user
            .and_then(|u| u.get("uid"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        let user_gid = user
            .and_then(|u| u.get("gid"))
            .and_then(Value::as_u64)
            .unwrap_or(0) as u32;
        let user_additional_gids = user
            .and_then(|u| u.get("additionalGids"))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u32))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let user_umask = user
            .and_then(|u| u.get("umask"))
            .and_then(Value::as_u64)
            .map(|n| n as u32);

        let root = v.get("root").ok_or_else(missing("root"))?;
        let root_rel = root
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(missing("root.path"))?;
        let root_path = if std::path::Path::new(root_rel).is_absolute() {
            PathBuf::from(root_rel)
        } else {
            bundle.join(root_rel)
        };
        let root_readonly = root
            .get("readonly")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let hostname = v
            .get("hostname")
            .and_then(Value::as_str)
            .unwrap_or("rsrun")
            .to_string();

        let mut namespaces = Vec::new();
        let mut uid_mappings = Vec::new();
        let mut gid_mappings = Vec::new();
        let mut masked_paths = Vec::new();
        let mut readonly_paths = Vec::new();
        let mut sysctls: Vec<(String, String)> = Vec::new();
        let mut rootfs_propagation = None;
        if let Some(linux) = v.get("linux") {
            if let Some(obj) = linux.get("sysctl").and_then(Value::as_object) {
                for (k, val) in obj {
                    if let Some(s) = val.as_str() {
                        sysctls.push((k.clone(), s.to_string()));
                    }
                }
            }
            rootfs_propagation = linux
                .get("rootfsPropagation")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(String::from);
            if let Some(arr) = linux.get("maskedPaths").and_then(Value::as_array) {
                masked_paths.extend(arr.iter().filter_map(|v| v.as_str().map(String::from)));
            }
            if let Some(arr) = linux.get("readonlyPaths").and_then(Value::as_array) {
                readonly_paths.extend(arr.iter().filter_map(|v| v.as_str().map(String::from)));
            }
            if let Some(nsa) = linux.get("namespaces").and_then(Value::as_array) {
                for ns in nsa {
                    if let Some(ty) = ns.get("type").and_then(Value::as_str) {
                        if let Some(k) = parse_ns(ty) {
                            let path = ns
                                .get("path")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                                .map(PathBuf::from);
                            namespaces.push(NamespaceEntry { kind: k, path });
                        }
                    }
                }
            }
            if let Some(arr) = linux.get("uidMappings").and_then(Value::as_array) {
                for m in arr {
                    if let Some(im) = parse_mapping(m) {
                        uid_mappings.push(im);
                    }
                }
            }
            if let Some(arr) = linux.get("gidMappings").and_then(Value::as_array) {
                for m in arr {
                    if let Some(im) = parse_mapping(m) {
                        gid_mappings.push(im);
                    }
                }
            }
        }

        let mut mounts = Vec::new();
        if let Some(ma) = v.get("mounts").and_then(Value::as_array) {
            for m in ma {
                let destination = m
                    .get("destination")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if destination.is_empty() {
                    continue;
                }
                let source = m
                    .get("source")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let fstype = m
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or("none")
                    .to_string();
                let options = m.get("options").map(string_array).unwrap_or_default();
                let parse_maps = |key: &str| -> Vec<IdMapping> {
                    m.get(key)
                        .and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(parse_mapping).collect())
                        .unwrap_or_default()
                };
                mounts.push(MountSpec {
                    destination,
                    source,
                    fstype,
                    options,
                    uid_mappings: parse_maps("uidMappings"),
                    gid_mappings: parse_maps("gidMappings"),
                });
            }
        }

        Ok(Spec {
            args,
            env,
            cwd,
            terminal,
            root_path,
            root_readonly,
            hostname,
            namespaces,
            mounts,
            uid_mappings,
            gid_mappings,
            rlimits,
            capabilities,
            no_new_privileges,
            masked_paths,
            readonly_paths,
            user_uid,
            user_gid,
            user_additional_gids,
            user_umask,
            apparmor_profile,
            selinux_label,
            sysctls,
            rootfs_propagation,
            oom_score_adj,
            raw: v,
            bundle: bundle.to_path_buf(),
        })
    }
}

fn parse_rlimit(v: &Value) -> Option<RLimit> {
    let ty = v.get("type").and_then(Value::as_str)?;
    let soft = v.get("soft").and_then(Value::as_u64)?;
    let hard = v.get("hard").and_then(Value::as_u64)?;
    let kind = match ty {
        "RLIMIT_CPU" => RLimitKind::Cpu,
        "RLIMIT_FSIZE" => RLimitKind::Fsize,
        "RLIMIT_DATA" => RLimitKind::Data,
        "RLIMIT_STACK" => RLimitKind::Stack,
        "RLIMIT_CORE" => RLimitKind::Core,
        "RLIMIT_RSS" => RLimitKind::Rss,
        "RLIMIT_NPROC" => RLimitKind::Nproc,
        "RLIMIT_NOFILE" => RLimitKind::Nofile,
        "RLIMIT_MEMLOCK" => RLimitKind::Memlock,
        "RLIMIT_AS" => RLimitKind::As,
        "RLIMIT_LOCKS" => RLimitKind::Locks,
        "RLIMIT_SIGPENDING" => RLimitKind::Sigpending,
        "RLIMIT_MSGQUEUE" => RLimitKind::Msgqueue,
        "RLIMIT_NICE" => RLimitKind::Nice,
        "RLIMIT_RTPRIO" => RLimitKind::Rtprio,
        "RLIMIT_RTTIME" => RLimitKind::Rttime,
        _ => return None,
    };
    Some(RLimit { kind, soft, hard })
}

fn parse_capabilities(v: &Value) -> Capabilities {
    let get = |key: &str| -> Vec<String> {
        v.get(key)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    Capabilities {
        bounding: get("bounding"),
        effective: get("effective"),
        permitted: get("permitted"),
        inheritable: get("inheritable"),
        ambient: get("ambient"),
    }
}

fn parse_mapping(v: &Value) -> Option<IdMapping> {
    let c = v.get("containerID").and_then(Value::as_u64)?;
    let h = v.get("hostID").and_then(Value::as_u64)?;
    let s = v.get("size").and_then(Value::as_u64)?;
    Some(IdMapping {
        container_id: c as u32,
        host_id: h as u32,
        size: s as u32,
    })
}

fn parse_ns(s: &str) -> Option<NamespaceKind> {
    Some(match s {
        "pid" => NamespaceKind::Pid,
        "network" => NamespaceKind::Network,
        "mount" => NamespaceKind::Mount,
        "ipc" => NamespaceKind::Ipc,
        "uts" => NamespaceKind::Uts,
        "user" => NamespaceKind::User,
        "cgroup" => NamespaceKind::Cgroup,
        _ => return None,
    })
}

fn string_array(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn missing(field: &'static str) -> impl Fn() -> std::io::Error {
    move || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("missing OCI field: {field}"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;

    fn minimal() -> serde_json::Value {
        json!({
            "process": {"args": ["/bin/true"]},
            "root": {"path": "rootfs"}
        })
    }

    #[test]
    fn defaults_when_optional_fields_missing() {
        let spec = Spec::from_value(minimal(), Path::new("/bundle")).unwrap();
        assert_eq!(spec.args, vec!["/bin/true".to_string()]);
        assert!(spec.env.is_empty());
        assert_eq!(spec.cwd, "/");
        assert!(!spec.terminal);
        assert!(!spec.no_new_privileges);
        assert!(!spec.root_readonly);
        assert_eq!(spec.hostname, "rsrun");
        assert!(spec.namespaces.is_empty());
        assert_eq!(spec.user_uid, 0);
        assert_eq!(spec.user_gid, 0);
    }

    #[test]
    fn missing_required_field_errors() {
        let no_process = json!({"root": {"path": "rootfs"}});
        assert!(Spec::from_value(no_process, Path::new("/bundle")).is_err());

        let no_root = json!({"process": {"args": ["/bin/true"]}});
        assert!(Spec::from_value(no_root, Path::new("/bundle")).is_err());

        let no_args = json!({"process": {}, "root": {"path": "rootfs"}});
        assert!(Spec::from_value(no_args, Path::new("/bundle")).is_err());
    }

    #[test]
    fn relative_rootfs_resolves_against_bundle() {
        let v = minimal();
        let spec = Spec::from_value(v, Path::new("/bundle")).unwrap();
        assert_eq!(spec.root_path, Path::new("/bundle/rootfs"));
    }

    #[test]
    fn absolute_rootfs_unchanged() {
        let v = json!({
            "process": {"args": ["/bin/true"]},
            "root": {"path": "/abs/rootfs"}
        });
        let spec = Spec::from_value(v, Path::new("/bundle")).unwrap();
        assert_eq!(spec.root_path, Path::new("/abs/rootfs"));
    }

    #[test]
    fn namespaces_with_and_without_path() {
        let v = json!({
            "process": {"args": ["/bin/true"]},
            "root": {"path": "rootfs"},
            "linux": {
                "namespaces": [
                    {"type": "pid"},
                    {"type": "network", "path": "/var/run/netns/red"},
                    {"type": "user", "path": ""}
                ]
            }
        });
        let spec = Spec::from_value(v, Path::new("/bundle")).unwrap();
        assert_eq!(spec.namespaces.len(), 3);
        assert_eq!(spec.namespaces[0].kind, NamespaceKind::Pid);
        assert!(spec.namespaces[0].path.is_none());
        assert_eq!(spec.namespaces[1].kind, NamespaceKind::Network);
        assert_eq!(
            spec.namespaces[1].path.as_deref(),
            Some(Path::new("/var/run/netns/red"))
        );
        // Empty string is treated as "no path" (regression: `path: ""`
        // shouldn't kick the namespace into setns mode).
        assert_eq!(spec.namespaces[2].kind, NamespaceKind::User);
        assert!(spec.namespaces[2].path.is_none());
    }

    #[test]
    fn rlimits_and_capabilities() {
        let v = json!({
            "process": {
                "args": ["/bin/true"],
                "rlimits": [
                    {"type": "RLIMIT_NOFILE", "soft": 1024, "hard": 4096},
                    {"type": "RLIMIT_NOTAREAL", "soft": 1, "hard": 1}
                ],
                "capabilities": {
                    "bounding": ["CAP_NET_BIND_SERVICE"],
                    "effective": ["CAP_NET_BIND_SERVICE"],
                    "permitted": ["CAP_NET_BIND_SERVICE"],
                    "inheritable": [],
                    "ambient": []
                }
            },
            "root": {"path": "rootfs"}
        });
        let spec = Spec::from_value(v, Path::new("/bundle")).unwrap();
        // Unknown rlimit kinds are dropped, valid one survives.
        assert_eq!(spec.rlimits.len(), 1);
        assert_eq!(spec.rlimits[0].kind, RLimitKind::Nofile);
        assert_eq!(spec.rlimits[0].soft, 1024);
        let caps = spec.capabilities.unwrap();
        assert_eq!(caps.bounding, vec!["CAP_NET_BIND_SERVICE".to_string()]);
        assert!(caps.inheritable.is_empty());
    }

    #[test]
    fn empty_hostname_uses_rsrun_default() {
        // Spec parser substitutes "rsrun" when hostname is absent.
        // Empty-string in spec is honored verbatim (caller decides
        // semantics); plan converts empty to set_hostname=false.
        let mut v = minimal();
        v["hostname"] = json!("");
        let spec = Spec::from_value(v, Path::new("/bundle")).unwrap();
        assert_eq!(spec.hostname, "");
    }
}
