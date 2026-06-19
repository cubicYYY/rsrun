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
    pub namespaces: Vec<NamespaceKind>,
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
    /// linux.maskedPaths: bind-mount /dev/null over each (file) or
    /// remount tmpfs RDONLY over each (dir).
    pub masked_paths: Vec<String>,
    /// linux.readonlyPaths: bind-mount each onto itself with MS_RDONLY.
    pub readonly_paths: Vec<String>,
    pub user_uid: u32,
    pub user_gid: u32,
    pub user_additional_gids: Vec<u32>,
    pub user_umask: Option<u32>,
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

#[derive(Debug, Clone)]
pub struct MountSpec {
    pub destination: String,
    pub source: String,
    pub fstype: String,
    pub options: Vec<String>,
}

impl Spec {
    pub fn from_bundle(bundle: &std::path::Path) -> std::io::Result<Self> {
        let path = bundle.join("config.json");
        let bytes = std::fs::read(&path)?;
        let v: Value = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let process = v.get("process").ok_or_else(missing("process"))?;
        let args = string_array(process.get("args").ok_or_else(missing("process.args"))?);
        let env = process
            .get("env")
            .map(string_array)
            .unwrap_or_default();
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
        if let Some(linux) = v.get("linux") {
            if let Some(arr) = linux.get("maskedPaths").and_then(Value::as_array) {
                masked_paths.extend(
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from)),
                );
            }
            if let Some(arr) = linux.get("readonlyPaths").and_then(Value::as_array) {
                readonly_paths.extend(
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from)),
                );
            }
            if let Some(nsa) = linux.get("namespaces").and_then(Value::as_array) {
                for ns in nsa {
                    if let Some(ty) = ns.get("type").and_then(Value::as_str) {
                        if let Some(k) = parse_ns(ty) {
                            namespaces.push(k);
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
                let options = m
                    .get("options")
                    .map(string_array)
                    .unwrap_or_default();
                mounts.push(MountSpec {
                    destination,
                    source,
                    fstype,
                    options,
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
