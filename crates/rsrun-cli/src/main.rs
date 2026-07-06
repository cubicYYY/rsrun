//! rsrun — a small OCI runtime in Rust.

use rsrun_core as runtime;

use clap::{Parser, Subcommand};
#[cfg(feature = "rollout")]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::ExitCode;

/// Top-level CLI. Global options follow the standard OCI-runtime
/// shape so containerd's shim can drive rsrun without translation.
#[derive(Parser)]
#[command(name = "rsrun", version, about = "A small OCI runtime in Rust.")]
struct Cli {
    /// Override the per-container state directory (default /run/rsrun).
    #[arg(long, global = true)]
    root: Option<String>,

    /// Redirect rsrun's stderr to this file. containerd reads it on failure.
    #[arg(long, global = true)]
    log: Option<String>,

    /// `text` (default) or `json`. JSON emits `{"level":"error",...}` on stderr.
    #[arg(long = "log-format", global = true)]
    log_format: Option<String>,

    /// Accepted for engine compatibility; rootless is autodetected by uid.
    #[arg(long, global = true)]
    rootless: Option<String>,

    /// Accepted for engine compatibility; no cgroup driver yet.
    #[arg(long = "systemd-cgroup", global = true)]
    systemd_cgroup: bool,

    /// Accepted for engine compatibility; no-op.
    #[arg(long, global = true)]
    debug: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Cmd {
    /// Create a container from an OCI bundle. Init blocks until `start`.
    Create {
        #[arg(short, long, default_value = ".")]
        bundle: PathBuf,
        #[arg(long = "pid-file")]
        pid_file: Option<PathBuf>,
        /// AF_UNIX socket the engine listens on for the PTY master fd.
        /// Used when the bundle sets `process.terminal: true`.
        #[arg(long = "console-socket")]
        console_socket: Option<PathBuf>,
        /// Pass extra file descriptors 3..=N+2 into the container's
        /// init. Used by systemd socket-activation and by engines
        /// that pre-bind listening sockets.
        #[arg(long = "preserve-fds")]
        preserve_fds: Option<u32>,
        /// Use chroot(2) instead of pivot_root(2). Required for
        /// read-only rootfs setups where pivot_root would fail.
        #[arg(long = "no-pivot")]
        no_pivot: bool,
        /// Bound create, including parent-side hooks.
        #[arg(long)]
        timeout: Option<String>,
        id: String,
    },
    /// Unblock the created container; the workload begins running.
    Start {
        /// Bound start, including parent-side poststart hooks.
        #[arg(long)]
        timeout: Option<String>,
        id: String,
    },
    /// Stop the container (if `--force`) and remove its state.
    Delete {
        #[arg(short, long)]
        force: bool,
        /// Bound delete, including poststop hooks and cleanup.
        #[arg(long)]
        timeout: Option<String>,
        id: String,
    },
    /// Reset an overlayfs-backed stopped container rootfs.
    #[cfg(feature = "rollout")]
    Reset {
        #[arg(long)]
        json: bool,
        id: String,
    },
    /// List changed files for an overlayfs-backed container.
    #[cfg(feature = "rollout")]
    ChangedFiles {
        #[arg(long)]
        json: bool,
        id: String,
    },
    /// Print filesystem diff metadata for an overlayfs-backed container.
    #[cfg(feature = "rollout")]
    Diff {
        #[arg(long)]
        json: bool,
        id: String,
    },
    /// Export an overlayfs diff.
    #[cfg(feature = "rollout")]
    ExportDiff {
        #[arg(long, default_value = "tar")]
        format: String,
        id: String,
    },
    /// Save a named filesystem marker for later effects comparison.
    #[cfg(feature = "rollout")]
    Mark { id: String, name: String },
    /// Show filesystem effects since a named marker.
    #[cfg(feature = "rollout")]
    Effects {
        #[arg(long)]
        since: String,
        #[arg(long)]
        json: bool,
        id: String,
    },
    /// Snapshot the filesystem state of an overlayfs-backed stopped container.
    #[cfg(feature = "rollout")]
    Snapshot { id: String, snapshot_id: String },
    /// Save the current writable layer as an immutable checkpoint layer.
    #[cfg(feature = "rollout")]
    Checkpoint {
        #[arg(long)]
        json: bool,
        #[arg(long, default_value = "directory")]
        pack: String,
        id: String,
        checkpoint_id: String,
    },
    /// Export a checkpoint as a portable artifact.
    #[cfg(feature = "rollout")]
    ExportCheckpoint {
        #[arg(long, default_value = "tar")]
        format: String,
        checkpoint_id: String,
    },
    /// Import a portable checkpoint artifact.
    #[cfg(feature = "rollout")]
    ImportCheckpoint {
        #[arg(long)]
        json: bool,
        checkpoint_id: String,
        artifact: PathBuf,
    },
    /// Restore a filesystem snapshot as a new stopped overlayfs-backed state.
    #[cfg(feature = "rollout")]
    Restore {
        #[arg(long)]
        json: bool,
        snapshot_id: String,
        new_id: String,
    },
    /// Fork a checkpoint into a new stopped state with an empty writable layer.
    #[cfg(feature = "rollout")]
    ForkCheckpoint {
        #[arg(long)]
        json: bool,
        checkpoint_id: String,
        new_id: String,
    },
    /// Fork a stopped overlayfs-backed container filesystem into a new state.
    #[cfg(feature = "rollout")]
    Fork {
        #[arg(long)]
        json: bool,
        id: String,
        new_id: String,
    },
    /// Activate a stopped rollout state so it can be started and exec'd.
    #[cfg(feature = "rollout")]
    Activate {
        #[arg(short, long)]
        bundle: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        timeout: Option<String>,
        id: String,
    },
    /// Print the OCI state document for the container.
    State { id: String },
    /// Send a signal to the container init. Defaults to TERM (Docker compat).
    Kill {
        id: String,
        #[arg(default_value = "TERM")]
        signal: String,
    },
    /// Run a process inside a running container (the CVE-2019-5736 path).
    #[cfg_attr(feature = "rollout", command(trailing_var_arg = true))]
    Exec {
        #[arg(short = 'p', long)]
        process: Option<PathBuf>,
        #[arg(long = "pid-file")]
        pid_file: Option<PathBuf>,
        #[arg(short, long)]
        detach: bool,
        /// Rollout mode: maximum wall time before terminating the exec.
        #[cfg(feature = "rollout")]
        #[arg(long)]
        timeout: Option<String>,
        /// Rollout mode: signal the exec process group on timeout.
        #[cfg(feature = "rollout")]
        #[arg(long = "kill-tree")]
        kill_tree: bool,
        /// Rollout mode: per-stream captured output limit.
        #[cfg(feature = "rollout")]
        #[arg(long = "max-output-bytes", default_value_t = 2 * 1024 * 1024)]
        max_output_bytes: usize,
        /// Rollout mode: emit a structured result object.
        #[cfg(feature = "rollout")]
        #[arg(long)]
        json: bool,
        /// Rollout mode: read stdin payload from a file, or `-` for stdin.
        #[cfg(feature = "rollout")]
        #[arg(long)]
        stdin: Option<PathBuf>,
        // Args below accepted for engine compatibility but unused here.
        #[arg(short, long)]
        _tty: bool,
        #[arg(long = "console-socket")]
        console_socket: Option<PathBuf>,
        #[arg(long = "pidfd-socket")]
        _pidfd_socket: Option<String>,
        #[arg(short, long)]
        _user: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(short, long)]
        env: Vec<String>,
        #[arg(long = "additional-gids")]
        _additional_gids: Option<String>,
        #[arg(long)]
        _apparmor: Option<String>,
        #[arg(long)]
        _cap: Vec<String>,
        #[arg(long = "no-new-privs")]
        _no_new_privs: bool,
        #[arg(long = "preserve-fds")]
        _preserve_fds: Option<String>,
        id: String,
        /// Rollout mode command. Use `--` before the command.
        #[cfg(feature = "rollout")]
        command: Vec<String>,
    },
    /// Emit the runtime feature descriptor JSON Docker queries at registration.
    Features,
    /// Check whether an OCI bundle is supported before running it.
    ValidateBundle {
        bundle: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// List known containers.
    List,
    /// Not implemented.
    Spec,
    /// Freeze a running container's processes (cgroup-v2 cgroup.freeze).
    #[cfg(feature = "pause")]
    Pause { id: String },
    /// Unfreeze a paused container.
    #[cfg(feature = "pause")]
    Resume { id: String },
    /// Re-write the cgroup-v2 resource limits of a running container.
    #[cfg(feature = "update")]
    Update {
        /// Path to a JSON file with the OCI `linux.resources` shape;
        /// reads stdin if absent.
        #[arg(short, long, alias = "resources")]
        resources: Option<PathBuf>,
        id: String,
    },
    /// Print one JSON line of cgroup-v2 metrics for a running container.
    #[cfg(feature = "stats")]
    Stats { id: String },
    /// Stream cgroup-v2 metrics every second (or one shot with --stats).
    #[cfg(feature = "stats")]
    Events {
        /// Print one snapshot and exit.
        #[arg(long)]
        stats: bool,
        id: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    if command_needs_sealed_reexec(&cli.cmd) {
        if let Err(e) = reexec_from_sealed_memfd() {
            eprintln!("rsrun: CVE-2019-5736 mitigation failed: {e}");
            return ExitCode::from(1);
        }
    }

    if let Some(p) = &cli.root {
        std::env::set_var("RSRUN_ROOT", p);
    }
    if cli.log_format.as_deref() == Some("json") {
        std::env::set_var("RSRUN_LOG_FORMAT_JSON", "1");
    }
    if cli.systemd_cgroup {
        std::env::set_var("RSRUN_SYSTEMD_CGROUP", "1");
    }

    // If --log was given, redirect stderr to it. containerd reads this
    // file on failure to recover the runtime's error message. The file
    // is created unconditionally so containerd never sees ENOENT.
    if let Some(p) = cli.log.as_deref() {
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(p)
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::dup2(file.as_raw_fd(), 2);
            }
            drop(file);
        }
    }

    let res: std::io::Result<()> = match cli.cmd {
        Cmd::Create {
            bundle,
            pid_file,
            console_socket,
            preserve_fds,
            no_pivot,
            timeout,
            id,
        } => parse_optional_duration_ms(timeout.as_deref()).and_then(|timeout_ms| {
            create_with_ext(
                &id,
                &bundle,
                pid_file.as_deref(),
                console_socket.as_deref(),
                preserve_fds.unwrap_or(0),
                no_pivot,
                timeout_ms,
            )
        }),
        Cmd::Start { timeout, id } => parse_optional_duration_ms(timeout.as_deref())
            .and_then(|timeout_ms| runtime::cmd_start_with_timeout(&id, timeout_ms)),
        Cmd::Delete { force, timeout, id } => parse_optional_duration_ms(timeout.as_deref())
            .and_then(|timeout_ms| runtime::cmd_delete_with_timeout(&id, force, timeout_ms)),
        #[cfg(feature = "rollout")]
        Cmd::Reset { json, id } => runtime::rollout::cmd_reset(&id, json),
        #[cfg(feature = "rollout")]
        Cmd::ChangedFiles { json, id } => runtime::rollout::cmd_changed_files(&id, json),
        #[cfg(feature = "rollout")]
        Cmd::Diff { json, id } => runtime::rollout::cmd_diff(&id, json),
        #[cfg(feature = "rollout")]
        Cmd::ExportDiff { format, id } => runtime::rollout::cmd_export_diff(&id, &format),
        #[cfg(feature = "rollout")]
        Cmd::Mark { id, name } => runtime::rollout::cmd_mark(&id, &name),
        #[cfg(feature = "rollout")]
        Cmd::Effects { since, json, id } => runtime::rollout::cmd_effects(&id, &since, json),
        #[cfg(feature = "rollout")]
        Cmd::Snapshot { id, snapshot_id } => runtime::rollout::cmd_snapshot(&id, &snapshot_id),
        #[cfg(feature = "rollout")]
        Cmd::Checkpoint {
            json,
            pack,
            id,
            checkpoint_id,
        } => runtime::rollout::cmd_checkpoint(&id, &checkpoint_id, &pack, json),
        #[cfg(feature = "rollout")]
        Cmd::ExportCheckpoint {
            format,
            checkpoint_id,
        } => runtime::rollout::cmd_export_checkpoint(&checkpoint_id, &format),
        #[cfg(feature = "rollout")]
        Cmd::ImportCheckpoint {
            json,
            checkpoint_id,
            artifact,
        } => runtime::rollout::cmd_import_checkpoint(&checkpoint_id, &artifact, json),
        #[cfg(feature = "rollout")]
        Cmd::Restore {
            json,
            snapshot_id,
            new_id,
        } => runtime::rollout::cmd_restore(&snapshot_id, &new_id, json),
        #[cfg(feature = "rollout")]
        Cmd::ForkCheckpoint {
            json,
            checkpoint_id,
            new_id,
        } => runtime::rollout::cmd_fork_checkpoint(&checkpoint_id, &new_id, json),
        #[cfg(feature = "rollout")]
        Cmd::Fork { json, id, new_id } => runtime::rollout::cmd_fork(&id, &new_id, json),
        #[cfg(feature = "rollout")]
        Cmd::Activate {
            bundle,
            json,
            timeout,
            id,
        } => parse_optional_duration_ms(timeout.as_deref())
            .and_then(|timeout_ms| activate_with_ext(&id, bundle.as_deref(), json, timeout_ms)),
        Cmd::State { id } => runtime::cmd_state(&id),
        Cmd::Kill { id, signal } => runtime::cmd_kill(&id, &signal),
        Cmd::Exec {
            process,
            pid_file,
            detach,
            id,
            console_socket,
            #[cfg(feature = "rollout")]
            timeout,
            #[cfg(feature = "rollout")]
            kill_tree,
            #[cfg(feature = "rollout")]
            max_output_bytes,
            #[cfg(feature = "rollout")]
            json,
            #[cfg(feature = "rollout")]
            stdin,
            cwd,
            env,
            #[cfg(feature = "rollout")]
            command,
            ..
        } => (|| -> std::io::Result<()> {
            #[cfg(feature = "rollout")]
            if !command.is_empty() {
                if detach {
                    Err(std::io::Error::other(
                        "direct exec command form does not support --detach",
                    ))
                } else if console_socket.is_some() {
                    Err(std::io::Error::other(
                        "direct exec command form does not support --console-socket",
                    ))
                } else {
                    let opts = runtime::rollout::RolloutExecOpts {
                        timeout_ms: match timeout.as_deref() {
                            Some(s) => Some(parse_duration_ms(s)?),
                            None => None,
                        },
                        kill_tree,
                        max_output_bytes,
                        cwd,
                        env,
                        json,
                        stdin: read_exec_stdin(stdin.as_deref())?,
                    };
                    runtime::rollout::cmd_exec_rollout(&id, &command, opts)
                }
            } else {
                let _ = (&cwd, &env);
                let process = process.ok_or_else(|| {
                    std::io::Error::other("exec requires either -p/--process or a command after --")
                })?;
                runtime::cmd_exec_full(
                    &id,
                    &process,
                    pid_file.as_deref(),
                    detach,
                    console_socket.as_deref(),
                )
            }
            #[cfg(not(feature = "rollout"))]
            {
                let _ = (&cwd, &env);
                let process = process.ok_or_else(|| {
                    std::io::Error::other("exec requires -p/--process in this build")
                })?;
                runtime::cmd_exec_full(
                    &id,
                    &process,
                    pid_file.as_deref(),
                    detach,
                    console_socket.as_deref(),
                )
            }
        })(),
        Cmd::Features => sub_features(),
        Cmd::ValidateBundle { bundle, json } => validate_bundle(&bundle, json),
        Cmd::List => runtime::cmd_list(),
        Cmd::Spec => Err(std::io::Error::other("spec subcommand not implemented")),
        #[cfg(feature = "pause")]
        Cmd::Pause { id } => runtime::cmd_pause(&id),
        #[cfg(feature = "pause")]
        Cmd::Resume { id } => runtime::cmd_resume(&id),
        #[cfg(feature = "update")]
        Cmd::Update { resources, id } => runtime::cmd_update(&id, resources.as_deref()),
        #[cfg(feature = "stats")]
        Cmd::Stats { id } => runtime::cmd_stats(&id),
        #[cfg(feature = "stats")]
        Cmd::Events { stats, id } => runtime::cmd_events(&id, stats),
    };

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // containerd parses log.json line-by-line as
            //   {"level":"error","time":"...","msg":"..."}
            // when invoked with --log-format json.
            if std::env::var_os("RSRUN_LOG_FORMAT_JSON").is_some() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let mut tm: libc::tm = unsafe { std::mem::zeroed() };
                let t: libc::time_t = now as libc::time_t;
                let ts = unsafe {
                    if libc::gmtime_r(&t, &mut tm).is_null() {
                        "1970-01-01T00:00:00Z".to_string()
                    } else {
                        format!(
                            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                            tm.tm_year + 1900,
                            tm.tm_mon + 1,
                            tm.tm_mday,
                            tm.tm_hour,
                            tm.tm_min,
                            tm.tm_sec
                        )
                    }
                };
                let line = format!(
                    "{{\"level\":\"error\",\"time\":\"{}\",\"msg\":\"{}\"}}\n",
                    ts,
                    e.to_string().replace('"', "\\\"")
                );
                eprint!("{}", line);
            } else {
                eprintln!("rsrun: {e}");
            }
            ExitCode::from(1)
        }
    }
}

fn parse_duration_ms(s: &str) -> std::io::Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        return Err(std::io::Error::other("empty duration"));
    }
    let (num, mult) = if let Some(n) = s.strip_suffix("ms") {
        (n, 1)
    } else if let Some(n) = s.strip_suffix('s') {
        (n, 1_000)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 60_000)
    } else {
        (s, 1_000)
    };
    let value = num
        .parse::<u64>()
        .map_err(|_| std::io::Error::other(format!("bad duration: {s}")))?;
    value
        .checked_mul(mult)
        .ok_or_else(|| std::io::Error::other(format!("duration too large: {s}")))
}

fn parse_optional_duration_ms(s: Option<&str>) -> std::io::Result<Option<u64>> {
    s.map(parse_duration_ms).transpose()
}

#[cfg(feature = "rollout")]
fn read_exec_stdin(path: Option<&std::path::Path>) -> std::io::Result<Option<Vec<u8>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    if path == std::path::Path::new("-") {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf)?;
        return Ok(Some(buf));
    }
    std::fs::read(path).map(Some)
}

fn validate_bundle(bundle: &std::path::Path, json: bool) -> std::io::Result<()> {
    let canonical = bundle.canonicalize()?;
    let config_path = canonical.join("config.json");
    let mut reasons = Vec::new();

    match rsrun_core::spec::Spec::from_bundle(&canonical) {
        Ok(spec) => {
            if let Err(e) = rsrun_ext::compile(&spec, "validate") {
                reasons.push(format!("extension plan compile failed: {e}"));
            }
        }
        Err(e) => reasons.push(format!("config.json is not supported: {e}")),
    }

    let value = match std::fs::read(&config_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
    {
        Some(value) => value,
        None => {
            reasons.push("config.json is missing or invalid JSON".to_string());
            serde_json::Value::Null
        }
    };
    collect_validation_reasons(&value, &mut reasons);

    let supported = reasons.is_empty();
    if json {
        let out = serde_json::json!({
            "supported": supported,
            "reasons": reasons,
            "safe_to_fallback": !supported,
        });
        println!("{}", serde_json::to_string(&out)?);
    } else if supported {
        println!("supported");
    } else {
        println!("unsupported");
        for reason in &reasons {
            println!("- {reason}");
        }
    }

    if supported {
        Ok(())
    } else {
        Err(std::io::Error::other("bundle is not fully supported"))
    }
}

fn collect_validation_reasons(value: &serde_json::Value, reasons: &mut Vec<String>) {
    let linux = value.get("linux").unwrap_or(&serde_json::Value::Null);
    if linux.get("resources").is_some()
        && !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
    {
        reasons.push("cgroup v2 is not available on this host".to_string());
    }
    if linux
        .get("mountLabel")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .is_some()
    {
        reasons.push("linux.mountLabel is not supported".to_string());
    }
    for key in ["intelRdt", "memoryPolicy", "timeOffsets"] {
        if linux.get(key).is_some() {
            reasons.push(format!("linux.{key} is not supported"));
        }
    }
    if value
        .get("process")
        .and_then(|p| p.get("consoleSize"))
        .is_some()
    {
        reasons.push("process.consoleSize is not supported".to_string());
    }
    if value
        .get("process")
        .and_then(|p| p.get("ioPriority"))
        .is_some()
    {
        reasons.push("process.ioPriority is not supported".to_string());
    }
    if value
        .get("process")
        .and_then(|p| p.get("rlimits"))
        .is_some()
    {
        validate_rlimits(value, reasons);
    }
    validate_sysctls(value, reasons);
    validate_mount_options(value, reasons);
}

fn validate_rlimits(value: &serde_json::Value, reasons: &mut Vec<String>) {
    let Some(rlimits) = value
        .get("process")
        .and_then(|p| p.get("rlimits"))
        .and_then(|v| v.as_array())
    else {
        return;
    };
    for rlimit in rlimits {
        let soft = rlimit.get("soft").and_then(|v| v.as_u64());
        let hard = rlimit.get("hard").and_then(|v| v.as_u64());
        if let (Some(soft), Some(hard)) = (soft, hard) {
            if soft > hard {
                let kind = rlimit
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                reasons.push(format!(
                    "process.rlimits[{kind}] has soft greater than hard"
                ));
            }
        }
    }
}

fn validate_sysctls(value: &serde_json::Value, reasons: &mut Vec<String>) {
    let Some(sysctls) = value
        .get("linux")
        .and_then(|l| l.get("sysctl"))
        .and_then(|v| v.as_object())
    else {
        return;
    };
    let namespaces = value
        .get("linux")
        .and_then(|l| l.get("namespaces"))
        .and_then(|v| v.as_array());
    let has_ns = |name: &str| -> bool {
        namespaces
            .map(|items| {
                items
                    .iter()
                    .any(|ns| ns.get("type").and_then(|v| v.as_str()) == Some(name))
            })
            .unwrap_or(false)
    };
    if value
        .get("hostname")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .is_some()
        && sysctls.contains_key("kernel.hostname")
    {
        reasons.push("linux.sysctl.kernel.hostname conflicts with hostname".to_string());
    }
    for key in sysctls.keys() {
        if key.starts_with("net.") && !has_ns("network") {
            reasons.push(format!("linux.sysctl.{key} requires a network namespace"));
        }
        if matches!(key.as_str(), "kernel.hostname" | "kernel.domainname") && !has_ns("uts") {
            reasons.push(format!("linux.sysctl.{key} requires a UTS namespace"));
        }
    }
}

fn validate_mount_options(value: &serde_json::Value, reasons: &mut Vec<String>) {
    let Some(mounts) = value.get("mounts").and_then(|v| v.as_array()) else {
        return;
    };
    for mount in mounts {
        let dest = mount
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("<unknown>");
        let Some(options) = mount.get("options").and_then(|v| v.as_array()) else {
            continue;
        };
        for option in options.iter().filter_map(|v| v.as_str()) {
            if option == "tmpcopyup" {
                reasons.push(format!(
                    "mount option tmpcopyup is not supported for {dest}"
                ));
            }
            if is_recursive_mount_attr(option) {
                reasons.push(format!(
                    "recursive mount option {option} is not supported for {dest}"
                ));
            }
        }
    }
}

fn is_recursive_mount_attr(option: &str) -> bool {
    matches!(
        option,
        "rro"
            | "rrw"
            | "rnoexec"
            | "rexec"
            | "rnosuid"
            | "rsuid"
            | "rnodev"
            | "rdev"
            | "rrelatime"
            | "rnorelatime"
            | "rnoatime"
            | "ratime"
            | "rnodiratime"
            | "rdiratime"
    )
}

fn sub_features() -> std::io::Result<()> {
    let f = serde_json::json!({
        "ociVersionMin": "1.0.0",
        "ociVersionMax": "1.0.2",
        "linux": {
            "namespaces": ["mount", "pid", "ipc", "uts", "network", "cgroup", "user"],
            "capabilities": null,
            "cgroup": {},
            "seccomp": null,
            "apparmor": null,
            "selinux": null,
            "intelRdt": null,
            "mountExtensions": null,
        },
        "annotations": null,
        "potentiallyUnsafeConfigAnnotations": null,
    });
    println!("{}", serde_json::to_string(&f)?);
    Ok(())
}

/// Build an `ExtPlan` (seccomp, cgroup limits, hooks, devices) from the
/// bundle and hand it to core, threading through the optional console
/// socket.
fn create_with_ext(
    id: &str,
    bundle: &std::path::Path,
    pid_file: Option<&std::path::Path>,
    console_socket: Option<&std::path::Path>,
    preserve_fds: u32,
    no_pivot: bool,
    timeout_ms: Option<u64>,
) -> std::io::Result<()> {
    let canonical = bundle.canonicalize()?;
    let spec = rsrun_core::spec::Spec::from_bundle(&canonical)?;
    let ext = rsrun_ext::compile(&spec, id)?;
    let opts = rsrun_core::plan::CreateOpts {
        preserve_fds,
        no_pivot,
    };
    runtime::cmd_create_full_with_timeout(
        id,
        bundle,
        pid_file,
        ext,
        console_socket,
        opts,
        timeout_ms,
    )
}

#[cfg(feature = "rollout")]
fn activate_with_ext(
    id: &str,
    bundle: Option<&std::path::Path>,
    json: bool,
    timeout_ms: Option<u64>,
) -> std::io::Result<()> {
    let bundle = match bundle {
        Some(path) => path.canonicalize()?,
        None => stored_bundle_for_container(id)?.canonicalize()?,
    };
    let spec = rsrun_core::spec::Spec::from_bundle(&bundle)?;
    let ext = rsrun_ext::compile(&spec, id)?;
    runtime::rollout::cmd_activate_with_ext(id, &bundle, ext, json, timeout_ms)
}

#[cfg(feature = "rollout")]
fn stored_bundle_for_container(id: &str) -> std::io::Result<PathBuf> {
    let paths = rsrun_core::state::ContainerPaths::for_id(id);
    let bytes = std::fs::read(paths.state_file())?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let bundle = value
        .get("bundle")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            std::io::Error::other("activate requires --bundle because stored bundle is empty")
        })?;
    Ok(PathBuf::from(bundle))
}

fn command_needs_sealed_reexec(cmd: &Cmd) -> bool {
    match cmd {
        Cmd::Create { .. } | Cmd::Exec { .. } => true,
        #[cfg(feature = "rollout")]
        Cmd::Activate { .. } => true,
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn reexec_from_sealed_memfd() -> std::io::Result<()> {
    const MARKER: &str = "RSRUN_MEMFD_REEXEC";
    if std::env::var_os(MARKER).is_some() {
        return Ok(());
    }

    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"rsrun".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        ) as i32
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    if let Err(e) = copy_self_exe_to_memfd(fd) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }

    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(e);
    }

    let mut argv = Vec::new();
    for arg in std::env::args_os() {
        argv.push(
            std::ffi::CString::new(arg.as_os_str().as_bytes()).map_err(|_| {
                unsafe { libc::close(fd) };
                std::io::Error::other("argv contains NUL")
            })?,
        );
    }
    let mut envp = Vec::new();
    envp.push(std::ffi::CString::new(format!("{MARKER}=1")).unwrap());
    for (key, value) in std::env::vars_os() {
        let mut item = Vec::new();
        item.extend_from_slice(key.as_os_str().as_bytes());
        item.push(b'=');
        item.extend_from_slice(value.as_os_str().as_bytes());
        envp.push(std::ffi::CString::new(item).map_err(|_| {
            unsafe { libc::close(fd) };
            std::io::Error::other("environment contains NUL")
        })?);
    }

    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = envp
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    unsafe {
        libc::fexecve(fd, argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
    }
    let e = std::io::Error::last_os_error();
    unsafe { libc::close(fd) };
    Err(e)
}

#[cfg(not(target_os = "linux"))]
fn reexec_from_sealed_memfd() -> std::io::Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn copy_self_exe_to_memfd(memfd: i32) -> std::io::Result<()> {
    let mut exe = std::fs::File::open("/proc/self/exe")?;
    let len = exe.metadata()?.len();
    let mut offset: libc::off_t = 0;

    while (offset as u64) < len {
        let remaining = (len - offset as u64).min(usize::MAX as u64) as usize;
        let n = unsafe { libc::sendfile(memfd, exe.as_raw_fd(), &mut offset, remaining) };
        if n > 0 {
            continue;
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "sendfile copied a partial executable",
            ));
        }

        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if err.raw_os_error() == Some(libc::EINVAL) || err.raw_os_error() == Some(libc::ENOSYS) {
            return copy_self_exe_to_memfd_buffered(memfd, &mut exe);
        }
        return Err(err);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn copy_self_exe_to_memfd_buffered(memfd: i32, exe: &mut std::fs::File) -> std::io::Result<()> {
    if unsafe { libc::lseek(exe.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::ftruncate(memfd, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::lseek(memfd, 0, libc::SEEK_SET) } < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let mut buf = [0u8; 128 * 1024];
    loop {
        let n = std::io::Read::read(exe, &mut buf)?;
        if n == 0 {
            break;
        }
        write_all_raw_fd(memfd, &buf[..n])?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_all_raw_fd(fd: i32, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        let n = unsafe { libc::write(fd, data.as_ptr() as *const _, data.len()) };
        if n > 0 {
            data = &data[n as usize..];
            continue;
        }
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "write returned 0",
            ));
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_duration_suffixes() {
        assert_eq!(parse_duration_ms("250ms").unwrap(), 250);
        assert_eq!(parse_duration_ms("2s").unwrap(), 2_000);
        assert_eq!(parse_duration_ms("3m").unwrap(), 180_000);
        assert_eq!(parse_duration_ms("4").unwrap(), 4_000);
        assert!(parse_duration_ms("abc").is_err());
    }

    #[test]
    fn sealed_reexec_only_wraps_container_entry_paths() {
        assert!(command_needs_sealed_reexec(&Cmd::Create {
            bundle: PathBuf::from("."),
            pid_file: None,
            console_socket: None,
            preserve_fds: None,
            no_pivot: false,
            timeout: None,
            id: "id".into(),
        }));
        assert!(command_needs_sealed_reexec(&Cmd::Exec {
            process: None,
            pid_file: None,
            detach: false,
            #[cfg(feature = "rollout")]
            timeout: None,
            #[cfg(feature = "rollout")]
            kill_tree: false,
            #[cfg(feature = "rollout")]
            max_output_bytes: 1024,
            #[cfg(feature = "rollout")]
            json: false,
            #[cfg(feature = "rollout")]
            stdin: None,
            _tty: false,
            console_socket: None,
            _pidfd_socket: None,
            _user: None,
            cwd: None,
            env: Vec::new(),
            _additional_gids: None,
            _apparmor: None,
            _cap: Vec::new(),
            _no_new_privs: false,
            _preserve_fds: None,
            id: "id".into(),
            #[cfg(feature = "rollout")]
            command: Vec::new(),
        }));
        assert!(!command_needs_sealed_reexec(&Cmd::State {
            id: "id".into()
        }));
        assert!(!command_needs_sealed_reexec(&Cmd::Features));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn buffered_reexec_copy_replaces_partial_memfd_contents() {
        let src = std::env::temp_dir().join(format!("rsrun-copy-src-{}", std::process::id()));
        std::fs::write(&src, b"runtime-bytes").unwrap();
        let mut src_file = std::fs::File::open(&src).unwrap();
        std::fs::remove_file(&src).unwrap();

        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c"rsrun-test".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
            ) as i32
        };
        assert!(fd >= 0);

        write_all_raw_fd(fd, b"partial").unwrap();
        copy_self_exe_to_memfd_buffered(fd, &mut src_file).unwrap();

        assert!(unsafe { libc::lseek(fd, 0, libc::SEEK_SET) } >= 0);
        let mut got = [0u8; 32];
        let n = unsafe { libc::read(fd, got.as_mut_ptr() as *mut _, got.len()) };
        unsafe { libc::close(fd) };
        assert_eq!(&got[..n as usize], b"runtime-bytes");
    }

    #[test]
    fn validation_reports_unsupported_and_conflicting_fields() {
        let spec = json!({
            "hostname": "demo",
            "process": {
                "consoleSize": {"height": 24, "width": 80},
                "rlimits": [{"type": "RLIMIT_NOFILE", "soft": 9, "hard": 8}]
            },
            "mounts": [{
                "destination": "/cfg",
                "type": "tmpfs",
                "source": "tmpfs",
                "options": ["tmpcopyup", "rro"]
            }],
            "linux": {
                "mountLabel": "system_u:object_r:container_file_t:s0",
                "sysctl": {"kernel.hostname": "other", "net.ipv4.ip_forward": "1"},
                "namespaces": [{"type": "mount"}]
            }
        });
        let mut reasons = Vec::new();
        collect_validation_reasons(&spec, &mut reasons);
        assert!(reasons.iter().any(|r| r.contains("linux.mountLabel")));
        assert!(reasons.iter().any(|r| r.contains("process.consoleSize")));
        assert!(reasons.iter().any(|r| r.contains("soft greater than hard")));
        assert!(reasons
            .iter()
            .any(|r| r.contains("kernel.hostname conflicts")));
        assert!(reasons
            .iter()
            .any(|r| r.contains("requires a network namespace")));
        assert!(reasons.iter().any(|r| r.contains("tmpcopyup")));
        assert!(reasons
            .iter()
            .any(|r| r.contains("recursive mount option rro")));
    }
}
