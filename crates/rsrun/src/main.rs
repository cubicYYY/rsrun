//! rsrun — a small OCI runtime in Rust.

use rsrun_core as runtime;

use clap::{Parser, Subcommand};
use std::io::Read;
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
        id: String,
    },
    /// Unblock the created container; the workload begins running.
    Start { id: String },
    /// Stop the container (if `--force`) and remove its state.
    Delete {
        #[arg(short, long)]
        force: bool,
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
    #[command(trailing_var_arg = true)]
    Exec {
        #[arg(short = 'p', long)]
        process: Option<PathBuf>,
        #[arg(long = "pid-file")]
        pid_file: Option<PathBuf>,
        #[arg(short, long)]
        detach: bool,
        /// Agent mode: maximum wall time before terminating the exec.
        #[arg(long)]
        timeout: Option<String>,
        /// Agent mode: signal the exec process group on timeout.
        #[arg(long = "kill-tree")]
        kill_tree: bool,
        /// Agent mode: per-stream captured output limit.
        #[arg(long = "max-output-bytes", default_value_t = 2 * 1024 * 1024)]
        max_output_bytes: usize,
        /// Agent mode: emit a structured result object.
        #[arg(long)]
        json: bool,
        /// Agent mode: read stdin payload from a file, or `-` for stdin.
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
        /// Agent mode command. Use `--` before the command.
        command: Vec<String>,
    },
    /// Emit the runtime feature descriptor JSON Docker queries at registration.
    Features,
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
            id,
        } => create_with_ext(
            &id,
            &bundle,
            pid_file.as_deref(),
            console_socket.as_deref(),
            preserve_fds.unwrap_or(0),
            no_pivot,
        ),
        Cmd::Start { id } => runtime::cmd_start(&id),
        Cmd::Delete { force, id } => runtime::cmd_delete(&id, force),
        Cmd::State { id } => runtime::cmd_state(&id),
        Cmd::Kill { id, signal } => runtime::cmd_kill(&id, &signal),
        Cmd::Exec {
            process,
            pid_file,
            detach,
            id,
            console_socket,
            timeout,
            kill_tree,
            max_output_bytes,
            json,
            stdin,
            cwd,
            env,
            command,
            ..
        } => (|| -> std::io::Result<()> {
            if !command.is_empty() {
                if detach {
                    Err(std::io::Error::other(
                        "agent exec command form does not support --detach",
                    ))
                } else if console_socket.is_some() {
                    Err(std::io::Error::other(
                        "agent exec command form does not support --console-socket",
                    ))
                } else {
                    let opts = runtime::AgentExecOpts {
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
                    runtime::cmd_exec_agent(&id, &command, opts)
                }
            } else {
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
        })(),
        Cmd::Features => sub_features(),
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
) -> std::io::Result<()> {
    let canonical = bundle.canonicalize()?;
    let spec = rsrun_core::spec::Spec::from_bundle(&canonical)?;
    let ext = rsrun_ext::compile(&spec, id)?;
    let opts = rsrun_core::plan::CreateOpts {
        preserve_fds,
        no_pivot,
    };
    runtime::cmd_create_full(id, bundle, pid_file, ext, console_socket, opts)
}
