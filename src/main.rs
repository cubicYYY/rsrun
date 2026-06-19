//! rsrun — a small OCI runtime in Rust.
//!
//! Argv parsing is hand-rolled (no `clap`) to keep startup small.

// `runtime` picks the real Linux implementation or a non-Linux stub via
// cfg. The other modules hold Linux-specific types (MsFlags, CloneFlags,
// rlimit64, …) and are only compiled on Linux.
mod runtime;

#[cfg(target_os = "linux")]
mod clone3;
#[cfg(target_os = "linux")]
mod plan;
#[cfg(target_os = "linux")]
mod spec;
#[cfg(target_os = "linux")]
mod state;

use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match dispatch(&args) {
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

fn dispatch(args: &[String]) -> std::io::Result<()> {
    if args.len() < 2 {
        usage();
        return Err(std::io::Error::other("missing subcommand"));
    }

    // Global runc-style options that appear BEFORE the subcommand.
    // Docker/containerd pass these unconditionally.
    //   --root <path>              honored — override state dir
    //   --log <path>               honored — redirect stderr there
    //   --log-format text|json     honored — JSON error frames if json
    //   --systemd-cgroup           accepted; no cgroup driver yet
    //   --rootless auto|true|false accepted; rootless is autodetected by uid
    //   --debug                    accepted; no-op
    let mut i = 1;
    let mut log_path: Option<String> = None;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                if i + 1 >= args.len() {
                    return Err(std::io::Error::other("--root needs an argument"));
                }
                std::env::set_var("RSRUN_ROOT", &args[i + 1]);
                i += 2;
            }
            "--log" => {
                if i + 1 >= args.len() {
                    return Err(std::io::Error::other("--log needs an argument"));
                }
                log_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--log-format" => {
                if i + 1 < args.len() && args[i + 1] == "json" {
                    std::env::set_var("RSRUN_LOG_FORMAT_JSON", "1");
                }
                i += 2;
            }
            "--rootless" => {
                i += 2;
            }
            "--systemd-cgroup" | "--debug" => {
                i += 1;
            }
            _ => break,
        }
    }

    // If --log was given, redirect stderr to it. containerd reads this
    // file on failure to recover the runtime's error message. The file
    // is created unconditionally so containerd never sees ENOENT.
    if let Some(p) = log_path.as_deref() {
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

    if i >= args.len() {
        usage();
        return Err(std::io::Error::other("missing subcommand"));
    }

    let sub = &args[i];
    let rest = &args[i + 1..];

    match sub.as_str() {
        "create" => sub_create(rest),
        "start" => sub_start(rest),
        "delete" => sub_delete(rest),
        "state" => sub_state(rest),
        "kill" => sub_kill(rest),
        "exec" => sub_exec(rest),
        "features" => sub_features(),
        "list" => sub_list(),
        "spec" => Err(std::io::Error::other("spec subcommand not implemented")),
        "--version" | "-v" => {
            println!("rsrun 0.1.0");
            Ok(())
        }
        "--help" | "-h" | "help" => {
            usage();
            Ok(())
        }
        other => {
            usage();
            Err(std::io::Error::other(format!("unknown subcommand: {other}")))
        }
    }
}

/// `rsrun exec <id>` — run a process inside an already-running container.
fn sub_exec(args: &[String]) -> std::io::Result<()> {
    let mut process_path: Option<PathBuf> = None;
    let mut pid_file: Option<PathBuf> = None;
    let mut detach = false;
    let mut id: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--process" => {
                if i + 1 >= args.len() {
                    return Err(std::io::Error::other("--process needs an argument"));
                }
                process_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--pid-file" => {
                if i + 1 >= args.len() {
                    return Err(std::io::Error::other("--pid-file needs an argument"));
                }
                pid_file = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--detach" | "-d" => {
                detach = true;
                i += 1;
            }
            "--tty" | "-t" => i += 1,
            "--console-socket" | "--pidfd-socket" | "--user" | "-u" | "--cwd"
            | "--env" | "-e" | "--additional-gids" | "-g" | "--apparmor" | "--cap"
            | "--no-new-privs" | "--preserve-fds" => i += 2,
            s if s.starts_with('-') => {
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => {
                if id.is_none() {
                    id = Some(args[i].clone());
                }
                i += 1;
            }
        }
    }
    let id = id.ok_or_else(|| std::io::Error::other("exec: missing container ID"))?;
    let process_path = process_path
        .ok_or_else(|| std::io::Error::other("exec: --process required"))?;
    runtime::cmd_exec(&id, &process_path, pid_file.as_deref(), detach)
}

fn sub_list() -> std::io::Result<()> {
    runtime::cmd_list()
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

fn sub_create(args: &[String]) -> std::io::Result<()> {
    let mut bundle = PathBuf::from(".");
    let mut id: Option<String> = None;
    let mut pid_file: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-b" | "--bundle" => {
                if i + 1 >= args.len() {
                    return Err(std::io::Error::other("--bundle needs an argument"));
                }
                bundle = PathBuf::from(&args[i + 1]);
                i += 2;
            }
            "--pid-file" => {
                if i + 1 >= args.len() {
                    return Err(std::io::Error::other("--pid-file needs an argument"));
                }
                pid_file = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--console-socket" | "--preserve-fds" => {
                // Accepted, ignored. No console support yet.
                i += 2;
            }
            "--no-pivot" => {
                // Accepted, ignored. rsrun always uses pivot_root.
                i += 1;
            }
            s if s.starts_with('-') => {
                if i + 1 < args.len() && !args[i + 1].starts_with('-') {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => {
                if id.is_none() {
                    id = Some(args[i].clone());
                }
                i += 1;
            }
        }
    }
    let id = id.ok_or_else(|| std::io::Error::other("create: missing container ID"))?;
    runtime::cmd_create(&id, &bundle, pid_file.as_deref())
}

fn sub_start(args: &[String]) -> std::io::Result<()> {
    let id = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .ok_or_else(|| std::io::Error::other("start: missing container ID"))?;
    runtime::cmd_start(id)
}

fn sub_delete(args: &[String]) -> std::io::Result<()> {
    let force = args.iter().any(|a| a == "-f" || a == "--force");
    let id = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .ok_or_else(|| std::io::Error::other("delete: missing container ID"))?;
    runtime::cmd_delete(id, force)
}

fn sub_state(args: &[String]) -> std::io::Result<()> {
    let id = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .ok_or_else(|| std::io::Error::other("state: missing container ID"))?;
    runtime::cmd_state(id)
}

fn sub_kill(args: &[String]) -> std::io::Result<()> {
    let positional: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if positional.is_empty() {
        return Err(std::io::Error::other("kill: need <id>"));
    }
    let signal = if positional.len() >= 2 {
        positional[1].as_str()
    } else {
        "TERM"
    };
    runtime::cmd_kill(positional[0], signal)
}

fn usage() {
    eprintln!(
        "rsrun 0.1.0 — speed-first OCI-shaped runtime\n\
         \n\
         Usage:\n  \
           rsrun create -b BUNDLE ID\n  \
           rsrun start ID\n  \
           rsrun delete [-f] ID\n  \
           rsrun state ID\n  \
           rsrun kill ID SIGNAL"
    );
}
