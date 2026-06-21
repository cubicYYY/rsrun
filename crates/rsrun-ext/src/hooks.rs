//! OCI lifecycle hooks.
//!
//! Hooks are commands the runtime fork+execs at specific lifecycle
//! phases, with the container `state.json` fed on stdin. core invokes
//! them; ext just compiles the spec into ready-to-exec `HookCmd`s.
//!
//! Phases supported in v0: `prestart` (deprecated but widely used) and
//! `poststop`. The newer 5-phase model (`createRuntime`,
//! `createContainer`, `startContainer`, `poststart`) parses correctly
//! but only `poststart` runs today; the others are tracked in roadmap.

use rsrun_core::plan::{HookCmd, Hooks};
use serde_json::Value;
use std::ffi::CString;
use std::path::Path;

pub fn compile(hooks: Option<&Value>, _bundle: &Path) -> std::io::Result<Hooks> {
    let mut out = Hooks::default();
    let Some(hooks) = hooks else {
        return Ok(out);
    };

    out.prestart = parse_phase(hooks.get("prestart"))?;
    out.create_runtime = parse_phase(hooks.get("createRuntime"))?;
    out.create_container = parse_phase(hooks.get("createContainer"))?;
    out.start_container = parse_phase(hooks.get("startContainer"))?;
    out.poststart = parse_phase(hooks.get("poststart"))?;
    out.poststop = parse_phase(hooks.get("poststop"))?;

    Ok(out)
}

fn parse_phase(arr: Option<&Value>) -> std::io::Result<Vec<HookCmd>> {
    let Some(arr) = arr.and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    let mut cmds = Vec::with_capacity(arr.len());
    for h in arr {
        let path = h
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| std::io::Error::other("hook entry missing path"))?;
        let path_c =
            CString::new(path).map_err(|_| std::io::Error::other("hook path contains NUL"))?;

        let argv = h
            .get("args")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| CString::new(s).map_err(|_| std::io::Error::other("hook arg has NUL")))
                    .collect::<std::io::Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_else(|| vec![path_c.clone()]);

        let envp = h
            .get("env")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| CString::new(s).map_err(|_| std::io::Error::other("hook env has NUL")))
                    .collect::<std::io::Result<Vec<_>>>()
            })
            .transpose()?
            .unwrap_or_default();

        let timeout_ms = h
            .get("timeout")
            .and_then(Value::as_u64)
            .map(|s| s.saturating_mul(1000));

        cmds.push(HookCmd {
            path: path_c,
            args: argv,
            env: envp,
            timeout_ms,
        });
    }
    Ok(cmds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn no_hooks_returns_empty() {
        let h = compile(None, Path::new("/bundle")).unwrap();
        assert!(h.is_empty());
    }

    #[test]
    fn parses_all_six_phases() {
        let v = json!({
            "prestart":         [{"path": "/p1"}],
            "createRuntime":    [{"path": "/p2"}],
            "createContainer":  [{"path": "/p3"}],
            "startContainer":   [{"path": "/p4"}],
            "poststart":        [{"path": "/p5"}],
            "poststop":         [{"path": "/p6"}]
        });
        let h = compile(Some(&v), Path::new("/bundle")).unwrap();
        assert_eq!(h.prestart.len(), 1);
        assert_eq!(h.create_runtime.len(), 1);
        assert_eq!(h.create_container.len(), 1);
        assert_eq!(h.start_container.len(), 1);
        assert_eq!(h.poststart.len(), 1);
        assert_eq!(h.poststop.len(), 1);
        assert_eq!(h.prestart[0].path.to_str().unwrap(), "/p1");
    }

    #[test]
    fn missing_args_defaults_to_path() {
        // OCI says `args` is optional; if absent, argv[0] should be the
        // executable path itself. Otherwise the kernel's exec call
        // produces an empty argv.
        let v = json!({"prestart": [{"path": "/usr/bin/true"}]});
        let h = compile(Some(&v), Path::new("/bundle")).unwrap();
        assert_eq!(h.prestart[0].args.len(), 1);
        assert_eq!(h.prestart[0].args[0].to_str().unwrap(), "/usr/bin/true");
    }

    #[test]
    fn args_and_env_lists_are_threaded_through() {
        let v = json!({
            "prestart": [{
                "path": "/h",
                "args": ["h", "-x"],
                "env": ["A=1", "B=2"],
                "timeout": 10
            }]
        });
        let h = compile(Some(&v), Path::new("/bundle")).unwrap();
        let cmd = &h.prestart[0];
        assert_eq!(cmd.args.len(), 2);
        assert_eq!(cmd.env.len(), 2);
        assert_eq!(cmd.timeout_ms, Some(10_000));
    }

    #[test]
    fn missing_path_errors() {
        let v = json!({"prestart": [{"args": ["foo"]}]});
        assert!(compile(Some(&v), Path::new("/bundle")).is_err());
    }

    #[test]
    fn nul_byte_in_path_errors() {
        let v = json!({"prestart": [{"path": "/with\0nul"}]});
        assert!(compile(Some(&v), Path::new("/bundle")).is_err());
    }
}
