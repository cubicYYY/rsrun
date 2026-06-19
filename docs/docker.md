# Using rsrun as a Docker runtime

Docker can be configured to use rsrun the same way it uses `crun` or
`youki`: register the binary in `/etc/docker/daemon.json` and pass
`--runtime=rsrun` to `docker run`.

## Setup

```jsonc
// /etc/docker/daemon.json
{
  "runtimes": {
    "rsrun": { "path": "/usr/local/bin/rsrun" }
  }
}
```

```sh
sudo systemctl restart docker
docker run --rm --runtime=rsrun alpine echo hello
```

## How Docker invokes rsrun

Docker delegates to `containerd-shim`, which calls the runtime with this
argv shape:

```
rsrun --root <state-dir> \
      --log <log.json> \
      --log-format json \
      --systemd-cgroup \
      create --bundle <bundle-dir> --pid-file <pid-file> <id>
```

rsrun handles this layer in `src/main.rs`:

- `--root` overrides the state directory.
- `--log` redirects rsrun's stderr to that file so containerd can
  recover the error message on failure.
- `--log-format json` switches stderr error output to
  `{"level":"error","time":"...","msg":"..."}` so containerd's parser
  is happy.
- `--systemd-cgroup`, `--rootless`, `--debug` are accepted and ignored.
- `kill <id>` without an explicit signal (Docker's `docker stop`)
  defaults to `SIGTERM`.
- `features` returns a JSON descriptor of supported namespaces and
  OCI version range, which Docker queries at registration time.

## What works

| Test | Result |
|------|--------|
| `docker run --rm --runtime=rsrun alpine echo hello` | works |
| `docker run --rm --runtime=rsrun alpine sh -c 'ls /proc/1'` | works (PID namespace) |
| `docker run --rm --runtime=rsrun --hostname=mybox alpine hostname` | works |
| `docker run --rm --runtime=rsrun -e FOO=bar alpine sh -c 'echo $FOO'` | works |
| `docker run --rm --runtime=rsrun alpine sh -c 'exit 42'` | exit code propagated |
| `docker run --name X` then re-using `--name X` after `docker rm` | works |
| `docker run -d --runtime=rsrun ...` + `docker stop` + `docker rm` | works |

## Known limitations

- **`--memory`, `--cpus`, etc. don't enforce.** rsrun applies the
  cgroup *namespace* but does not write per-container resource limits.
- **No console socket / TTY.** `docker run -it` interactive sessions
  may not behave as expected.
- **OCI hooks are not run.** Docker doesn't typically set them, but
  containerd's shim layer might.
