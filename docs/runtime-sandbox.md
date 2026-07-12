# Runtime Sandbox (experimental)

Static AST scanning has a hard ceiling: it can't see what compiled code does, and
it can't stop a payload that decrypts or downloads a second stage at runtime. A
runtime sandbox is the only way to move from *pre-install advice* to an
*install-time guarantee*. This page is the design spike for that work (#55).

!!! warning "Experimental"
    `pipguard/sandbox.py` is a working prototype, **not** wired into the default
    install gate. It is opt-in tooling for evaluation.

## Threat model recap

pipguard defends against malicious code that runs **during installation** — a
`.pth` autorun, or code in `setup.py` / a `pyproject.toml` build backend — doing
things a package install should never do: reading `~/.ssh/id_rsa`, phoning home,
spawning a shell. The overwhelming majority of these payloads are **Python**.

## Options considered

| Mechanism | Blocks by | Portability | Covers native code? | Notes |
|-----------|-----------|-------------|---------------------|-------|
| **Python audit hooks (PEP 578)** | capability (open path, connect, spawn) | any OS, no root | ❌ Python only | Fires in-process; fits the threat model directly |
| seccomp-bpf | syscall number/args | Linux, no root | ✅ | Can't filter by file *path*; blunt for `open` |
| Landlock LSM | filesystem path | Linux ≥ 5.13 | ✅ | No stdlib binding; per-path rules; kernel-version gated |
| bubblewrap / namespaces | mount + namespace isolation | Linux, user-ns | ✅ | Needs `bwrap` or user namespaces; heavier setup |
| Full container | everything | needs Docker/podman | ✅ | Strongest, least portable; high overhead |

## Recommendation

Ship the **audit-hook sandbox as the portable default** and layer an OS-level
sandbox (landlock on Linux, else bubblewrap/container) as optional hardening for
environments that also need to contain native payloads.

Rationale: the audit hook is zero-dependency, runs anywhere Python does, needs no
privileges, and targets exactly the Python-payload threat that pipguard already
scans for. Its blind spot (compiled extensions, non-Python subprocesses) is real
but is a *smaller* surface than the Python install hooks, and is the same blind
spot the static scanner already flags as UNKNOWN/binary.

## Prototype

`pipguard/sandbox.py` installs a capability policy into a target process (and its
Python children) via a generated `sitecustomize` on `PYTHONPATH`:

```python
from pipguard.sandbox import run_sandboxed

# Deny credential reads, deny outbound network, allow benign subprocesses.
rc = run_sandboxed(
    [sys.executable, "setup.py", "build"],
    allow_network=False,
    allow_subprocess=True,
)
```

The hook vetoes three capabilities by raising **before** the syscall:

- **credential reads** — any `open()` whose resolved path contains a denied
  fragment (`/.ssh/`, `/.aws/`, `/.kube/`, `/.gnupg/`, gcloud, `.netrc`,
  `.git-credentials`);
- **outbound network** — the `socket.connect` audit event (when
  `allow_network=False`);
- **process execution** — `os.system` / `subprocess.Popen` (when
  `allow_subprocess=False`).

Because it hooks audit *events*, the block is hermetic and syscall-accurate: a
`socket.create_connection(...)` is stopped at the `connect` event, no real
network needed.

## What `pipguard install --sandbox` covers

`--sandbox` runs the **pip install process** under the sandbox. It contains code
that executes *during* installation — most importantly an **sdist build**
(`setup.py` / build-backend), which is where install-time credential theft and
callbacks live.

It does **not** cover code that runs *after* the pip process exits — a `.pth`
autorun or a first-import payload runs at the **next** interpreter startup, which
is outside the sandboxed process. Those are pipguard's job *before* install: the
static scanner flags `.pth` executable content as CRITICAL and blocks it at the
gate. `--sandbox` is defense-in-depth for the build-time surface, not a
replacement for the scan.

## Limitations (be honest)

- **Install-time only.** Covers code run during the pip process (e.g. sdist
  builds), not post-install `.pth` / first-import autorun (the scanner handles
  those pre-install).
- **Python only.** A payload in a `.so`/`.pyd` extension, or a non-Python child
  process, is not covered. Pair with an OS sandbox for those.
- **Not a syscall firewall.** It enforces the specific audit events above, not
  arbitrary syscalls.
- **Path matching is substring-based** on the normalised path — intentionally
  conservative to avoid breaking legitimate installs.

## Status / next steps

1. Prototype + this note — **done**.
2. Opt-in `pipguard install --sandbox` running the `pip install` step under
   `run_sandboxed` (network denied — the local-cache install is already offline
   via `--no-index`; credential reads denied; subprocesses allowed so build
   backends work) — **done**.
3. Evaluate a landlock backend on Linux for native-code containment — todo.
