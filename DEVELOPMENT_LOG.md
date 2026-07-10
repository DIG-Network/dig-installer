# Development log

High-signal, durable realizations from building dig-installer. Concise facts with
context — not a change diary. See CLAUDE.md → §4.5 for how this is maintained.

## Defaults drift silently when they're duplicated across repos (task #140)

`--dig-node-port` defaulted to `8080` here (`src/main.rs`, `src/service.rs`) long
after dig-node itself moved its own default to `9778` (task #132 — an uncommon
high port, sibling of the dig-wallet HTTP API's `9777`). Nothing failed: the
installer still ran, dig-node still started — it just silently registered the
service on the wrong port relative to what the extension / DIG Browser / the
§5.3 `localhost` tier now expect by default. A duplicated literal default (here:
the installer's own `ServiceConfig::default()` mirroring dig-node's
`config::DEFAULT_PORT` by convention rather than by reference, since they're
different binaries/repos) needs an explicit cross-repo grep whenever the
canonical value moves — `SYSTEM.md` recording the canonical port is necessary
but not sufficient; every consumer's *own* default literal has to be swept too.

## `ToSocketAddrs` on a bare IP literal is a network-free way to unit-test resolver logic

`hosts::resolve_dig_local()` asks the real OS resolver (`getaddrinfo`/the Windows
equivalent, via `std::net::ToSocketAddrs`) whether `dig.local` maps to
`127.0.0.2` — a genuine post-install verification, not a re-parse of the
installer's own hosts-file write (which would trivially always "pass"). The
pure comparison logic (`hosts::resolve_host`) is unit-tested by feeding it bare
IP literals (`"127.0.0.2"`, `"127.0.0.1"`) instead of hostnames: `ToSocketAddrs`
parses a literal directly with **no I/O**, so the success/mismatch branches are
deterministic and CI-safe. The "doesn't resolve" branch is tested with a
`.invalid`-TLD hostname (RFC 2606 reserved, guaranteed never to resolve) rather
than a made-up name, which could theoretically hit a search-domain suffix on
some networks. The real `dig.local` resolution itself is only exercised as a
manual/integration check post-install (mirrors how `write_dig_local()`'s actual
system-hosts-file write was never unit-tested either — see `hosts.rs`'s
`_at`-suffixed pure-path variants for the testable core).

## `service-manager` 0.7.1's restart-on-crash defaults differ silently per OS (task #223)

Both dig-node-service and this installer's own dig-dns wiring register OS
services via the `service-manager` crate pinned at `0.7.1`, with
`ServiceInstallCtx.contents: None` (letting the crate generate the systemd
unit / launchd plist / SCM entry) and no explicit restart config. Checked the
crate source at tag `v0.7.1` (GitHub API, since it isn't vendored locally) to
learn what that actually produces:

- **systemd** — `SystemdConfig::default().restart` is
  `SystemdServiceRestartType::OnFailure`; the generated unit gets
  `Restart=on-failure` automatically. Auto-restart-on-crash "just works" on Linux.
- **launchd** — `LaunchdInstallConfig::default().keep_alive` is `true`; the
  generated plist gets `KeepAlive: true` (+ `RunAtLoad: true` from
  `ServiceInstallCtx.autostart`). Auto-restart-on-crash "just works" on macOS too.
- **Windows (SCM)** — `src/sc.rs`'s `install()` only shells `sc create …`; it
  never calls `sc failure`/`ChangeServiceConfig2` to set recovery actions.
  Windows services do **NOT** restart on crash by default — this is a REAL gap,
  not a documentation gap. Filed as
  [DIG-Network/dig_ecosystem#224](https://github.com/DIG-Network/dig_ecosystem/issues/224)
  (in `dig-node-service`, out of scope for this repo).

Lesson: "delegates to the `service-manager` crate" is not one behavior — its
per-OS default differs, and the only way to know which is to read that crate's
actual per-backend source for the pinned version (docs.rs/the crate's own docs
don't spell this out; `ServiceInstallCtx`'s fields are the same across OSes,
but the *manager's own* config struct, which this installer/dig-node-service
never touch, is what carries the OS-specific default).
