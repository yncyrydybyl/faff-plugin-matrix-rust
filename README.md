# faff-plugin-matrix-rust

A native Rust port of [`faff-plugin-matrix`](../faff-plugin-matrix), built
directly against the Rust core (`faff_core::Workspace` + the storage event
stream) and [matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk)
with the `e2e-encryption` + `sqlite` features.

Same shape and behaviour as the Python version: a sidecar daemon that posts
the **current faff** (active session start / stop / switch) into a Matrix
room. Designed for **end-to-end encrypted** rooms on **Matrix Authentication
Service (MAS)** homeservers such as `matrix.datanauten.de`.

## Why a Rust port?

- Single static binary, no Python interpreter or `libolm` C dep at install
  time. (matrix-sdk uses `vodozemac`, a pure-Rust Olm/Megolm implementation,
  via the `e2e-encryption` feature.)
- Direct use of the Rust core's `tokio::sync::broadcast::Receiver<StorageEvent>`
  — no thread-bridge needed (the Python version had to run the blocking
  iterator on a daemon thread and bounce events into an `asyncio.Queue`).
- Field model matches the new Rust core (`title`, `impact`, `mode`) with no
  legacy `Intent` indirection.

## Status

Builds clean against `rustc 1.96.0-nightly` (`cargo build --release` ~2m,
73 MB self-contained binary) with the dependency setup described in
[Known caveats](#known-caveats). Has not yet been runtime-tested against a
real MAS homeserver.

## Requirements

- Rust 1.88+ and Cargo (required by `matrix-sdk` 0.16)
- The faff core sources at `../faff-core` (this crate uses a path dependency
  on `../faff-core/core`). Clone all of `faffhub/*` next to each other.
- A Matrix account on the target homeserver, **already a member** of the
  room you want to post into. The bot will not auto-join.

No system C library is required at runtime — `vodozemac` is pure Rust.

## Build

```sh
cargo build --release
# binary lands at target/release/faff-plugin-matrix-rust
```

## Getting credentials under MAS

MAS homeservers (e.g. `matrix.datanauten.de`) **disable the legacy
`/_matrix/client/v3/login` endpoint**. This binary therefore never calls
`login` — it restores a session from a `(user_id, device_id, access_token)`
triple obtained out of band.

The `device_id` and `access_token` **must be a matched pair**. If you mix a
token from one device with a different device id, Megolm key sharing will
silently fail and the bot's messages will be undecryptable for everyone in
the room.

### Option A — `mas-cli` (server admin)

```sh
mas-cli manage issue-compatibility-token <username>
```

prints a `device_id` and an `access_token`. Combine with the known `user_id`.

### Option B — Element session (no admin needed)

1. Log in as the bot user in Element Web or Element X.
2. Element Web: **Settings → Help & About → Advanced**. Reveal `Access
   Token`, `Device ID`, and your full `User ID`.
3. Copy all three into the config below.

Treat the access token like a password.

## Configure

Copy `config.template.toml` to a real path and fill it in:

```toml
id = "personal"
plugin = "faff-plugin-matrix-rust"

[connection]
homeserver = "https://matrix.datanauten.de"
user_id    = "@yourbot:datanauten.de"
device_id  = "ABCDEFGHIJ"
# Prefer the env-var form so the token never sits on disk:
access_token_env = "FAFF_MATRIX_TOKEN"

room = "#faff-status:datanauten.de"

[options]
notify_on = ["start", "stop", "switch"]
```

```sh
export FAFF_MATRIX_TOKEN="syt_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

## Use

```sh
# 1. End-to-end check: authenticate, resolve room, post a probe message.
./target/release/faff-plugin-matrix-rust -c ~/.config/faff/plugin-matrix.toml test

# 2. One-shot: post the current active session and exit (good for hooks).
./target/release/faff-plugin-matrix-rust -c ~/.config/faff/plugin-matrix.toml now

# 3. Watcher: run the daemon, post on every start / stop / switch.
./target/release/faff-plugin-matrix-rust -c ~/.config/faff/plugin-matrix.toml run
```

The watcher reads the same `~/.faff` (or `$FAFF_DIR`) workspace as the rest
of the faff toolchain — the path is governed by `FileSystemStorage` in
`faff-core`, not by a CLI flag.

## E2EE notes

- The encryption store is a SQLite DB under
  `~/.local/share/faff-plugin-matrix-rust/<id>/`. **Do not delete it** — it
  holds the Olm session keys for this device. Nuke it and you must re-issue
  the device + token.
- This bot **does not implement device verification or cross-signing**. It
  trusts whoever is in the room and shares Megolm keys with all of their
  devices. This is the standard write-only-bot trade-off; if you need to
  lock it down, do verification out of band.
- On first run we do a `sync_once(full_state=true)` so the bot learns the
  encrypted room's membership and can immediately share keys. A long-running
  `client.sync` task runs in the background to keep that state fresh.

## How it differs from the Python version

| | Python (`faff-plugin-matrix`) | Rust (this crate) |
|---|---|---|
| Matrix client | `matrix-nio[e2e]` | `matrix-sdk` (e2e-encryption + sqlite) |
| Crypto backend | `python-olm` (libolm C dep) | `vodozemac` (pure Rust) |
| Faff core access | `faff_core` Python bindings | `faff-core` crate (path dep) |
| Event stream | blocking iterator on a daemon thread, bridged into `asyncio.Queue` | native `tokio::sync::broadcast::Receiver<StorageEvent>` |
| Session model | `session.intent.alias` (legacy `Intent` shape from the bindings) | `session.title` directly (current Rust model) |
| Diff key | `intent.intent_id` | `session.start: DateTime<Tz>` |
| Install footprint | Python 3.11+ + libolm-dev + pip wheels | one static binary after `cargo build --release` |

The user-facing CLI (`run` / `test` / `now`) and config file shape are kept
deliberately compatible.

## Run as a systemd user service

`~/.config/systemd/user/faff-plugin-matrix-rust.service`:

```ini
[Unit]
Description=faff matrix sidecar (rust)
After=default.target

[Service]
Type=simple
Environment=FAFF_MATRIX_TOKEN=syt_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
ExecStart=%h/.local/bin/faff-plugin-matrix-rust -c %h/.config/faff/plugin-matrix.toml run
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload
systemctl --user enable --now faff-plugin-matrix-rust
journalctl --user -u faff-plugin-matrix-rust -f
```

## Known caveats

- **matrix-sdk dependency uses a git pin, not a release.** Cargo.toml
  points at `git = "https://github.com/matrix-org/matrix-rust-sdk"`
  rather than the 0.16 release on crates.io. The reason: rustc
  1.96.0-nightly trips a query-depth overflow inside matrix-sdk 0.16's own
  compilation while computing the layout of `Client::sync()`'s async
  future, and the recursion-limit attribute would have to live inside
  matrix-sdk's `lib.rs` (which we can't reach from outside). Main branch
  doesn't hit this. Once a published release builds clean on current
  nightly, switch back to `matrix-sdk = "0.x"`.
- **No `native-tls` feature flag.** Main branch has restructured features
  and TLS is no longer a separate flag (always-on via reqwest's defaults).
  If you bump to a future release that brings the flag back, add it.
- **`bundled-sqlite` is enabled** so the binary statically links sqlite from
  source and has no runtime C dependency. Without this feature, linking
  fails on hosts that don't ship `libsqlite3` (`-lsqlite3` not found). The
  trade-off is a slightly longer first build and a larger binary (~73 MB
  release on x86_64).
- **Crate-level `recursion_limit` and `type_length_limit` bumps.**
  `src/main.rs` starts with `#![recursion_limit = "1024"]` and
  `#![type_length_limit = "4194304"]`. These are needed because
  `tokio::spawn(async move { client.sync(...).await })` triggers an
  auto-trait `Send` check on the giant `Client::sync` future, which
  overflows the default trait-eval depth on recent nightly. They're
  harmless and may not be needed forever.
- **API drift across matrix-sdk releases.** The current imports are
  `matrix_sdk::authentication::matrix::MatrixSession`,
  `matrix_sdk::SessionTokens` (crate root), and
  `client.restore_session(session)` as a top-level shortcut. In 0.7 these
  lived under `matrix_sdk::matrix_auth` and the tokens type was
  `MatrixSessionTokens`. If `cargo build` fails on those imports after a
  version bump, check the changelog and adjust `src/main.rs` — the logic
  is unchanged.
- **Workspace path.** Set `FAFF_DIR` if you don't keep your workspace at
  `~/.faff`. There is no `--workspace` flag because `FileSystemStorage`
  doesn't take a path argument.
- **No `login` subcommand.** MAS device-code OAuth2 flow needs a registered
  client_id at the homeserver — out of scope for v1. Get a token via Option
  A or B above.
