# faff-plugin-matrix-rust
A faffage plugin for posting the current faff into an end-to-end encrypted Matrix room. Rust port of [faff-plugin-matrix](https://github.com/yncyrydybyl/faff-plugin-matrix).

Designed for [Matrix Authentication Service](https://element-hq.github.io/matrix-authentication-service/) homeservers — restores its session from a `(user_id, device_id, access_token)` triple and never calls the legacy `/login` endpoint. Uses [matrix-rust-sdk](https://github.com/matrix-org/matrix-rust-sdk) with `vodozemac` for crypto, so there is no `libolm` system dependency.

## Installation

Requires Rust 1.88+.

```sh
cargo build --release
# binary lands at target/release/faff-plugin-matrix-rust
```

The release binary is around 73 MB and self-contained — `bundled-sqlite` statically links sqlite from source.

## Configuration

Copy `config.template.toml` somewhere and fill it in. Get the
`(user_id, device_id, access_token)` triple from `mas-cli manage
issue-compatibility-token <username> [device_id]` on the homeserver, or
from an existing Element session. The bot must already be a member of
the target room — this plugin will not auto-join.

The token is best kept out of dotfiles via `access_token_env`:

```sh
export FAFF_MATRIX_TOKEN="mct_..."
```

## Usage

```sh
# Verify credentials, resolve room, post a probe.
faff-plugin-matrix-rust -c ~/.config/faff/plugin-matrix.toml test

# Post the current active session once and exit.
faff-plugin-matrix-rust -c ~/.config/faff/plugin-matrix.toml now

# Run the watcher loop. Posts on every start / stop / switch.
faff-plugin-matrix-rust -c ~/.config/faff/plugin-matrix.toml run
```

The watcher reads faff state directly from the `faff_core` crate and consumes its `tokio::sync::broadcast::Receiver<StorageEvent>` — no thread bridge between the filesystem watcher and the matrix client.

Workspace path follows `$FAFF_DIR` or `~/.faff` (governed by `FileSystemStorage`); there is no `--workspace` flag.

## Notes

- `Cargo.toml` pins `matrix-sdk` to `git = "https://github.com/matrix-org/matrix-rust-sdk"` rather than the 0.16 release on crates.io. The released `Client::sync()` future overflows rustc's query-depth limit during layout computation on recent nightlies; main carries a fix.
- `src/main.rs` sets `#![recursion_limit = "1024"]` and `#![type_length_limit = "4194304"]` because `tokio::spawn`-ing `client.sync` triggers a `Send` auto-trait check on the giant sync future that overflows the default trait-eval depth.
- Encryption store lives at `~/.local/share/faff-plugin-matrix-rust/<id>/`. Don't delete it.
- Sends use `ignore_unverified_devices=true` — keys are shared with all devices in the room without manual verification.
