// matrix-sdk's Client::sync() future is enormous, and on recent nightly
// rustc the auto-trait Send check for it overflows the default recursion
// limit when we tokio::spawn it. Bump both knobs.
#![recursion_limit = "1024"]
#![type_length_limit = "4194304"]

//! faff-plugin-matrix-rust
//!
//! Sidecar that posts the current faff (active session) to an end-to-end
//! encrypted Matrix room. Built directly against the Rust core
//! (`faff_core::Workspace` + the storage event stream) and matrix-rust-sdk
//! with the e2e-encryption + sqlite features.
//!
//! Auth model: never calls `/_matrix/client/v3/login` — that endpoint is
//! disabled on Matrix Authentication Service (MAS) homeservers. Instead we
//! restore a session from a (user_id, device_id, access_token) triple
//! obtained out-of-band (`mas-cli manage issue-compatibility-token` or
//! extracted from an Element session). The device_id MUST be the device the
//! token was issued for, otherwise Megolm key sharing will silently fail.
//!
//! Architecture: matrix-sdk is async (tokio); the Rust core's storage event
//! stream is a `tokio::sync::broadcast::Receiver<StorageEvent>` so it
//! integrates natively. We do an initial `sync_once(full_state)` to learn
//! room membership, spawn a background `client.sync` task to keep Megolm
//! sessions current, then loop on storage events. On each `LogChanged` we
//! re-read the active session, diff against the previous snapshot, and
//! emit a templated message via `Room::send`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use chrono::DateTime;
use chrono_tz::Tz;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;

use faff_core::storage::StorageEvent;
use faff_core::Workspace;

use matrix_sdk::{
    authentication::matrix::MatrixSession,
    config::SyncSettings,
    room::RoomMember,
    ruma::{
        events::room::message::RoomMessageEventContent, OwnedDeviceId, OwnedRoomId, OwnedUserId,
        RoomAliasId,
    },
    Client, Room, RoomMemberships, SessionMeta, SessionTokens,
};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    id: Option<String>,
    connection: RawConnection,
    #[serde(default)]
    options: RawOptions,
}

#[derive(Debug, Deserialize)]
struct RawConnection {
    homeserver: String,
    user_id: String,
    device_id: String,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    access_token_env: Option<String>,
    #[serde(default)]
    store_passphrase: Option<String>,
    #[serde(default)]
    store_passphrase_env: Option<String>,
    room: String,
}

#[derive(Debug, Default, Deserialize)]
struct RawOptions {
    #[serde(default)]
    notify_on: Option<Vec<String>>,
    #[serde(default)]
    announce_on_startup: Option<bool>,
    #[serde(default)]
    dry_run: Option<bool>,
    #[serde(default)]
    templates: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
struct Config {
    instance_id: String,
    homeserver: String,
    user_id: OwnedUserId,
    device_id: OwnedDeviceId,
    access_token: String,
    /// Optional passphrase for encrypting the on-disk crypto store.
    /// `None` leaves the SQLite DB unencrypted on disk.
    store_passphrase: Option<String>,
    room: String,
    notify_on: HashSet<String>,
    announce_on_startup: bool,
    dry_run: bool,
    templates: Templates,
}

#[derive(Debug, Clone)]
struct Templates {
    start: String,
    stop: String,
    switch: String,
}

impl Config {
    fn load(path: &Path) -> Result<Self> {
        let raw_str = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let raw: RawConfig = toml::from_str(&raw_str).context("parsing config TOML")?;

        let token = match (raw.connection.access_token_env.as_deref(), &raw.connection.access_token) {
            (Some(var), _) if !var.is_empty() => std::env::var(var).ok().filter(|s| !s.is_empty()),
            _ => None,
        }
        .or(raw.connection.access_token.clone())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow!(
                "config: provide connection.access_token or set the env var named by \
                 connection.access_token_env"
            )
        })?;

        // Same precedence rules for the optional store passphrase:
        // env var wins if set and non-empty, otherwise fall back to the
        // direct value, otherwise None (= unencrypted store).
        let store_passphrase = match (
            raw.connection.store_passphrase_env.as_deref(),
            &raw.connection.store_passphrase,
        ) {
            (Some(var), _) if !var.is_empty() => std::env::var(var).ok().filter(|s| !s.is_empty()),
            _ => None,
        }
        .or(raw.connection.store_passphrase.clone())
        .filter(|s| !s.is_empty());

        let user_id = OwnedUserId::try_from(raw.connection.user_id.clone())
            .map_err(|e| anyhow!("invalid user_id {:?}: {}", raw.connection.user_id, e))?;
        let device_id: OwnedDeviceId = raw.connection.device_id.clone().into();

        let opts = raw.options;
        let templates_map = opts.templates.unwrap_or_default();

        Ok(Config {
            instance_id: raw.id.unwrap_or_else(|| "default".to_string()),
            homeserver: raw.connection.homeserver.trim_end_matches('/').to_string(),
            user_id,
            device_id,
            access_token: token,
            store_passphrase,
            room: raw.connection.room,
            notify_on: opts
                .notify_on
                .unwrap_or_else(|| vec!["start".into(), "stop".into(), "switch".into()])
                .into_iter()
                .collect(),
            announce_on_startup: opts.announce_on_startup.unwrap_or(false),
            dry_run: opts.dry_run.unwrap_or(false),
            templates: Templates {
                start: templates_map
                    .get("start")
                    .cloned()
                    .unwrap_or_else(|| "[faff] started: {title} ({start_time})".to_string()),
                stop: templates_map
                    .get("stop")
                    .cloned()
                    .unwrap_or_else(|| "[faff] stopped: {title} after {duration}".to_string()),
                switch: templates_map
                    .get("switch")
                    .cloned()
                    .unwrap_or_else(|| "[faff] switched: {prev_title} -> {title}".to_string()),
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Session snapshot + diffing
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    title: String,
    role: String,
    impact: String,
    mode: String,
    subject: String,
    trackers: String,
    start: DateTime<Tz>,
}

impl Snapshot {
    fn from_session(session: &faff_core::models::Session) -> Self {
        Self {
            title: session.title.clone().unwrap_or_default(),
            role: session.role.clone().unwrap_or_default(),
            impact: session.impact.clone().unwrap_or_default(),
            mode: session.mode.clone().unwrap_or_default(),
            subject: session.subject.clone().unwrap_or_default(),
            trackers: session.trackers.join(", "),
            start: session.start,
        }
    }

    fn fields(&self) -> HashMap<&'static str, String> {
        let mut m = HashMap::new();
        m.insert("title", self.title.clone());
        m.insert("role", self.role.clone());
        m.insert("impact", self.impact.clone());
        m.insert("mode", self.mode.clone());
        m.insert("subject", self.subject.clone());
        m.insert("trackers", self.trackers.clone());
        m.insert("start_time", self.start.format("%H:%M").to_string());
        m
    }
}

fn fmt_duration(start: DateTime<Tz>, end: DateTime<Tz>) -> String {
    let secs = (end - start).num_seconds().max(0);
    if secs <= 0 {
        return "0m".into();
    }
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    if h > 0 {
        format!("{h}h{m:02}m")
    } else {
        format!("{m}m")
    }
}

/// Render a `{key}`-style template, leaving unknown keys as empty strings.
///
/// Walks the template by `&str` slices so multi-byte UTF-8 characters
/// (emoji, accents, arrows) round-trip correctly. An unmatched opening
/// brace is left in place verbatim.
fn render(template: &str, fields: &HashMap<&'static str, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        if let Some(close) = after.find('}') {
            let key = &after[..close];
            if let Some(v) = fields.get(key) {
                out.push_str(v);
            }
            rest = &after[close + 1..];
        } else {
            out.push_str(&rest[open..]);
            return out;
        }
    }
    out.push_str(rest);
    out
}

#[derive(Debug)]
enum Transition {
    Start,
    Stop,
    Switch,
}

impl Transition {
    fn name(&self) -> &'static str {
        match self {
            Transition::Start => "start",
            Transition::Stop => "stop",
            Transition::Switch => "switch",
        }
    }
}

fn diff(
    prev: Option<&Snapshot>,
    curr: Option<&Snapshot>,
    now: DateTime<Tz>,
    templates: &Templates,
) -> Option<(Transition, String)> {
    match (prev, curr) {
        (None, Some(c)) => Some((Transition::Start, render(&templates.start, &c.fields()))),
        (Some(p), None) => {
            let mut f = p.fields();
            f.insert("duration", fmt_duration(p.start, now));
            Some((Transition::Stop, render(&templates.stop, &f)))
        }
        (Some(p), Some(c)) if p.start != c.start => {
            let mut f = c.fields();
            f.insert("prev_title", p.title.clone());
            f.insert("prev_duration", fmt_duration(p.start, now));
            Some((Transition::Switch, render(&templates.switch, &f)))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Matrix
// ---------------------------------------------------------------------------

async fn build_client(cfg: &Config, store_path: &Path) -> Result<Client> {
    fs::create_dir_all(store_path)
        .with_context(|| format!("creating store dir {}", store_path.display()))?;

    // The crypto store holds the bot's Olm identity and Megolm session
    // keys — anyone with read access can impersonate the bot in
    // encrypted rooms. Lock it down to the owning user on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(store_path, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("chmod 0700 {}", store_path.display()))?;
    }

    let client = Client::builder()
        .homeserver_url(&cfg.homeserver)
        .sqlite_store(store_path, cfg.store_passphrase.as_deref())
        .build()
        .await
        .context("building matrix-sdk client")?;

    let session = MatrixSession {
        meta: SessionMeta {
            user_id: cfg.user_id.clone(),
            device_id: cfg.device_id.clone(),
        },
        tokens: SessionTokens {
            access_token: cfg.access_token.clone(),
            refresh_token: None,
        },
    };

    // 0.16 exposes restore_session as a top-level Client shortcut that
    // picks the right auth backend (MatrixAuth vs OAuth) for the session.
    client
        .restore_session(session)
        .await
        .context("restoring matrix session (check user_id/device_id/access_token triple)")?;

    // Sanity-check the (user_id, device_id) pair against the server.
    // restore_session itself will happily accept any triple, but if the
    // device_id doesn't match the one MAS issued the token for, Megolm
    // key sharing will silently fail and messages will be undecryptable
    // for everyone in the room. Catch this at startup with a clear
    // error instead of leaving the user to debug missing decryption.
    let who = client
        .whoami()
        .await
        .context("whoami after restore_session")?;
    if who.user_id != cfg.user_id {
        bail!(
            "config user_id ({}) does not match server ({})",
            cfg.user_id,
            who.user_id
        );
    }
    if let Some(device_id) = who.device_id.as_ref() {
        if device_id != &cfg.device_id {
            bail!(
                "config device_id ({}) does not match server ({})",
                cfg.device_id,
                device_id
            );
        }
    }

    // Bootstrap cross-signing keys for the bot if they don't exist yet.
    // Without this the bot's device shows in clients as "unverified",
    // which is alarming even though decryption works fine. Once the bot
    // has self-signing/master/user-signing keys uploaded, clients can
    // see that the bot's device is signed by the bot's own master key,
    // and a single one-time verification of @faff-bot's master key by
    // a human user will trust every current and future bot device.
    //
    // Failure here is non-fatal: bot still sends/encrypts correctly,
    // device just shows unverified until somebody verifies it manually.
    bootstrap_cross_signing(&client).await;

    Ok(client)
}

/// Idempotent cross-signing setup. Logs and continues on failure
/// rather than aborting startup — encryption still works.
async fn bootstrap_cross_signing(client: &Client) {
    let encryption = client.encryption();
    match encryption.cross_signing_status().await {
        Some(status) if status.is_complete() => {
            tracing::debug!("cross-signing already set up for this device");
            return;
        }
        Some(status) => {
            tracing::info!(
                "cross-signing partially set up (master={}, self_signing={}, user_signing={}); \
                 (re)bootstrapping",
                status.has_master,
                status.has_self_signing,
                status.has_user_signing,
            );
        }
        None => {
            tracing::info!("no cross-signing keys found; bootstrapping");
        }
    }
    if let Err(e) = encryption.bootstrap_cross_signing(None).await {
        tracing::warn!(
            "cross-signing bootstrap failed: {e}. \
             The bot device will appear unverified in clients until \
             somebody verifies @faff-bot manually."
        );
    } else {
        tracing::info!("cross-signing bootstrap complete");
    }
}

/// Run the first sync from a fresh (or restored) crypto store.
///
/// `full_state(true)` is critical here: it makes matrix-sdk fetch the
/// complete member list of every joined room, so that when the bot
/// builds a Megolm session it shares with every device in the room.
/// Skipping it on the very first sync of a fresh store can lead to
/// silently undecryptable messages for some members.
async fn first_sync(client: &Client) -> Result<()> {
    client
        .sync_once(SyncSettings::default().full_state(true))
        .await
        .context("initial sync")?;
    Ok(())
}

async fn resolve_room(client: &Client, room: &str) -> Result<OwnedRoomId> {
    if let Some(rest) = room.strip_prefix('!') {
        return Ok(format!("!{rest}").parse()?);
    }
    if room.starts_with('#') {
        let alias: &RoomAliasId = <&RoomAliasId>::try_from(room)
            .map_err(|e| anyhow!("invalid room alias {room:?}: {e}"))?;
        let resp = client
            .resolve_room_alias(alias)
            .await
            .with_context(|| format!("resolving room alias {room}"))?;
        return Ok(resp.room_id);
    }
    bail!("invalid room identifier {room:?} — must start with # or !");
}

async fn ensure_member(client: &Client, room_id: &OwnedRoomId) -> Result<Room> {
    client
        .get_room(room_id)
        .ok_or_else(|| anyhow!("bot user is not a member of {room_id}; invite + accept first"))
}

async fn send_text(room: &Room, body: &str, dry_run: bool) -> Result<()> {
    if dry_run {
        println!("[dry_run] {body}");
        return Ok(());
    }
    let content = RoomMessageEventContent::text_plain(body);
    room.send(content)
        .await
        .with_context(|| format!("sending message: {body}"))?;
    println!("{body}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Workspace helpers
// ---------------------------------------------------------------------------

async fn read_active_snapshot(ws: &Arc<Workspace>) -> Result<Option<Snapshot>> {
    // NOTE: this only reads today's log. The Rust core's LogManager
    // auto-stops yesterday's unclosed sessions when get_log(today) is
    // first called after midnight, which fires a LogChanged event and
    // makes the watcher emit a "stop" notification at midnight even
    // though the user took no action. See #12 — this is currently
    // accepted behaviour, not a bug to fix here.
    let log = ws.logs().get_log(ws.today()).await?;
    Ok(log.active_session().map(Snapshot::from_session))
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

async fn cmd_test(cfg: Config, store_path: PathBuf) -> Result<()> {
    let client = build_client(&cfg, &store_path).await?;
    tracing::info!(
        "authenticated as {} (device {})",
        cfg.user_id,
        cfg.device_id
    );

    first_sync(&client).await?;
    let room_id = resolve_room(&client, &cfg.room).await?;
    tracing::info!("resolved room: {room_id}");
    let room = ensure_member(&client, &room_id).await?;

    // Warn if the room has only the bot as a joined member: the probe
    // message will be encrypted to nobody useful and "test ok" would be
    // misleading. This is the canonical first-run failure mode (other
    // invitees haven't accepted yet) and worth surfacing loudly.
    //
    // Use Room::members(RoomMemberships::JOIN) rather than
    // joined_members_count(): the latter reads from the cached room
    // summary populated lazily from heroes, which is wildly out of
    // date in fresh stores and produces false positives.
    let joined: Vec<RoomMember> = room
        .members(RoomMemberships::JOIN)
        .await
        .context("listing joined members")?;
    let other_joined = joined.iter().filter(|m| m.user_id() != cfg.user_id).count();
    if other_joined == 0 {
        tracing::warn!(
            "room {room_id} has only the bot user as a joined member. \
             The probe message will not be decryptable for anyone until other \
             members accept the invite and sync."
        );
    } else {
        tracing::info!(
            "room {room_id} has {other_joined} other joined member(s)"
        );
    }

    if cfg.dry_run {
        println!("dry_run set; not posting probe.");
        return Ok(());
    }
    send_text(&room, "[faff] connection test ok", false).await?;
    Ok(())
}

async fn cmd_now(cfg: Config, store_path: PathBuf) -> Result<()> {
    let ws = Workspace::new().await?;
    let snap = read_active_snapshot(&ws).await?;
    let Some(snap) = snap else {
        println!("no active session");
        return Ok(());
    };
    let body = render(&cfg.templates.start, &snap.fields());

    if cfg.dry_run {
        println!("[dry_run] {body}");
        return Ok(());
    }

    let client = build_client(&cfg, &store_path).await?;
    first_sync(&client).await?;
    let room_id = resolve_room(&client, &cfg.room).await?;
    let room = ensure_member(&client, &room_id).await?;
    send_text(&room, &body, false).await?;
    Ok(())
}

async fn cmd_run(cfg: Config, store_path: PathBuf) -> Result<()> {
    let client = build_client(&cfg, &store_path).await?;
    tracing::info!(
        "authenticated as {} device {}",
        cfg.user_id,
        cfg.device_id
    );

    first_sync(&client).await?;
    let room_id = resolve_room(&client, &cfg.room).await?;
    let room = ensure_member(&client, &room_id).await?;
    tracing::info!("posting to {room_id}");

    // Background sync keeps Megolm sessions and member lists current.
    // matrix-sdk's sync() returns on a non-recoverable error (network
    // dropout, server restart, MAS rotated the token). When that
    // happens we need to retry rather than silently giving up — the
    // watcher loop above keeps emitting events that would otherwise
    // all fail. Exponential backoff up to 60s.
    let bg_client = client.clone();
    let sync_handle = tokio::spawn(async move {
        let mut backoff = std::time::Duration::from_secs(2);
        loop {
            match bg_client.sync(SyncSettings::default()).await {
                Ok(()) => break,
                Err(e) => {
                    tracing::warn!(
                        "background sync stopped: {e}; retrying in {backoff:?}"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
                }
            }
        }
    });

    let ws = Workspace::new().await?;
    let mut prev = read_active_snapshot(&ws).await?;

    if cfg.announce_on_startup {
        if let Some(ref snap) = prev {
            if cfg.notify_on.contains("start") {
                let body = render(&cfg.templates.start, &snap.fields());
                if let Err(e) = send_text(&room, &body, cfg.dry_run).await {
                    tracing::warn!("startup announce failed: {e}");
                }
            }
        }
    }

    let stream = ws
        .storage()
        .spawn_event_stream()
        .ok_or_else(|| anyhow!("storage backend does not support event streams"))?;
    let mut rx = stream.subscribe();
    tracing::info!("watching faff workspace for log changes...");

    // Signal handlers for graceful shutdown. ctrl_c covers SIGINT;
    // SignalKind::terminate covers SIGTERM (systemd 'stop'). We need
    // both — without explicit handling, Ctrl-C kills the runtime
    // before any cleanup runs and systemd's SIGTERM is ignored.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing SIGTERM handler")?;

    loop {
        tokio::select! {
            recv = rx.recv() => match recv {
                Ok(StorageEvent::LogChanged(_)) => {
                    let curr = match read_active_snapshot(&ws).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("failed to read active session: {e}");
                            continue;
                        }
                    };
                    if let Some((kind, body)) =
                        diff(prev.as_ref(), curr.as_ref(), ws.now(), &cfg.templates)
                    {
                        if cfg.notify_on.contains(kind.name()) {
                            if let Err(e) = send_text(&room, &body, cfg.dry_run).await {
                                tracing::error!("matrix post failed: {e}");
                            }
                        }
                    }
                    prev = curr;
                }
                Ok(StorageEvent::PlanChanged(_)) => { /* ignore */ }
                Err(RecvError::Lagged(n)) => {
                    tracing::warn!("event stream lagged, dropped {n} events; resyncing state");
                    // Don't propagate transient read errors here — that
                    // would tear down the watcher on a hiccup. Match
                    // the other read_active_snapshot call site.
                    prev = match read_active_snapshot(&ws).await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!("post-lag resync failed: {e}");
                            continue;
                        }
                    };
                }
                Err(RecvError::Closed) => {
                    tracing::warn!("event stream closed");
                    break;
                }
            },
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received SIGINT, shutting down");
                break;
            }
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM, shutting down");
                break;
            }
        }
    }

    sync_handle.abort();
    let _ = sync_handle.await;
    Ok(())
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "faff-plugin-matrix-rust",
    about = "Post the current faff to an end-to-end encrypted Matrix room (Rust port)."
)]
struct Cli {
    /// Path to the plugin config TOML.
    #[arg(short, long)]
    config: PathBuf,

    /// E2EE crypto store directory (default: ~/.local/share/faff-plugin-matrix-rust/<id>)
    #[arg(long)]
    store_path: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the watcher loop (default).
    Run,
    /// Verify credentials, resolve room, post a probe message.
    Test,
    /// Post the current active session once and exit.
    Now,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Disable ANSI escape codes when stderr isn't a TTY (e.g. piped to
    // a file or captured by journald). Without this, every log line
    // gets wrapped in [2m...[0m noise that downstream consumers have
    // to strip.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,faff_plugin_matrix_rust=info")),
        )
        .init();

    let cli = Cli::parse();
    let cfg = Config::load(&cli.config)?;

    let store_path = cli.store_path.unwrap_or_else(|| {
        let base = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("faff-plugin-matrix-rust");
        base.join(&cfg.instance_id)
    });

    match cli.cmd.unwrap_or(Cmd::Run) {
        Cmd::Run => cmd_run(cfg, store_path).await,
        Cmd::Test => cmd_test(cfg, store_path).await,
        Cmd::Now => cmd_now(cfg, store_path).await,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono_tz::UTC;

    fn ts(h: u32, m: u32) -> DateTime<Tz> {
        chrono::NaiveDate::from_ymd_opt(2026, 4, 8)
            .unwrap()
            .and_hms_opt(h, m, 0)
            .unwrap()
            .and_local_timezone(UTC)
            .unwrap()
    }

    fn snap(title: &str, h: u32, m: u32) -> Snapshot {
        Snapshot {
            title: title.into(),
            role: String::new(),
            impact: String::new(),
            mode: String::new(),
            subject: String::new(),
            trackers: String::new(),
            start: ts(h, m),
        }
    }

    fn fields_with(title: &str) -> HashMap<&'static str, String> {
        let mut f = HashMap::new();
        f.insert("title", title.to_string());
        f
    }

    // ----- render -----

    #[test]
    fn render_handles_unicode_in_template() {
        // Regression for #1: byte-cast version produced mojibake here.
        assert_eq!(render("▶ {title}", &fields_with("ok")), "▶ ok");
    }

    #[test]
    fn render_handles_emoji_in_template() {
        assert_eq!(render("⏱ {title} 🎯", &fields_with("focus")), "⏱ focus 🎯");
    }

    #[test]
    fn render_unknown_keys_become_empty() {
        assert_eq!(render("[{nope}]", &HashMap::new()), "[]");
    }

    #[test]
    fn render_unmatched_open_brace_is_passthrough() {
        assert_eq!(render("hello {world", &HashMap::new()), "hello {world");
    }

    #[test]
    fn render_no_placeholders_is_identity() {
        assert_eq!(render("plain text", &HashMap::new()), "plain text");
    }

    #[test]
    fn render_replaces_multiple_placeholders() {
        let mut f = HashMap::new();
        f.insert("a", "1".to_string());
        f.insert("b", "2".to_string());
        assert_eq!(render("{a}-{b}", &f), "1-2");
    }

    // ----- diff -----

    #[test]
    fn diff_none_to_none_is_no_op() {
        let templates = templates();
        assert!(diff(None, None, ts(12, 0), &templates).is_none());
    }

    #[test]
    fn diff_none_to_some_is_start() {
        let templates = templates();
        let curr = snap("hack", 9, 0);
        let (kind, _body) = diff(None, Some(&curr), ts(9, 5), &templates).unwrap();
        assert!(matches!(kind, Transition::Start));
    }

    #[test]
    fn diff_some_to_none_is_stop() {
        let templates = templates();
        let prev = snap("hack", 9, 0);
        let (kind, _body) = diff(Some(&prev), None, ts(9, 30), &templates).unwrap();
        assert!(matches!(kind, Transition::Stop));
    }

    #[test]
    fn diff_same_start_is_no_op() {
        let templates = templates();
        let prev = snap("hack", 9, 0);
        let curr = snap("hack", 9, 0);
        assert!(diff(Some(&prev), Some(&curr), ts(9, 30), &templates).is_none());
    }

    #[test]
    fn diff_different_start_is_switch() {
        let templates = templates();
        let prev = snap("hack", 9, 0);
        let curr = snap("review", 10, 0);
        let (kind, body) = diff(Some(&prev), Some(&curr), ts(10, 5), &templates).unwrap();
        assert!(matches!(kind, Transition::Switch));
        assert!(body.contains("hack"));
        assert!(body.contains("review"));
    }

    fn templates() -> Templates {
        Templates {
            start: "[start] {title}".to_string(),
            stop: "[stop] {title} ({duration})".to_string(),
            switch: "[switch] {prev_title} -> {title} ({prev_duration})".to_string(),
        }
    }

    // ----- fmt_duration -----

    #[test]
    fn fmt_duration_minutes_only() {
        assert_eq!(fmt_duration(ts(9, 0), ts(9, 5)), "5m");
    }

    #[test]
    fn fmt_duration_hours_and_minutes() {
        assert_eq!(fmt_duration(ts(9, 0), ts(11, 30)), "2h30m");
    }

    #[test]
    fn fmt_duration_zero() {
        assert_eq!(fmt_duration(ts(9, 0), ts(9, 0)), "0m");
    }

    #[test]
    fn fmt_duration_negative_clamps_to_zero() {
        // Clock skew between log and now: end < start.
        assert_eq!(fmt_duration(ts(11, 0), ts(9, 0)), "0m");
    }

    #[test]
    fn fmt_duration_pads_minutes_when_hours_present() {
        assert_eq!(fmt_duration(ts(9, 0), ts(10, 5)), "1h05m");
    }
}
