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
    ruma::{
        events::room::message::RoomMessageEventContent, OwnedDeviceId, OwnedRoomId, OwnedUserId,
        RoomAliasId,
    },
    Client, Room, SessionMeta, SessionTokens,
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
fn render(template: &str, fields: &HashMap<&'static str, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            if let Some(end) = template[i + 1..].find('}') {
                let key = &template[i + 1..i + 1 + end];
                if let Some(v) = fields.get(key) {
                    out.push_str(v);
                } // unknown keys render as empty
                i += 1 + end + 1;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
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

    let client = Client::builder()
        .homeserver_url(&cfg.homeserver)
        .sqlite_store(store_path, None)
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

    Ok(client)
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
    let log = ws.logs().get_log(ws.today()).await?;
    Ok(log.active_session().map(Snapshot::from_session))
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

async fn cmd_test(cfg: Config, store_path: PathBuf) -> Result<()> {
    let client = build_client(&cfg, &store_path).await?;
    println!(
        "authenticated as {} (device {})",
        cfg.user_id, cfg.device_id
    );

    // Initial sync to fetch room state and learn membership.
    client.sync_once(SyncSettings::default()).await?;
    let room_id = resolve_room(&client, &cfg.room).await?;
    println!("resolved room: {room_id}");
    let room = ensure_member(&client, &room_id).await?;

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
    client.sync_once(SyncSettings::default()).await?;
    let room_id = resolve_room(&client, &cfg.room).await?;
    let room = ensure_member(&client, &room_id).await?;
    send_text(&room, &body, false).await?;
    Ok(())
}

async fn cmd_run(cfg: Config, store_path: PathBuf) -> Result<()> {
    let client = build_client(&cfg, &store_path).await?;
    eprintln!(
        "authenticated as {} device {}",
        cfg.user_id, cfg.device_id
    );

    client.sync_once(SyncSettings::default().full_state(true)).await?;
    let room_id = resolve_room(&client, &cfg.room).await?;
    let room = ensure_member(&client, &room_id).await?;
    eprintln!("posting to {room_id}");

    // Background sync keeps Megolm sessions and member lists current.
    let bg_client = client.clone();
    let sync_handle = tokio::spawn(async move {
        if let Err(e) = bg_client.sync(SyncSettings::default()).await {
            eprintln!("warn: background sync stopped: {e}");
        }
    });

    let ws = Workspace::new().await?;
    let mut prev = read_active_snapshot(&ws).await?;

    if cfg.announce_on_startup {
        if let Some(ref snap) = prev {
            if cfg.notify_on.contains("start") {
                let body = render(&cfg.templates.start, &snap.fields());
                if let Err(e) = send_text(&room, &body, cfg.dry_run).await {
                    eprintln!("warn: startup announce failed: {e}");
                }
            }
        }
    }

    let stream = ws
        .storage()
        .spawn_event_stream()
        .ok_or_else(|| anyhow!("storage backend does not support event streams"))?;
    let mut rx = stream.subscribe();
    eprintln!("watching faff workspace for log changes...");

    loop {
        match rx.recv().await {
            Ok(StorageEvent::LogChanged(_)) => {
                let curr = match read_active_snapshot(&ws).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("warn: failed to read active session: {e}");
                        continue;
                    }
                };
                if let Some((kind, body)) =
                    diff(prev.as_ref(), curr.as_ref(), ws.now(), &cfg.templates)
                {
                    if cfg.notify_on.contains(kind.name()) {
                        if let Err(e) = send_text(&room, &body, cfg.dry_run).await {
                            eprintln!("matrix post failed: {e}");
                        }
                    }
                }
                prev = curr;
            }
            Ok(StorageEvent::PlanChanged(_)) => { /* ignore */ }
            Err(RecvError::Lagged(n)) => {
                eprintln!("warn: event stream lagged, dropped {n} events; resyncing state");
                prev = read_active_snapshot(&ws).await?;
            }
            Err(RecvError::Closed) => {
                eprintln!("event stream closed");
                break;
            }
        }
    }

    sync_handle.abort();
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
    tracing_subscriber::fmt()
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
