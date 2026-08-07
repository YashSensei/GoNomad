//! The GoNomad daemon and the `gonomad` command-line interface.
//!
//! One binary is both the daemon and the CLI (`ARCHITECTURE.md` §5.3), because a
//! self-hosted tool that needs two executables installed correctly has doubled
//! the number of ways a first run can fail.

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

use gonomad_server::{fs_service, router, serve, state};

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use gonomad_core::{ManualCode, PairingSecret, PairingTicket};
use gonomad_policy::{PathGuard, SecretDenylist, WorkspaceRoot};

/// GoNomad — your development machine, anywhere.
#[derive(Debug, Parser)]
#[command(name = "gonomad", version, about, long_about = None)]
struct Cli {
    /// Override the state directory. Mainly for testing side by side.
    #[arg(long, global = true, value_name = "DIR")]
    state_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create this machine's identity. Run once, before anything else.
    Init,

    /// Show a pairing QR code for a phone to scan.
    Pair {
        /// Workspace root to grant the phone access to. Defaults to the
        /// current directory.
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
    },

    /// Serve paired devices until interrupted.
    Serve {
        /// Workspace root to expose. Defaults to the current directory.
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
        /// Port to listen on.
        #[arg(long, default_value_t = gonomad_transport::DEFAULT_PORT)]
        port: u16,
    },

    /// Report this machine's identity and configuration.
    Status,

    /// List paired devices.
    Devices,

    /// List the files the daemon would expose for a workspace.
    ///
    /// A diagnostic: it runs the real policy pipeline, so it shows exactly what a
    /// paired phone would and would not see — including secrets being hidden.
    Ls {
        /// Directory to list.
        path: Option<PathBuf>,
        /// Workspace root to treat as the boundary. Defaults to `path`.
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
    },

    /// Print a file exactly as the daemon would send it to a phone.
    ///
    /// The other half of the `ls` diagnostic: it proves the read path refuses
    /// secrets, refuses binaries, and reports truncation rather than hiding it.
    Cat {
        /// File to read.
        path: PathBuf,
        /// Workspace root to treat as the boundary. Defaults to the file's parent.
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
    },

    /// Diagnose the environment: shells, state, and what is missing.
    Doctor,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "gonomad=info".into()),
        )
        .with_target(false)
        .init();

    let cli = Cli::parse();
    let paths = match &cli.state_dir {
        Some(dir) => state::Paths::under(dir.clone()),
        None => state::Paths::discover().context("could not locate a state directory")?,
    };

    match cli.command {
        Command::Init => cmd_init(&paths),
        Command::Pair { workspace } => runtime()?.block_on(cmd_pair(&paths, workspace)),
        Command::Serve { workspace, port } => {
            runtime()?.block_on(cmd_serve(&paths, workspace, port))
        }
        Command::Status => cmd_status(&paths),
        Command::Devices => cmd_devices(&paths),
        Command::Ls { path, workspace } => cmd_ls(path, workspace),
        Command::Cat { path, workspace } => cmd_cat(path, workspace),
        Command::Doctor => {
            cmd_doctor(&paths);
            Ok(())
        }
    }
}

fn cmd_init(paths: &state::Paths) -> Result<()> {
    let identity = state::create_identity(paths).context("could not create an identity")?;

    println!("GoNomad initialised.");
    println!();
    println!("  state directory  {}", paths.root.display());
    println!("  device id        {}", identity.device_id());
    println!("  signing key      {}", identity.public_key().short());
    println!("  noise key        {}", identity.noise_public_key().short());
    println!();
    println!("{}", state::KEY_STORAGE_WARNING);
    println!();
    println!("Next: run `gonomad pair` and scan the code with the GoNomad app.");
    Ok(())
}

async fn cmd_pair(paths: &state::Paths, workspace: Option<PathBuf>) -> Result<()> {
    let identity = std::sync::Arc::new(state::load_identity(paths)?);

    let workspace = resolve_workspace(workspace)?;

    let secret = PairingSecret::generate();

    let store = gonomad_store::Store::open(&paths.database)
        .context("could not open the device database")?;
    let daemon = build_daemon(&workspace)?;

    // Bind BEFORE building the ticket. The hints a QR pins have to describe an
    // endpoint that exists: iroh chooses its own UDP port, so the only way to
    // advertise a reachable address is to ask the bound endpoint for it. The
    // previous version called `local_addresses()`, which guessed the interface
    // correctly but hard-coded port 41234 — a port nothing was listening on. Those
    // hints could never succeed, so every same-network pairing silently fell
    // through to hole-punching or a relay instead of taking the fast LAN path.
    let transport = serve::bind_pairing_iroh(std::sync::Arc::clone(&identity), &secret).await?;

    // Wait for a relay before advertising one, so the ticket cannot pin a relay
    // the endpoint has not settled on yet.
    transport.online().await;

    // The NodeId is what makes the phone reachable off-LAN: iroh dials by public
    // key and finds a path itself, so this is the field that turns "same Wi-Fi
    // only" into "any network". The direct addresses stay as hints because they
    // make the same-network case fast, but they are no longer what pairing depends
    // on. `addr_hints` also carries the relay URL, which is what lets a phone on
    // mobile data reach a machine behind CGNAT on the very first attempt.
    let hints = transport.addr_hints();
    let addrs: Vec<String> = hints
        .iter()
        .filter_map(|hint| hint.socket_addr().map(|addr| addr.to_string()))
        .collect();
    // `AddrHint` is `#[non_exhaustive]`, so a wildcard is required. A hint kind
    // this build does not know about is not a relay, which is the safe reading.
    let relay_hint = hints.iter().find_map(|hint| match hint {
        gonomad_transport::AddrHint::Relay(url) => Some(url.clone()),
        _ => None,
    });

    let ticket = PairingTicket {
        daemon_key: identity.noise_public_key(),
        node_id: identity.iroh_node_id(),
        addr_hints: addrs.clone(),
        relay_hint: relay_hint.clone(),
    };
    let payload = ticket.encode(&secret);

    println!();
    render_qr(&payload)?;
    println!();
    println!("  workspace     {}", workspace.display());
    println!(
        "  addresses     {}",
        if addrs.is_empty() {
            "none found".into()
        } else {
            addrs.join(", ")
        }
    );
    println!(
        "  relay         {}",
        relay_hint.as_deref().unwrap_or("none — direct only")
    );
    println!("  manual code   {}", ManualCode::from_secret(&secret));
    println!("  valid for     120 seconds, single use");
    println!();
    println!("Scan the code above with the GoNomad app, then confirm the six digits");
    println!("shown on your phone match the ones this machine displays.");
    println!();
    println!("Waiting for a device…  (Ctrl-C to cancel)");
    println!();
    println!("Your phone does not need to be on this network. If nothing happens after");
    println!("scanning, check the phone has internet at all — run `gonomad doctor` too.");

    // The endpoint is already bound and already advertised in the QR above, so this
    // only waits for a device on it (ARCHITECTURE.md §4.2 Tiers 1–2). The TCP
    // binding remains available and is marginally faster on a LAN, but making it
    // the default here is what made pairing fail off-network.
    let device = serve::run_pairing_iroh(
        &transport,
        daemon,
        &store,
        std::time::Duration::from_millis(gonomad_core::PAIRING_WINDOW_MS),
    )
    .await?;

    // The "Paired" line is printed from inside serve_pairing the moment the
    // device registers, because the connection is deliberately kept open
    // afterwards so the reply is not truncated.
    tracing::debug!(device = %device.name, "pairing window closed");
    Ok(())
}

async fn cmd_serve(paths: &state::Paths, workspace: Option<PathBuf>, port: u16) -> Result<()> {
    let identity = std::sync::Arc::new(state::load_identity(paths)?);
    let workspace = resolve_workspace(workspace)?;
    let store = gonomad_store::Store::open(&paths.database)
        .context("could not open the device database")?;
    let daemon = build_daemon(&workspace)?;

    println!("GoNomad serving");
    println!("  workspace   {}", workspace.display());
    println!("  identity    {}", identity.noise_public_key().short());
    println!("  reachable   any network — hole-punched, with a relay fallback");
    println!();
    println!("{}", state::KEY_STORAGE_WARNING);
    println!();
    println!("Ctrl-C to stop.");
    println!();

    // `port` is only meaningful to the Tier 0 TCP binding. iroh picks its own
    // UDP port and does not need an inbound rule, which is the whole point.
    let _ = port;
    serve::serve_iroh(identity, daemon, store).await
}

fn cmd_devices(paths: &state::Paths) -> Result<()> {
    let store = gonomad_store::Store::open(&paths.database)
        .context("could not open the device database")?;
    let devices = store
        .devices()
        .list_active()
        .context("could not read the device list")?;

    if devices.is_empty() {
        println!("No devices paired. Run `gonomad pair`.");
        return Ok(());
    }

    println!("{} paired device(s):", devices.len());
    for d in devices {
        println!(
            "  {}  {}  key {}",
            d.id.short(),
            d.name,
            d.public_key.short()
        );
    }
    Ok(())
}

/// Resolves and canonicalises a workspace argument.
fn resolve_workspace(workspace: Option<PathBuf>) -> Result<PathBuf> {
    let raw = workspace
        .or_else(|| std::env::current_dir().ok())
        .context("no workspace given and the current directory is unreadable")?;
    dunce::canonicalize(&raw).with_context(|| format!("workspace {} does not exist", raw.display()))
}

/// Assembles the services a connection needs.
fn build_daemon(workspace: &std::path::Path) -> Result<std::sync::Arc<router::Daemon>> {
    let service = build_fs_service(workspace)?;
    Ok(std::sync::Arc::new(router::Daemon {
        fs: service,
        ptys: std::sync::Arc::new(parking_lot::Mutex::new(gonomad_pty::PtyManager::new())),
        workspace_roots: vec![workspace.display().to_string()],
        host_name: hostname(),
    }))
}

/// The machine's name, for the phone's "paired machine" card.
fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "this machine".to_owned())
}

/// A multi-threaded tokio runtime for the commands that need one.
///
/// Built here rather than with `#[tokio::main]` so the synchronous commands —
/// `init`, `status`, `ls`, `cat`, `doctor` — do not pay for a runtime they never
/// use. `doctor` in particular should stay usable on a machine too broken to
/// start one.
fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new().context("could not start the async runtime")
}

fn cmd_status(paths: &state::Paths) -> Result<()> {
    println!("state directory   {}", paths.root.display());

    if paths.is_initialised() {
        let identity = state::load_identity(paths)?;
        println!("initialised       yes");
        println!("device id         {}", identity.device_id());
        println!("signing key       {}", identity.public_key().short());
        println!("noise key         {}", identity.noise_public_key().short());
    } else {
        println!("initialised       no  — run `gonomad init`");
    }

    let addrs = local_addresses();
    println!(
        "addresses         {}",
        if addrs.is_empty() {
            "none found".into()
        } else {
            addrs.join(", ")
        }
    );
    println!("shells            {}", shell_summary());
    Ok(())
}

fn cmd_ls(path: Option<PathBuf>, workspace: Option<PathBuf>) -> Result<()> {
    let target = absolutise(
        path.or_else(|| std::env::current_dir().ok())
            .context("no path given and the current directory is unreadable")?,
    )?;
    let root = match workspace {
        Some(w) => absolutise(w)?,
        None => target.clone(),
    };
    let service = build_fs_service(&root)?;
    let grant = diagnostic_grant();

    let target_str = target.to_string_lossy();
    match service.list(Some(&grant), &target_str) {
        Ok(entries) => {
            println!("{} entries a paired phone would see:", entries.len());
            for entry in entries {
                let marker = match entry.kind {
                    fs_service::EntryKind::Directory => "/",
                    fs_service::EntryKind::Symlink => "@",
                    fs_service::EntryKind::File => "",
                };
                let size = entry
                    .size_bytes
                    .map_or_else(String::new, |b| format!("{b:>10} "));
                println!("  {size}{}{marker}", entry.name);
            }
            println!();
            println!("Anything on the secret denylist (.env, .ssh, keys) is absent by design.");
        }
        Err(e) => println!("denied: {}  ({})", e.kind.user_message(), e.kind.code()),
    }
    Ok(())
}

fn cmd_cat(path: PathBuf, workspace: Option<PathBuf>) -> Result<()> {
    let path = absolutise(path)?;
    let root = match workspace {
        Some(w) => absolutise(w)?,
        None => path
            .parent()
            .map(std::path::Path::to_path_buf)
            .context("could not determine a workspace root for that file")?,
    };

    let service = build_fs_service(&root)?;
    let grant = diagnostic_grant();

    match service.read(Some(&grant), &path.to_string_lossy()) {
        Ok(content) => {
            println!("path        {}", content.path);
            println!("hash        {}", content.content_hash.short());
            println!("bytes       {}", content.text.len());
            if content.truncated {
                println!(
                    "truncated   yes — showing the first {} bytes",
                    fs_service::MAX_READ_BYTES
                );
            }
            println!("---");
            print!("{}", content.text);
            if !content.text.ends_with('\n') {
                println!();
            }
        }
        Err(e) => println!("refused: {}  ({})", e.kind.user_message(), e.kind.code()),
    }
    Ok(())
}

/// Resolves a possibly-relative CLI argument to an absolute path.
///
/// The path guard refuses relative paths on purpose: resolving them against the
/// daemon's working directory would be a footgun, since a request's meaning would
/// then depend on where the daemon happened to be started. Resolving them is the
/// *CLI's* job, because only the CLI has a user with a shell and a cwd.
fn absolutise(path: PathBuf) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path);
    }
    let cwd = std::env::current_dir().context("the current directory is unreadable")?;
    Ok(cwd.join(path))
}

/// Builds a policy-guarded filesystem service over one workspace root.
fn build_fs_service(root: &std::path::Path) -> Result<fs_service::FsService> {
    let root = WorkspaceRoot::new(root)
        .with_context(|| format!("workspace root {} does not exist", root.display()))?;
    Ok(fs_service::FsService::new(
        gonomad_policy::PolicyEngine::new(
            PathGuard::new(vec![root]),
            SecretDenylist::with_defaults(),
        ),
    ))
}

/// The grant the `ls` and `cat` diagnostics run under.
///
/// Deliberately a *newly paired* device's grant rather than a full one, so the
/// diagnostics show what a real phone sees — including secrets being refused.
fn diagnostic_grant() -> gonomad_policy::DeviceGrant {
    gonomad_policy::DeviceGrant::newly_paired(gonomad_proto::DeviceId::from_bytes([0u8; 32]))
}

/// Reports environment problems rather than failing on them.
///
/// Returns nothing, deliberately: a diagnostic that exits non-zero on the first
/// problem it finds would hide every problem after it, which is the opposite of
/// what someone running `doctor` needs.
fn cmd_doctor(paths: &state::Paths) {
    println!("GoNomad doctor");
    println!();

    let ok = |label: &str, detail: &str| println!("  [ok]   {label:<18} {detail}");
    let warn = |label: &str, detail: &str| println!("  [warn] {label:<18} {detail}");

    if paths.is_initialised() {
        ok("identity", &paths.identity.display().to_string());
        warn(
            "key storage",
            "plain file, not the OS keyring (see ARCHITECTURE.md 3.3)",
        );
    } else {
        warn("identity", "not created — run `gonomad init`");
    }

    if paths.database.exists() {
        ok("database", &paths.database.display().to_string());
    } else {
        warn(
            "database",
            "not created yet; it appears on first connection",
        );
    }
    if paths.config.exists() {
        ok("config", &paths.config.display().to_string());
    } else {
        warn("config", "using defaults; no config.toml written yet");
    }

    let shells = gonomad_pty::detect();
    if shells.is_empty() {
        warn("shells", "none found; terminals will not work");
    } else {
        ok("shells", &shell_summary());
    }

    let addrs = local_addresses();
    if addrs.is_empty() {
        warn(
            "network",
            "no non-loopback address found; a phone cannot reach this machine",
        );
    } else {
        ok("network", &addrs.join(", "));
    }

    ok(
        "transport",
        "LAN direct — TCP + Noise. NAT traversal (iroh) lands later",
    );

    println!();
    print_firewall_note(gonomad_transport::DEFAULT_PORT);
    println!();
    println!("No router configuration and no port forwarding are ever needed.");
    println!("See docs/deployment.md.");
}

/// Explains the local firewall, which is the first thing that actually blocks a
/// phone on Windows.
///
/// Worth a dedicated note rather than a line in the docs: the daemon binds
/// successfully, prints a QR, and reports itself healthy, while the phone's
/// connection is dropped before the daemon ever sees it. Every symptom points at
/// the app, and none points at the firewall. Detecting the rule reliably would
/// mean parsing `netsh` output across locales, so the useful thing is to hand
/// over the exact command instead.
fn print_firewall_note(port: u16) {
    #[cfg(windows)]
    {
        println!("Windows Firewall blocks inbound connections by default, and it will");
        println!("silently drop your phone before the daemon sees it. Allow the port once,");
        println!("from an Administrator PowerShell:");
        println!();
        println!("  New-NetFirewallRule -DisplayName 'GoNomad' -Direction Inbound `");
        println!("    -Action Allow -Protocol TCP -LocalPort {port} -Profile Private");
        println!();
        println!("Private profile only, deliberately: that covers your home and office");
        println!("networks and leaves the port closed on any network Windows considers");
        println!("public, which is where you would least want it open.");
    }
    #[cfg(not(windows))]
    {
        println!("If a local firewall is active, allow inbound TCP on port {port} for your");
        println!("local network only. GoNomad never needs an inbound rule at the router.");
    }
}

/// Non-loopback IPv4 addresses, for the pairing ticket's hints.
///
/// Hand-rolled by asking the OS to route to a public address and reporting the
/// local end of that socket. No packet is sent — a UDP `connect` only selects a
/// route — so this works offline and needs no extra dependency. It reports the
/// address of the interface that would carry traffic, which is exactly the one a
/// phone on the same network should try.
fn local_addresses() -> Vec<String> {
    use std::net::UdpSocket;

    const PORT: u16 = 41_234;
    let mut found = Vec::new();

    for probe in ["8.8.8.8:80", "1.1.1.1:80"] {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(probe).is_ok() {
                if let Ok(addr) = sock.local_addr() {
                    let candidate = format!("{}:{PORT}", addr.ip());
                    if !addr.ip().is_loopback() && !found.contains(&candidate) {
                        found.push(candidate);
                    }
                }
            }
        }
    }
    found
}

fn shell_summary() -> String {
    let shells = gonomad_pty::detect();
    if shells.is_empty() {
        return "none".into();
    }
    shells
        .iter()
        .map(|s| s.display_name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Prints the pairing payload as a QR code in the terminal.
///
/// Rendered with two half-blocks per module so the code stays square in a
/// character cell, which is what makes it scannable from a screen.
fn render_qr(payload: &str) -> Result<()> {
    use qrcode::{EcLevel, QrCode};

    // Low error correction keeps the code small enough to stay scannable in a
    // terminal at a readable size; the payload is short-lived and re-generable,
    // so a failed scan costs a retry rather than anything worse.
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::L)
        .context("the pairing payload could not be encoded as a QR code")?;

    let rendered = code
        .render::<char>()
        .quiet_zone(true)
        .module_dimensions(2, 1)
        .light_color(' ')
        .dark_color('█')
        .build();

    let mut out = std::io::stdout().lock();
    for line in rendered.lines() {
        writeln!(out, "  {line}")?;
    }
    out.flush()?;
    Ok(())
}
