//! The GoNomad daemon and the `gonomad` command-line interface.
//!
//! One binary is both the daemon and the CLI (`ARCHITECTURE.md` §5.3), because a
//! self-hosted tool that needs two executables installed correctly has doubled
//! the number of ways a first run can fail.

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

mod fs_service;
mod state;

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

    /// Report this machine's identity and configuration.
    Status,

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
        Command::Pair { workspace } => cmd_pair(&paths, workspace),
        Command::Status => cmd_status(&paths),
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

fn cmd_pair(paths: &state::Paths, workspace: Option<PathBuf>) -> Result<()> {
    let identity = state::load_identity(paths)?;

    let workspace = workspace
        .or_else(|| std::env::current_dir().ok())
        .context("no workspace given and the current directory is unreadable")?;
    let workspace = dunce::canonicalize(&workspace)
        .with_context(|| format!("workspace {} does not exist", workspace.display()))?;

    let secret = PairingSecret::generate();
    let addrs = local_addresses();

    let ticket = PairingTicket {
        daemon_key: identity.noise_public_key(),
        addr_hints: addrs.clone(),
        relay_hint: None,
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
    println!("  manual code   {}", ManualCode::from_secret(&secret));
    println!("  valid for     120 seconds, single use");
    println!();
    println!("Scan the code above with the GoNomad app, then confirm the six digits");
    println!("shown on your phone match the ones this machine displays.");
    println!();

    // The listener is not wired up yet, so say so rather than appearing to wait.
    println!("note: this build renders the pairing code but does not yet accept a");
    println!("      connection — the transport layer is still landing. `gonomad pair`");
    println!("      is currently useful for verifying the code renders and scans.");

    Ok(())
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

    warn(
        "transport",
        "not implemented yet — pairing cannot complete in this build",
    );
    warn("mobile app", "not wired to the daemon yet");

    println!();
    println!("No inbound port needs to be opened; GoNomad never asks you to");
    println!("port-forward. See docs/deployment.md.");
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
