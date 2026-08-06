//! GoNomad terminals.
//!
//! PTY lifecycle plus a **daemon-side terminal emulator**. The daemon holds the
//! authoritative screen and sends the phone a rendered view, never a raw byte
//! stream (`ARCHITECTURE.md` §8.3). That is what puts a hard ceiling on the
//! bandwidth a noisy command can cost, and it is why the phone needs no VT
//! parser at all.
//!
//! | Module | Contents |
//! |---|---|
//! | [`shell`] | Shell detection, Windows-first: PowerShell 7 → PowerShell → WSL → cmd |
//! | [`session`] | [`PtyManager`], the PTY lifecycle, and the screen snapshot |

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

pub mod session;
pub mod shell;

pub use session::{
    PtyError, PtyId, PtyManager, ScreenSnapshot, DEFAULT_COLS, DEFAULT_ROWS, SCROLLBACK_LINES,
};
pub use shell::{by_id, default_shell, detect, Shell};
