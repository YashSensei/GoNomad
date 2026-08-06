//! Shell detection.
//!
//! Windows is GoNomad's first-class host (`ARCHITECTURE.md` §8.2), and its shell
//! situation is genuinely more complicated than Unix's: there are four plausible
//! shells, they behave differently, and the best one is not the default one.
//!
//! Detection order on Windows is PowerShell 7 → Windows PowerShell → WSL →
//! `cmd`. PowerShell 7 first because it is what a developer who installed it
//! wants; `cmd` last because it is the weakest but is guaranteed present, so it
//! is the floor rather than the default.
//!
//! WSL is offered as a first-class choice because many Windows developers
//! effectively live there. It carries a caveat the filesystem layer must respect:
//! **a WSL shell's paths are Linux paths**, so a PTY's working directory does not
//! necessarily share the host's path namespace (§8.2).

use std::path::PathBuf;

/// A shell the daemon can spawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shell {
    /// Stable identifier, e.g. `"pwsh"`. Used in config and on the wire.
    pub id: String,
    /// Human-readable name for the terminal's shell picker.
    pub display_name: String,
    /// Absolute path to the executable.
    pub program: PathBuf,
    /// Arguments needed to get an interactive shell.
    pub args: Vec<String>,
    /// Whether this shell's paths live in a different namespace from the host's.
    ///
    /// True for WSL. The filesystem layer must not assume a PTY's cwd is a valid
    /// host path when this is set.
    pub foreign_path_namespace: bool,
}

impl Shell {
    fn new(id: &str, display: &str, program: PathBuf, args: &[&str]) -> Self {
        Self {
            id: id.to_owned(),
            display_name: display.to_owned(),
            program,
            args: args.iter().map(|s| (*s).to_owned()).collect(),
            foreign_path_namespace: false,
        }
    }
}

/// Returns every shell found on this machine, best first.
///
/// Never empty on a functioning system: the last resort (`cmd` on Windows,
/// `/bin/sh` on Unix) is effectively guaranteed. Returning an empty list is
/// possible in principle and callers must handle it rather than indexing `[0]`.
#[must_use]
pub fn detect() -> Vec<Shell> {
    let mut found = Vec::new();

    #[cfg(windows)]
    {
        // PowerShell 7+, if installed. Preferred: it is what a developer who
        // went out of their way to install it expects to get.
        if let Some(p) = which("pwsh.exe") {
            found.push(Shell::new("pwsh", "PowerShell 7", p, &["-NoLogo"]));
        }

        // Windows PowerShell 5.1 — always present on a modern Windows.
        if let Some(p) = which("powershell.exe") {
            found.push(Shell::new(
                "powershell",
                "Windows PowerShell",
                p,
                &["-NoLogo"],
            ));
        }

        // WSL, if a distribution is installed. `wsl.exe` exists on Windows 10+
        // even with no distro, so its mere presence is not enough — but probing
        // properly means running it, which is too slow for a detect() call.
        // Listed optimistically and allowed to fail at spawn, where the error is
        // actionable, rather than blocking startup on a subprocess.
        if let Some(p) = which("wsl.exe") {
            let mut shell = Shell::new("wsl", "WSL", p, &["--cd", "~"]);
            shell.foreign_path_namespace = true;
            found.push(shell);
        }

        // The floor. Always available, least capable.
        if let Some(p) = which("cmd.exe") {
            found.push(Shell::new("cmd", "Command Prompt", p, &[]));
        }
    }

    #[cfg(unix)]
    {
        // Honour the user's configured login shell first — it is the one their
        // dotfiles, prompt, and aliases are set up for.
        if let Some(sh) = std::env::var_os("SHELL").map(PathBuf::from) {
            if sh.exists() {
                let name = sh
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("shell")
                    .to_owned();
                found.push(Shell::new(&name, &name, sh, &["-l"]));
            }
        }

        for (id, display, candidate) in [
            ("zsh", "zsh", "/bin/zsh"),
            ("bash", "bash", "/bin/bash"),
            ("sh", "sh", "/bin/sh"),
        ] {
            let path = PathBuf::from(candidate);
            if path.exists() && !found.iter().any(|s| s.program == path) {
                found.push(Shell::new(id, display, path, &["-l"]));
            }
        }
    }

    found
}

/// Returns the best available shell, or `None` on a system with none.
#[must_use]
pub fn default_shell() -> Option<Shell> {
    detect().into_iter().next()
}

/// Looks up a shell by its identifier.
#[must_use]
pub fn by_id(id: &str) -> Option<Shell> {
    detect().into_iter().find(|s| s.id == id)
}

/// Resolves an executable name against `PATH`.
///
/// Hand-rolled rather than adding a `which` dependency: the logic is a dozen
/// lines and this crate's dependency list is worth keeping short.
#[cfg(windows)]
fn which(exe: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(exe))
        .find(|candidate| candidate.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_finds_at_least_one_shell() {
        // If this fails, the host is too broken to run a terminal at all — but a
        // caller must still not index into an empty vec, hence the Option API.
        let shells = detect();
        assert!(!shells.is_empty(), "no shell found on this machine");
    }

    #[test]
    fn every_detected_shell_actually_exists() {
        for shell in detect() {
            assert!(
                shell.program.is_file(),
                "{} points at {:?}, which is not a file",
                shell.id,
                shell.program
            );
        }
    }

    #[test]
    fn shell_ids_are_unique() {
        // Ids reach config files and the wire, so a duplicate would make
        // `by_id` ambiguous.
        let shells = detect();
        let mut ids: Vec<&str> = shells.iter().map(|s| s.id.as_str()).collect();
        ids.sort_unstable();
        let before = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), before, "duplicate shell ids: {ids:?}");
    }

    #[test]
    fn default_shell_is_the_first_detected() {
        assert_eq!(default_shell(), detect().into_iter().next());
    }

    #[test]
    fn by_id_round_trips_for_every_detected_shell() {
        for shell in detect() {
            assert_eq!(by_id(&shell.id).as_ref(), Some(&shell));
        }
    }

    #[test]
    fn unknown_ids_return_none() {
        assert!(by_id("definitely-not-a-shell").is_none());
        assert!(by_id("").is_none());
    }

    #[test]
    fn every_shell_has_a_display_name() {
        for shell in detect() {
            assert!(
                !shell.display_name.is_empty(),
                "{} has no display name",
                shell.id
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn powershell_is_preferred_over_cmd() {
        // cmd is the floor, not the default. If PowerShell exists it must win.
        let shells = detect();
        let ps = shells
            .iter()
            .position(|s| s.id == "pwsh" || s.id == "powershell");
        let cmd = shells.iter().position(|s| s.id == "cmd");
        if let (Some(ps), Some(cmd)) = (ps, cmd) {
            assert!(ps < cmd, "cmd was preferred over PowerShell");
        }
    }

    #[cfg(windows)]
    #[test]
    fn wsl_is_flagged_as_a_foreign_path_namespace() {
        // A WSL shell's cwd is a Linux path. Callers that assume otherwise will
        // hand the filesystem layer an invalid host path.
        for shell in detect() {
            if shell.id == "wsl" {
                assert!(shell.foreign_path_namespace);
            } else {
                assert!(
                    !shell.foreign_path_namespace,
                    "{} wrongly flagged",
                    shell.id
                );
            }
        }
    }
}
