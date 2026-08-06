//! The secret denylist (`ARCHITECTURE.md` §3.6).
//!
//! # The attack
//!
//! A thief picks up an unlocked phone, opens GoNomad's file tree, taps
//! `~/.ssh/id_ed25519`, and now holds every server and every repository the
//! developer can reach. Nothing else in this crate stops that: the key *is*
//! inside a workspace root if the developer's home directory is a root, the
//! device *does* hold `fs:read`, and the request is well within its rate
//! budget. The denylist plus the biometric gate is the control that makes it
//! fail.
//!
//! # Where it sits
//!
//! **After** the path guard, never before. Matching against a path the guard
//! has already canonicalised means the denylist sees the real path, not the one
//! the client wrote — so `~/.ssh/../.ssh/id_rsa`, `~/link-to-ssh/id_rsa`, and
//! `~/.SSH/ID_RSA` on a case-insensitive volume all match the same rule.
//! A denylist applied to raw input is a denylist with a bypass for every
//! spelling of the same file.
//!
//! # And on listings, not just reads
//!
//! Filenames leak. `id_rsa`, `prod.env`, `aws-root.pem` — the existence and the
//! name are often most of the secret. So [`SecretDenylist::filter`] is applied
//! to directory listings and search results too, and a device without
//! `fs:secrets` does not learn that the file is there at all.

use std::path::{Path, PathBuf};

use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use gonomad_proto::{Capability, CapabilitySet, ProtoError};
use serde::{Deserialize, Serialize};

/// The patterns applied unless the user changes them.
///
/// Taken verbatim from the table in `ARCHITECTURE.md` §3.6, with one addition:
/// for every `X/**` rule there is also a bare `X` rule. Without it the
/// directory `.ssh` is itself listable — and "there is a `.ssh` here with four
/// entries in it" is already an answer an attacker wanted.
pub const DEFAULT_PATTERNS: &[&str] = &[
    // SSH: the highest-value target on any developer machine.
    "**/.ssh",
    "**/.ssh/**",
    "**/id_rsa*",
    "**/id_ed25519*",
    // Cloud provider credentials.
    "**/.aws",
    "**/.aws/**",
    "**/.kube/config",
    "**/.config/gcloud",
    "**/.config/gcloud/**",
    // Application secrets.
    "**/.env*",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    // Package registry and network credentials.
    "**/.netrc",
    "**/.npmrc",
    "**/.pypirc",
    "**/.docker/config.json",
    "**/.git-credentials",
    // Signing keys.
    "**/.gnupg",
    "**/.gnupg/**",
    // AI tool configuration, which routinely holds provider API keys.
    "**/.claude",
    "**/.claude/**",
    "**/.cursor",
    "**/.cursor/**",
];

/// A pattern that could not be compiled.
#[derive(Debug, thiserror::Error)]
#[error("invalid denylist pattern {pattern:?}: {source}")]
pub struct InvalidPattern {
    /// The pattern as written.
    pub pattern: String,
    /// Why `globset` rejected it.
    #[source]
    pub source: globset::Error,
}

/// User configuration for the denylist.
///
/// Serde-derived because it comes straight from the daemon's TOML config
/// (`ARCHITECTURE.md` §5.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DenylistConfig {
    /// Additional patterns to treat as secret.
    ///
    /// Extending is the safe direction and is silent.
    pub extra: Vec<String>,

    /// Default patterns to switch off.
    ///
    /// Narrowing is the unsafe direction and is never silent — see
    /// [`SecretDenylist::warnings`]. A user with a legitimate reason (a project
    /// full of test fixtures named `*.key`) should be able to do it; they
    /// should not be able to do it by accident, and the laptop-side security
    /// screen shows the warning.
    pub remove_defaults: Vec<String>,
}

/// Compiled secret patterns.
#[derive(Debug, Clone)]
pub struct SecretDenylist {
    set: GlobSet,
    patterns: Vec<String>,
    warnings: Vec<String>,
}

impl SecretDenylist {
    /// Compiles [`DEFAULT_PATTERNS`].
    ///
    /// # Panics
    ///
    /// Never in practice: the default patterns are compiled by a test in this
    /// module, so a malformed one cannot reach a release.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::from_config(&DenylistConfig::default())
            .expect("DEFAULT_PATTERNS are valid; guarded by a unit test")
    }

    /// Compiles the defaults as modified by `config`.
    ///
    /// # Errors
    ///
    /// [`InvalidPattern`] when a user-supplied pattern does not compile. The
    /// caller must treat this as fatal and refuse to start: running with a
    /// partially applied denylist is worse than not running.
    pub fn from_config(config: &DenylistConfig) -> Result<Self, InvalidPattern> {
        let mut warnings = Vec::new();
        let mut patterns: Vec<String> = Vec::new();

        for default in DEFAULT_PATTERNS {
            if config.remove_defaults.iter().any(|r| r == default) {
                warnings.push(format!(
                    "secret denylist narrowed: default pattern {default:?} disabled — files \
                     matching it are now readable by any device holding fs:read"
                ));
                tracing::warn!(pattern = default, "secret denylist narrowed");
                continue;
            }
            patterns.push((*default).to_owned());
        }

        for removal in &config.remove_defaults {
            if !DEFAULT_PATTERNS.contains(&removal.as_str()) {
                // Almost always a typo, and a typo here silently leaves the
                // pattern the user meant to remove in force — or, worse, makes
                // them believe they removed something they did not.
                warnings.push(format!(
                    "secret denylist: {removal:?} is not a default pattern, nothing was removed"
                ));
                tracing::warn!(pattern = %removal, "unknown default pattern in remove_defaults");
            }
        }

        patterns.extend(config.extra.iter().cloned());

        let mut builder = GlobSetBuilder::new();
        for pattern in &patterns {
            builder.add(compile(pattern)?);
        }
        let set = builder.build().map_err(|source| InvalidPattern {
            pattern: "<denylist>".to_owned(),
            source,
        })?;

        Ok(Self {
            set,
            patterns,
            warnings,
        })
    }

    /// The compiled patterns, in match order.
    #[must_use]
    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    /// Warnings raised while building, for the laptop's security screen.
    ///
    /// Non-empty means the user has weakened the default protection. The daemon
    /// surfaces these at startup and on the security screen rather than only
    /// writing them to a log nobody reads.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Whether `path` is considered a secret.
    #[must_use]
    pub fn is_secret(&self, path: &Path) -> bool {
        self.set.is_match(normalise(path))
    }

    /// The first pattern `path` matches, for the audit log and the UI's
    /// explanation of *why* a file is gated.
    #[must_use]
    pub fn matched_pattern(&self, path: &Path) -> Option<&str> {
        self.set
            .matches(normalise(path))
            .first()
            .and_then(|i| self.patterns.get(*i))
            .map(String::as_str)
    }

    /// Enforces the denylist for a single path.
    ///
    /// # Errors
    ///
    /// [`gonomad_proto::ErrorKind::Denied`] naming [`Capability::FsSecrets`]
    /// when the path is a secret and the device does not hold that capability.
    ///
    /// A device that *does* hold it is not finished: `fs:secrets` is
    /// presence-gated, so the caller must also clear
    /// [`crate::engine::check_presence`] (§3.10). Holding the capability is
    /// permission to ask; the fingerprint is permission to proceed.
    pub fn check(&self, path: &Path, capabilities: CapabilitySet) -> Result<(), ProtoError> {
        if self.is_secret(path) && !capabilities.contains(Capability::FsSecrets) {
            return Err(ProtoError::denied(Capability::FsSecrets));
        }
        Ok(())
    }

    /// Removes secret paths from a listing or a set of search results.
    ///
    /// Filtering rather than failing: a directory containing one `.env` should
    /// still list its other forty files. The `.env` simply is not among them,
    /// and the device learns nothing about it — not its name, not its size, not
    /// that it exists.
    pub fn filter<I>(&self, capabilities: CapabilitySet, entries: I) -> Vec<PathBuf>
    where
        I: IntoIterator<Item = PathBuf>,
    {
        if capabilities.contains(Capability::FsSecrets) {
            return entries.into_iter().collect();
        }
        entries
            .into_iter()
            .filter(|path| !self.is_secret(path))
            .collect()
    }

    /// How many entries [`SecretDenylist::filter`] would remove.
    ///
    /// The UI shows "3 items hidden by your security policy" rather than
    /// silently short-listing, so that a missing file is never mysterious.
    /// The count leaks only a number, never a name.
    #[must_use]
    pub fn hidden_count(&self, capabilities: CapabilitySet, entries: &[PathBuf]) -> usize {
        if capabilities.contains(Capability::FsSecrets) {
            return 0;
        }
        entries.iter().filter(|p| self.is_secret(p)).count()
    }
}

impl Default for SecretDenylist {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Compiles one pattern.
///
/// Two settings matter, and both are chosen in the strict direction:
///
/// - `literal_separator(true)` so that `*` stops at a directory boundary.
///   Without it `**/.env*` and `*` behave interchangeably and the patterns stop
///   meaning what they read as.
/// - `case_insensitive(true)` on **every** platform. On Windows and macOS this
///   is simply correct, because `.SSH` and `.ssh` are the same directory.
///   On Linux they are not, so this deliberately over-matches: a file genuinely
///   named `ID_RSA.BACKUP` gets gated when it need not have been. That is the
///   right way to be wrong. The failure mode of under-matching is handing out a
///   private key; the failure mode of over-matching is a fingerprint prompt.
fn compile(pattern: &str) -> Result<Glob, InvalidPattern> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .case_insensitive(true)
        .build()
        .map_err(|source| InvalidPattern {
            pattern: pattern.to_owned(),
            source,
        })
}

/// Renders a path for matching, with `/` as the separator.
///
/// `globset` matches on `/` only, so Windows paths must be translated or every
/// pattern silently matches nothing — a denylist that is on paper and off in
/// practice. Backslashes inside a *Unix* filename (legal, if strange) are
/// translated too, which can only cause a path to match more patterns, never
/// fewer.
fn normalise(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps_without_secrets() -> CapabilitySet {
        CapabilitySet::default_grant()
    }

    fn caps_with_secrets() -> CapabilitySet {
        CapabilitySet::default_grant().with(Capability::FsSecrets)
    }

    #[test]
    fn the_default_patterns_all_compile() {
        // This test is what makes `with_defaults`'s `expect` honest.
        for pattern in DEFAULT_PATTERNS {
            compile(pattern).unwrap_or_else(|e| panic!("{pattern}: {e}"));
        }
        assert!(!SecretDenylist::with_defaults().patterns().is_empty());
    }

    #[test]
    fn every_documented_secret_is_matched() {
        let d = SecretDenylist::with_defaults();
        for path in [
            "/home/dev/.ssh/id_ed25519",
            "/home/dev/.ssh/config",
            "/home/dev/.ssh",
            "/home/dev/projects/app/.env",
            "/home/dev/projects/app/.env.production",
            "/home/dev/projects/app/.env.local",
            "/home/dev/certs/server.pem",
            "/home/dev/certs/server.key",
            "/home/dev/certs/bundle.p12",
            "/home/dev/backup/id_rsa",
            "/home/dev/backup/id_rsa.pub",
            "/home/dev/backup/id_ed25519.old",
            "/home/dev/.aws/credentials",
            "/home/dev/.aws",
            "/home/dev/.git-credentials",
            "/home/dev/.gnupg/secring.gpg",
            "/home/dev/.gnupg",
            "/home/dev/.config/gcloud/credentials.db",
            "/home/dev/.claude/settings.json",
            "/home/dev/.cursor/mcp.json",
            "/home/dev/.kube/config",
            "/home/dev/.netrc",
            "/home/dev/.npmrc",
            "/home/dev/.pypirc",
            "/home/dev/.docker/config.json",
        ] {
            assert!(d.is_secret(Path::new(path)), "{path} was not gated");
        }
    }

    #[test]
    fn ordinary_project_files_are_not_gated() {
        let d = SecretDenylist::with_defaults();
        for path in [
            "/home/dev/projects/app/src/main.rs",
            "/home/dev/projects/app/README.md",
            "/home/dev/projects/app/Cargo.toml",
            "/home/dev/projects/app/env.example",
            "/home/dev/projects/app/docs/environment.md",
            "/home/dev/projects/app/src/keyboard.rs",
            "/home/dev/projects/app/.gitignore",
        ] {
            assert!(!d.is_secret(Path::new(path)), "{path} was wrongly gated");
        }
    }

    #[test]
    fn windows_paths_match_despite_backslashes() {
        // The bug this guards against is total: without separator translation
        // no pattern matches any Windows path, and the denylist is decorative.
        let d = SecretDenylist::with_defaults();
        assert!(d.is_secret(Path::new(r"C:\Users\dev\.ssh\id_ed25519")));
        assert!(d.is_secret(Path::new(r"C:\Users\dev\proj\.env")));
        assert!(!d.is_secret(Path::new(r"C:\Users\dev\proj\src\main.rs")));
    }

    #[test]
    fn matching_is_case_insensitive_on_every_platform() {
        let d = SecretDenylist::with_defaults();
        assert!(d.is_secret(Path::new("/home/dev/.SSH/ID_RSA")));
        assert!(d.is_secret(Path::new(r"C:\Users\dev\.Ssh\Id_Ed25519")));
        assert!(d.is_secret(Path::new("/home/dev/CERT.PEM")));
    }

    #[test]
    fn a_denylist_hit_requires_fs_secrets() {
        let d = SecretDenylist::with_defaults();
        let key = Path::new("/home/dev/.ssh/id_ed25519");

        let err = d.check(key, caps_without_secrets()).unwrap_err();
        match err.kind {
            gonomad_proto::ErrorKind::Denied { capability } => {
                assert_eq!(capability, Capability::FsSecrets);
            }
            other => panic!("expected Denied, got {other:?}"),
        }

        assert!(d.check(key, caps_with_secrets()).is_ok());
    }

    #[test]
    fn a_non_secret_needs_nothing_extra() {
        let d = SecretDenylist::with_defaults();
        assert!(d
            .check(
                Path::new("/home/dev/proj/src/main.rs"),
                CapabilitySet::EMPTY
            )
            .is_ok());
    }

    #[test]
    fn listings_hide_secrets_from_a_device_without_the_capability() {
        let d = SecretDenylist::with_defaults();
        let entries: Vec<PathBuf> = [
            "/home/dev/proj/src/main.rs",
            "/home/dev/proj/.env",
            "/home/dev/proj/README.md",
            "/home/dev/proj/server.pem",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();

        let visible = d.filter(caps_without_secrets(), entries.clone());
        assert_eq!(visible.len(), 2);
        // Not merely absent from the content: absent from the *names*, because
        // "there is a server.pem here" is itself the leak.
        assert!(!visible
            .iter()
            .any(|p| p.to_string_lossy().contains(".env") || p.to_string_lossy().contains(".pem")));
        assert_eq!(d.hidden_count(caps_without_secrets(), &entries), 2);

        let all = d.filter(caps_with_secrets(), entries.clone());
        assert_eq!(all.len(), 4);
        assert_eq!(d.hidden_count(caps_with_secrets(), &entries), 0);
    }

    #[test]
    fn search_results_are_filtered_by_the_same_call() {
        // Grep output is a filename leak with extra steps: matching a line in
        // `.env` reveals both the file and part of its contents.
        let d = SecretDenylist::with_defaults();
        let hits: Vec<PathBuf> = ["/p/.env", "/p/src/a.rs", "/p/.ssh/known_hosts"]
            .iter()
            .map(PathBuf::from)
            .collect();
        assert_eq!(
            d.filter(caps_without_secrets(), hits),
            vec![PathBuf::from("/p/src/a.rs")]
        );
    }

    #[test]
    fn extending_the_list_is_silent() {
        let d = SecretDenylist::from_config(&DenylistConfig {
            extra: vec!["**/*.secret".to_owned(), "**/vault/**".to_owned()],
            remove_defaults: Vec::new(),
        })
        .unwrap();
        assert!(d.warnings().is_empty());
        assert!(d.is_secret(Path::new("/p/tokens.secret")));
        assert!(d.is_secret(Path::new("/p/vault/prod")));
        // And the defaults are still in force.
        assert!(d.is_secret(Path::new("/p/.env")));
    }

    #[test]
    fn narrowing_the_list_warns() {
        let d = SecretDenylist::from_config(&DenylistConfig {
            extra: Vec::new(),
            remove_defaults: vec!["**/*.key".to_owned()],
        })
        .unwrap();
        assert_eq!(d.warnings().len(), 1);
        assert!(d.warnings()[0].contains("narrowed"));
        assert!(!d.is_secret(Path::new("/p/test-fixtures/sample.key")));
        // Narrowing one pattern must not disturb any other.
        assert!(d.is_secret(Path::new("/p/.ssh/id_rsa")));
        assert!(d.is_secret(Path::new("/p/cert.pem")));
    }

    #[test]
    fn removing_a_pattern_that_is_not_a_default_warns_about_the_typo() {
        let d = SecretDenylist::from_config(&DenylistConfig {
            extra: Vec::new(),
            remove_defaults: vec!["**/.shh/**".to_owned()],
        })
        .unwrap();
        assert_eq!(d.warnings().len(), 1);
        assert!(d.warnings()[0].contains("nothing was removed"));
        // The pattern they meant is untouched.
        assert!(d.is_secret(Path::new("/p/.ssh/id_rsa")));
    }

    #[test]
    fn an_invalid_pattern_is_fatal_rather_than_ignored() {
        // Silently dropping it would produce a daemon that believes it is
        // protecting a path it is not.
        let err = SecretDenylist::from_config(&DenylistConfig {
            extra: vec!["**/[".to_owned()],
            remove_defaults: Vec::new(),
        })
        .unwrap_err();
        assert_eq!(err.pattern, "**/[");
    }

    #[test]
    fn the_matched_pattern_is_reported_for_the_audit_log() {
        let d = SecretDenylist::with_defaults();
        // The directory itself matches the bare rule; a file inside it matches
        // the recursive one. Both are reported precisely, so the audit entry
        // and the UI can say which rule gated the file.
        assert_eq!(
            d.matched_pattern(Path::new("/home/dev/.ssh")),
            Some("**/.ssh")
        );
        assert_eq!(
            d.matched_pattern(Path::new("/home/dev/.ssh/id_ed25519")),
            Some("**/.ssh/**")
        );
        assert_eq!(d.matched_pattern(Path::new("/home/dev/src/main.rs")), None);
    }

    #[test]
    fn a_directory_separator_is_not_matched_by_a_single_star() {
        // `literal_separator(true)`. Without it these patterns would match far
        // more than they read as, which is how a denylist quietly becomes an
        // allowlist of two files.
        let d = SecretDenylist::from_config(&DenylistConfig {
            extra: vec!["/p/*.txt".to_owned()],
            remove_defaults: Vec::new(),
        })
        .unwrap();
        assert!(d.is_secret(Path::new("/p/a.txt")));
        assert!(!d.is_secret(Path::new("/p/sub/a.txt")));
    }

    #[test]
    fn config_round_trips_through_json() {
        let config = DenylistConfig {
            extra: vec!["**/*.secret".to_owned()],
            remove_defaults: vec!["**/*.key".to_owned()],
        };
        let text = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serde_json::from_str::<DenylistConfig>(&text).unwrap(),
            config
        );
    }
}
