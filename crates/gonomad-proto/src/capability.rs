//! The authorization vocabulary.
//!
//! Authentication (`ARCHITECTURE.md` §3.2) answers *who is connecting*.
//! Capabilities answer *what they may do*, and that is where most of the real
//! security lives: a paired phone is a credential to a developer's entire
//! workstation, so the default grant must be the smallest one that still makes
//! the product useful.
//!
//! Grants are stored server-side per device and are editable from the laptop.
//! Revoking one takes effect on the next request — there is no cached token
//! carrying a stale grant (§3.2).

use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};

/// A single permission a paired device may hold.
///
/// Deliberately coarse. Fine-grained permissions read as more secure but
/// produce grant sets nobody can reason about, and an authorization model a
/// user cannot understand is one they will over-grant to make something work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Capability {
    /// Read files inside an allowed workspace root.
    FsRead,
    /// Create, modify, delete, and move files inside an allowed workspace root.
    FsWrite,
    /// Read paths matching the secret denylist (`.ssh`, `.env`, credentials).
    ///
    /// Off by default and additionally gated on a hardware-backed biometric
    /// signature. The attack this exists to stop: a thief with an unlocked
    /// phone opening `~/.ssh/id_ed25519` and acquiring every server and
    /// repository the developer can reach (§3.6).
    FsSecrets,
    /// Open an interactive shell.
    ///
    /// **This transitively grants arbitrary code execution** — a shell can run
    /// anything. [`Capability::ExecArbitrary`] therefore governs only the
    /// structured `exec` API, not what a user can type into a terminal.
    /// GoNomad states this plainly rather than implying a boundary that does
    /// not exist; a device that must not execute code is denied `PtySpawn`.
    PtySpawn,
    /// Run commands matching the workspace's configured allowlist.
    ExecAllowlisted,
    /// Run arbitrary commands through the structured `exec` API.
    ExecArbitrary,
    /// Read git state: status, log, diff, blame.
    GitRead,
    /// Ordinary git mutations: commit, push, pull, branch, stash.
    GitWrite,
    /// History-rewriting git operations: force push, hard reset, rebase.
    ///
    /// Separated from [`Capability::GitWrite`] because these destroy work
    /// irrecoverably, and a phone is a poor place to confirm that intent.
    GitDangerous,
    /// Start and control AI agent sessions.
    AgentSpawn,
    /// Change security policy, pair new devices, and revoke existing ones.
    ///
    /// The privilege-escalation capability: a device holding this can grant
    /// itself anything else. Off by default and biometric-gated.
    PolicyWrite,
}

impl Capability {
    /// Every capability, in declaration order.
    pub const ALL: [Self; 11] = [
        Self::FsRead,
        Self::FsWrite,
        Self::FsSecrets,
        Self::PtySpawn,
        Self::ExecAllowlisted,
        Self::ExecArbitrary,
        Self::GitRead,
        Self::GitWrite,
        Self::GitDangerous,
        Self::AgentSpawn,
        Self::PolicyWrite,
    ];

    /// The grant a freshly paired device receives.
    ///
    /// Chosen as the smallest set that makes GoNomad useful on first run:
    /// browse and edit code, use a terminal, and use git — but no secrets, no
    /// history rewriting, and no ability to change its own permissions.
    pub const DEFAULT_GRANT: [Self; 7] = [
        Self::FsRead,
        Self::FsWrite,
        Self::PtySpawn,
        Self::ExecAllowlisted,
        Self::GitRead,
        Self::GitWrite,
        Self::AgentSpawn,
    ];

    /// The stable wire and configuration identifier, e.g. `"fs:read"`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FsRead => "fs:read",
            Self::FsWrite => "fs:write",
            Self::FsSecrets => "fs:secrets",
            Self::PtySpawn => "pty:spawn",
            Self::ExecAllowlisted => "exec:allowlisted",
            Self::ExecArbitrary => "exec:arbitrary",
            Self::GitRead => "git:read",
            Self::GitWrite => "git:write",
            Self::GitDangerous => "git:dangerous",
            Self::AgentSpawn => "agent:spawn",
            Self::PolicyWrite => "policy:write",
        }
    }

    /// Whether holding this capability requires a fresh hardware-backed
    /// biometric signature on **every** privileged use (§3.10).
    ///
    /// The realistic attack is not cryptographic — it is a habituated user
    /// tapping a green button while walking. Forcing a fingerprint breaks that
    /// habit loop exactly where the consequences are irreversible.
    #[must_use]
    pub const fn requires_presence(self) -> bool {
        matches!(
            self,
            Self::FsSecrets | Self::GitDangerous | Self::PolicyWrite | Self::ExecArbitrary
        )
    }

    /// Whether this capability is withheld from a newly paired device.
    #[must_use]
    pub fn is_off_by_default(self) -> bool {
        !Self::DEFAULT_GRANT.contains(&self)
    }

    /// A one-line description suitable for the pairing and policy screens.
    ///
    /// Written for a user deciding whether to grant it, not for a developer
    /// reading an API reference.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::FsRead => "Read files in your allowed project folders",
            Self::FsWrite => "Create, edit, and delete files in your allowed project folders",
            Self::FsSecrets => "Read secrets such as SSH keys and .env files",
            Self::PtySpawn => "Open terminals — this allows running any command",
            Self::ExecAllowlisted => "Run commands you have pre-approved for the project",
            Self::ExecArbitrary => "Run any command through the automation API",
            Self::GitRead => "View git status, history, and diffs",
            Self::GitWrite => "Commit, push, pull, and switch branches",
            Self::GitDangerous => "Force push and rewrite history — this can destroy work",
            Self::AgentSpawn => "Start and control AI coding agents",
            Self::PolicyWrite => "Change security settings and pair or remove devices",
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when a capability string is not recognised.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown capability: {0:?}")]
pub struct UnknownCapability(pub String);

impl FromStr for Capability {
    type Err = UnknownCapability;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|c| c.as_str() == s)
            .ok_or_else(|| UnknownCapability(s.to_owned()))
    }
}

/// A set of capabilities held by one device.
///
/// Backed by a bitmask rather than a `HashSet`: the set is checked on the hot
/// path of *every* request (`ARCHITECTURE.md` §2), so membership must be a
/// single bit test, and the whole grant must be cheap to copy.
#[derive(Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilitySet(u16);

impl CapabilitySet {
    /// An empty set — a device that may authenticate but do nothing.
    pub const EMPTY: Self = Self(0);

    /// The grant a freshly paired device receives.
    #[must_use]
    pub fn default_grant() -> Self {
        Self::from_iter(Capability::DEFAULT_GRANT)
    }

    /// Every capability. Intended for tests and for an explicit
    /// administrative grant, never as a default.
    #[must_use]
    pub fn all() -> Self {
        Self::from_iter(Capability::ALL)
    }

    #[allow(clippy::cast_possible_truncation)]
    const fn bit(cap: Capability) -> u16 {
        1u16 << (cap as u8)
    }

    /// Returns `true` when `cap` is held.
    #[must_use]
    pub const fn contains(self, cap: Capability) -> bool {
        self.0 & Self::bit(cap) != 0
    }

    /// Adds `cap`, returning the updated set.
    #[must_use]
    pub const fn with(self, cap: Capability) -> Self {
        Self(self.0 | Self::bit(cap))
    }

    /// Removes `cap`, returning the updated set.
    #[must_use]
    pub const fn without(self, cap: Capability) -> Self {
        Self(self.0 & !Self::bit(cap))
    }

    /// Adds `cap` in place.
    pub fn insert(&mut self, cap: Capability) {
        self.0 |= Self::bit(cap);
    }

    /// Removes `cap` in place.
    pub fn remove(&mut self, cap: Capability) {
        self.0 &= !Self::bit(cap);
    }

    /// Returns `true` when no capability is held.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The number of capabilities held.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// Iterates the held capabilities in declaration order.
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .into_iter()
            .filter(move |c| self.contains(*c))
    }

    /// Returns `true` when every capability in `other` is also held here.
    #[must_use]
    pub const fn contains_all(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns `true` when any held capability is presence-gated.
    #[must_use]
    pub fn requires_presence(self) -> bool {
        self.iter().any(Capability::requires_presence)
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        iter.into_iter().fold(Self::EMPTY, Self::with)
    }
}

impl fmt::Debug for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapabilitySet[")?;
        for (i, cap) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            f.write_str(cap.as_str())?;
        }
        f.write_str("]")
    }
}

impl fmt::Display for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let joined: Vec<&str> = self.iter().map(Capability::as_str).collect();
        f.write_str(&joined.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_contains_every_variant_exactly_once() {
        let mut sorted = Capability::ALL.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), Capability::ALL.len());
    }

    #[test]
    fn capability_set_fits_in_its_bitmask() {
        // A u16 backing store holds 16 capabilities. If ALL ever exceeds that,
        // `bit()` would silently shift out of range, so fail here instead.
        assert!(
            Capability::ALL.len() <= 16,
            "CapabilitySet's u16 backing store cannot hold {} capabilities",
            Capability::ALL.len()
        );
    }

    #[test]
    fn string_names_round_trip() {
        for cap in Capability::ALL {
            assert_eq!(cap.as_str().parse::<Capability>().unwrap(), cap);
        }
    }

    #[test]
    fn string_names_are_unique() {
        let mut names: Vec<&str> = Capability::ALL.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), Capability::ALL.len());
    }

    #[test]
    fn unknown_capability_names_are_rejected() {
        assert!("fs:sudo".parse::<Capability>().is_err());
        assert!("".parse::<Capability>().is_err());
        // Near-misses must not be silently accepted.
        assert!("fs:READ".parse::<Capability>().is_err());
        assert!("fsread".parse::<Capability>().is_err());
    }

    #[test]
    fn dangerous_capabilities_are_off_by_default() {
        for cap in [
            Capability::FsSecrets,
            Capability::GitDangerous,
            Capability::PolicyWrite,
            Capability::ExecArbitrary,
        ] {
            assert!(
                cap.is_off_by_default(),
                "{cap} must not be granted by default"
            );
        }
    }

    #[test]
    fn every_presence_gated_capability_is_off_by_default() {
        // A capability dangerous enough to need a fingerprint must never be
        // handed out automatically at pairing.
        for cap in Capability::ALL {
            if cap.requires_presence() {
                assert!(
                    cap.is_off_by_default(),
                    "{cap} is presence-gated but granted by default"
                );
            }
        }
    }

    #[test]
    fn default_grant_is_useful_but_bounded() {
        let g = CapabilitySet::default_grant();
        assert!(g.contains(Capability::FsRead));
        assert!(g.contains(Capability::FsWrite));
        assert!(g.contains(Capability::PtySpawn));
        assert!(g.contains(Capability::GitWrite));
        assert!(!g.contains(Capability::FsSecrets));
        assert!(!g.contains(Capability::GitDangerous));
        assert!(!g.contains(Capability::PolicyWrite));
    }

    #[test]
    fn set_operations_behave() {
        let mut set = CapabilitySet::EMPTY;
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);

        set.insert(Capability::FsRead);
        assert!(set.contains(Capability::FsRead));
        assert!(!set.contains(Capability::FsWrite));
        assert_eq!(set.len(), 1);

        // Inserting twice is idempotent.
        set.insert(Capability::FsRead);
        assert_eq!(set.len(), 1);

        set.remove(Capability::FsRead);
        assert!(set.is_empty());

        // Removing an absent capability is a no-op, not an error.
        set.remove(Capability::FsRead);
        assert!(set.is_empty());
    }

    #[test]
    fn every_capability_can_be_stored_and_retrieved() {
        // Guards against a `bit()` collision, which would silently grant one
        // capability when another was intended.
        for cap in Capability::ALL {
            let set = CapabilitySet::EMPTY.with(cap);
            assert!(set.contains(cap));
            assert_eq!(set.len(), 1, "{cap} collided with another capability's bit");
            for other in Capability::ALL {
                if other != cap {
                    assert!(!set.contains(other), "{cap} and {other} share a bit");
                }
            }
        }
    }

    #[test]
    fn contains_all_checks_subsets() {
        let full = CapabilitySet::all();
        let partial = CapabilitySet::default_grant();
        assert!(full.contains_all(partial));
        assert!(!partial.contains_all(full));
        assert!(partial.contains_all(partial));
        assert!(partial.contains_all(CapabilitySet::EMPTY));
    }

    #[test]
    fn iteration_yields_exactly_the_held_capabilities() {
        let set = CapabilitySet::from_iter([Capability::FsRead, Capability::GitWrite]);
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            vec![Capability::FsRead, Capability::GitWrite]
        );
    }

    #[test]
    fn default_is_empty_so_a_missing_grant_denies() {
        // If a grant fails to load, the fallback must be "no permissions",
        // never "all permissions".
        assert!(CapabilitySet::default().is_empty());
    }

    #[test]
    fn debug_lists_capability_names() {
        let set = CapabilitySet::from_iter([Capability::FsRead, Capability::PtySpawn]);
        assert_eq!(format!("{set:?}"), "CapabilitySet[fs:read, pty:spawn]");
    }

    #[test]
    fn every_capability_has_a_human_description() {
        for cap in Capability::ALL {
            let d = cap.description();
            assert!(!d.is_empty(), "{cap} has no description");
            // Descriptions are shown to users deciding whether to grant, so
            // they must not just restate the identifier.
            assert!(
                d.len() > cap.as_str().len(),
                "{cap}'s description is not informative"
            );
        }
    }

    #[test]
    fn serde_round_trips_through_cbor() {
        let set = CapabilitySet::default_grant();
        let mut buf = Vec::new();
        ciborium::into_writer(&set, &mut buf).unwrap();
        let back: CapabilitySet = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, set);
    }

    #[test]
    fn capability_serde_uses_snake_case_names() {
        let json = serde_json::to_string(&Capability::FsRead).unwrap();
        assert_eq!(json, "\"fs_read\"");
    }
}
