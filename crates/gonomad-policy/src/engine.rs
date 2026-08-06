//! The capability engine: grants, presence gating, and the composed check.
//!
//! # Fail closed, everywhere
//!
//! Every decision in this module has a default, and the default is *no*. A
//! grant that is missing, that failed to load from the database, that belongs
//! to a revoked device, or that is simply empty produces a denial — never an
//! allowance. This is stated three times in this file, asserted by tests, and
//! encoded in the types: [`check`] takes `Option<&DeviceGrant>` rather than
//! `&DeviceGrant`, so a caller that cannot find a grant has no way to express
//! that except by passing `None`, and `None` denies.
//!
//! The alternative — a caller unwrapping a missing grant into
//! `CapabilitySet::all()` "temporarily" — is not a hypothetical. It is what a
//! type that could not represent absence would invite.
//!
//! # Presence, and why the challenge is the operation
//!
//! Four capabilities require a fresh hardware-backed signature every time they
//! are used (`Capability::requires_presence`). The phone signs a challenge and
//! the daemon verifies it. What the challenge *is* determines whether the
//! scheme works at all.
//!
//! If it were a bare nonce, a compromised phone application could prompt the
//! user for a fingerprint on something innocuous, harvest the signature, and
//! spend it on `git push --force`. So the challenge is a digest of the exact
//! operation — the device, the method, and the arguments — and the daemon
//! verifies the signature *over the operation it is about to perform* (§3.10).
//! A signature for one operation is worthless for any other.
//!
//! Signature *verification* is not done here: keys and Ed25519 belong to the
//! session layer. This module decides which digest must have been signed, and
//! the caller asserts that it was, by passing [`Presence::Signed`].

use std::path::{Path, PathBuf};

use gonomad_proto::{Capability, CapabilitySet, DeviceId, Digest, ProtoError};
use serde::{Deserialize, Serialize};

use crate::denylist::SecretDenylist;
use crate::path_guard::{PathGuard, ResolvedPath};

/// Domain separation tag for presence challenges.
///
/// Prefixed so that a digest computed for a presence challenge can never
/// collide with a digest computed for a file's contents or for an audit
/// entry — which would let a value harvested from one context be replayed into
/// another.
const PRESENCE_DOMAIN: &[u8] = b"gonomad/presence/v1\x00";

/// What one paired device is permitted to do.
///
/// Loaded from the store on every request (`ARCHITECTURE.md` §3.2): there is no
/// cached token that could carry a stale grant, so a revocation takes effect on
/// the very next request rather than at some expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGrant {
    /// The device this grant belongs to.
    pub device_id: DeviceId,
    /// The capabilities granted.
    pub capabilities: CapabilitySet,
    /// Whether the grant has been revoked.
    ///
    /// Kept as a flag on the grant rather than as a deleted row so that a
    /// revoked device is still nameable in the audit log, and so that the code
    /// path for "revoked" is the same one as for "not granted".
    pub revoked: bool,
}

impl DeviceGrant {
    /// A live grant.
    #[must_use]
    pub const fn new(device_id: DeviceId, capabilities: CapabilitySet) -> Self {
        Self {
            device_id,
            capabilities,
            revoked: false,
        }
    }

    /// A grant with the capabilities a freshly paired device receives.
    #[must_use]
    pub fn newly_paired(device_id: DeviceId) -> Self {
        Self::new(device_id, CapabilitySet::default_grant())
    }

    /// Marks the grant revoked.
    #[must_use]
    pub const fn revoked(mut self) -> Self {
        self.revoked = true;
        self
    }

    /// The capabilities that actually apply right now.
    ///
    /// Empty for a revoked device. Every check goes through this rather than
    /// reading `capabilities` directly, so that forgetting to test `revoked` is
    /// not a thing a caller can do.
    #[must_use]
    pub fn effective_capabilities(&self) -> CapabilitySet {
        if self.revoked {
            CapabilitySet::EMPTY
        } else {
            self.capabilities
        }
    }
}

/// Whether the client has proven physical presence for this operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// No presence signature accompanied the request.
    Absent,

    /// A presence signature was supplied and **already verified** by the
    /// session layer, over this digest.
    ///
    /// The contract is precise, because getting it wrong silently disables the
    /// entire biometric gate: the caller must have checked an Ed25519 signature
    /// by the device's registered *presence* key over exactly these bytes,
    /// before constructing this value. This module then checks that those bytes
    /// are the digest of the operation about to be performed. Neither check is
    /// sufficient alone.
    Signed(Digest),
}

/// Derives the challenge a presence signature must cover.
///
/// Binds three things, each length-framed because
/// [`Digest::of_parts`][gonomad_proto::Digest::of_parts] concatenates without
/// separators — `("ab", "c")` and `("a", "bc")` would otherwise hash equal, and
/// two different operations that share a digest are two operations one
/// signature approves:
///
/// - the **device**, so a signature from one phone cannot be replayed by another;
/// - the **method**, so an approval for `fs.read` is not an approval for `fs.delete`;
/// - the **arguments**, so an approval to force-push `feature/x` is not an
///   approval to force-push `main`.
#[must_use]
pub fn operation_challenge(device_id: &DeviceId, method: &str, args_digest: &Digest) -> Digest {
    let method_len = u32::try_from(method.len())
        .unwrap_or(u32::MAX)
        .to_le_bytes();
    Digest::of_parts(&[
        PRESENCE_DOMAIN,
        device_id.as_bytes(),
        &method_len,
        method.as_bytes(),
        args_digest.as_bytes(),
    ])
}

/// Checks that a device holds a capability.
///
/// The single entry point for "may this device do this at all". Takes an
/// `Option` because the honest answer to "what is this unknown device's grant"
/// is *nothing*, and a type that cannot express that invites a caller to invent
/// something.
///
/// # Errors
///
/// [`gonomad_proto::ErrorKind::Denied`] naming `required`, when the grant is
/// absent, revoked, or does not include it. All three cases produce the
/// identical error: a client learns that it lacks the capability, not whether
/// its pairing still exists.
pub fn check(grant: Option<&DeviceGrant>, required: Capability) -> Result<(), ProtoError> {
    match grant {
        Some(grant) if grant.effective_capabilities().contains(required) => Ok(()),
        // Covers `None` (no grant loaded, unknown device, storage failure) and
        // a revoked or insufficient grant. Fail closed.
        _ => Err(ProtoError::denied(required)),
    }
}

/// Checks the presence requirement for a capability.
///
/// A no-op for capabilities that are not presence-gated, so callers can call it
/// unconditionally and cannot forget it for the ones that are.
///
/// # Errors
///
/// [`gonomad_proto::ErrorKind::PresenceRequired`] carrying `expected`, when the
/// capability needs a signature and either none was supplied or the one
/// supplied covers a different operation. The client prompts for a fingerprint,
/// signs the challenge it is handed, and sends a new request.
pub fn check_presence(
    required: Capability,
    expected: Digest,
    presence: Presence,
) -> Result<(), ProtoError> {
    if !required.requires_presence() {
        return Ok(());
    }
    match presence {
        // `Digest`'s equality is constant-time, so a near-miss cannot be walked
        // in byte by byte.
        Presence::Signed(signed) if signed == expected => Ok(()),
        // A signature for a *different* operation is treated exactly like no
        // signature at all: the harvest-and-redirect attack this exists to stop
        // must not get a distinguishable error to work with.
        Presence::Absent | Presence::Signed(_) => Err(ProtoError::presence_required(expected)),
    }
}

/// One authorization question, in full.
///
/// A struct rather than eight positional parameters because the parameters are
/// mostly the same two types, and a transposed `&str` in a security check is
/// the kind of bug that compiles.
#[derive(Debug, Clone, Copy)]
pub struct PathRequest<'a> {
    /// The requesting device's grant, or `None` if none could be loaded.
    pub grant: Option<&'a DeviceGrant>,
    /// The capability the operation needs — usually `FsRead` or `FsWrite`.
    pub capability: Capability,
    /// The path as the client asked for it, before any validation.
    pub path: &'a Path,
    /// The protocol method name, e.g. `"fs.read"`. Bound into the challenge.
    pub method: &'a str,
    /// A digest of the request's arguments. Bound into the challenge.
    pub args_digest: Digest,
    /// Any presence signature the client supplied.
    pub presence: Presence,
}

/// The composed policy decision for filesystem operations.
///
/// Holds the two stateless halves of the policy — the path guard and the
/// denylist — and runs them in the order `ARCHITECTURE.md` §2 step 5 lays down.
/// Rate limiting is deliberately *not* here: [`crate::rate_limit::RateLimiter`]
/// is mutable state owned by the router actor, while this engine is shared and
/// immutable. See the crate documentation for the ordering the router applies.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    guard: PathGuard,
    denylist: SecretDenylist,
}

impl PolicyEngine {
    /// Composes a guard and a denylist.
    #[must_use]
    pub const fn new(guard: PathGuard, denylist: SecretDenylist) -> Self {
        Self { guard, denylist }
    }

    /// The path guard.
    #[must_use]
    pub const fn guard(&self) -> &PathGuard {
        &self.guard
    }

    /// The secret denylist.
    #[must_use]
    pub const fn denylist(&self) -> &SecretDenylist {
        &self.denylist
    }

    /// Runs the whole authorization pipeline for a path operation.
    ///
    /// The order is not arbitrary, and each step is placed where it is for a
    /// reason that costs something to get wrong:
    ///
    /// 1. **Capability.** Cheapest, touches no disk, and leaks nothing about
    ///    the filesystem. A device without `fs:read` must not be able to learn
    ///    whether a file exists by observing which error it gets.
    /// 2. **Presence for that capability.** Before any I/O, so that a
    ///    presence-gated operation cannot be used as an existence oracle by a
    ///    client that never intends to supply a signature.
    /// 3. **Path guard.** Canonicalise and check containment.
    /// 4. **Denylist**, on the *canonical* path — the only form that cannot be
    ///    spelled around.
    /// 5. **Presence for `fs:secrets`**, if the denylist matched. Reading a
    ///    secret needs a fingerprint even from a device that holds the
    ///    capability (§3.10).
    ///
    /// # Errors
    ///
    /// `Denied`, `PresenceRequired`, `NotFound`, or `BadRequest`, per the steps
    /// above. Path failures collapse to `NotFound` so the engine cannot be used
    /// to map the filesystem.
    pub fn authorize_path(&self, request: &PathRequest<'_>) -> Result<ResolvedPath, ProtoError> {
        let challenge = request.grant.map_or_else(
            // No grant means the capability check below will deny anyway; the
            // placeholder challenge is never returned to anyone.
            || {
                operation_challenge(
                    &DeviceId::from_bytes([0u8; 32]),
                    request.method,
                    &request.args_digest,
                )
            },
            |g| operation_challenge(&g.device_id, request.method, &request.args_digest),
        );

        check(request.grant, request.capability)?;
        check_presence(request.capability, challenge, request.presence)?;

        let resolved = self.guard.resolve(request.path)?;

        if self.denylist.is_secret(resolved.path()) {
            check(request.grant, Capability::FsSecrets)?;
            check_presence(Capability::FsSecrets, challenge, request.presence)?;
        }

        Ok(resolved)
    }

    /// Filters a directory listing or a set of search results.
    ///
    /// Applies both halves: entries outside every root are dropped (a symlink
    /// in a listing can point anywhere), and secret entries are dropped for a
    /// device without `fs:secrets`. Filtering rather than erroring, so one
    /// gated file does not make a whole directory unlistable.
    #[must_use]
    pub fn filter_listing(
        &self,
        grant: Option<&DeviceGrant>,
        entries: Vec<PathBuf>,
    ) -> Vec<PathBuf> {
        let capabilities = grant.map_or(CapabilitySet::EMPTY, DeviceGrant::effective_capabilities);
        let within_roots: Vec<PathBuf> = entries
            .into_iter()
            .filter(|entry| {
                self.guard
                    .roots()
                    .iter()
                    .any(|root| PathGuard::is_within(root.canonical(), entry))
            })
            .collect();
        self.denylist.filter(capabilities, within_roots)
    }

    /// How many entries [`PolicyEngine::filter_listing`] would hide.
    #[must_use]
    pub fn hidden_count(&self, grant: Option<&DeviceGrant>, entries: &[PathBuf]) -> usize {
        let capabilities = grant.map_or(CapabilitySet::EMPTY, DeviceGrant::effective_capabilities);
        self.denylist.hidden_count(capabilities, entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use gonomad_proto::ErrorKind;
    use tempfile::TempDir;

    use crate::path_guard::WorkspaceRoot;

    fn device() -> DeviceId {
        DeviceId::from_bytes([7u8; 32])
    }

    fn other_device() -> DeviceId {
        DeviceId::from_bytes([8u8; 32])
    }

    struct Fixture {
        _dir: TempDir,
        root: PathBuf,
        engine: PolicyEngine,
    }

    fn fixture() -> Fixture {
        let dir = TempDir::new().unwrap();
        let base = dunce::canonicalize(dir.path()).unwrap();
        let root = base.join("proj");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::create_dir_all(root.join(".ssh")).unwrap();
        fs::write(root.join("src").join("main.rs"), b"fn main() {}").unwrap();
        fs::write(root.join(".ssh").join("id_ed25519"), b"KEY").unwrap();
        fs::write(root.join(".env"), b"TOKEN=1").unwrap();
        fs::write(root.join("README.md"), b"# hi").unwrap();

        let engine = PolicyEngine::new(
            PathGuard::new(vec![WorkspaceRoot::new(&root).unwrap()]),
            SecretDenylist::with_defaults(),
        );
        Fixture {
            _dir: dir,
            root,
            engine,
        }
    }

    fn request<'a>(
        grant: Option<&'a DeviceGrant>,
        capability: Capability,
        path: &'a Path,
        presence: Presence,
    ) -> PathRequest<'a> {
        PathRequest {
            grant,
            capability,
            path,
            method: "fs.read",
            args_digest: Digest::of(b"args"),
            presence,
        }
    }

    // -- fail closed ---------------------------------------------------------

    #[test]
    fn a_missing_grant_denies_every_capability() {
        for capability in Capability::ALL {
            let err = check(None, capability).unwrap_err();
            assert_eq!(
                err.kind,
                ErrorKind::Denied { capability },
                "{capability} was not denied for a missing grant"
            );
        }
    }

    #[test]
    fn an_empty_grant_denies_every_capability() {
        let grant = DeviceGrant::new(device(), CapabilitySet::EMPTY);
        for capability in Capability::ALL {
            assert!(
                check(Some(&grant), capability).is_err(),
                "{capability} was allowed by an empty grant"
            );
        }
    }

    #[test]
    fn a_revoked_grant_denies_everything_it_used_to_allow() {
        let grant = DeviceGrant::new(device(), CapabilitySet::all()).revoked();
        assert!(grant.effective_capabilities().is_empty());
        for capability in Capability::ALL {
            assert!(
                check(Some(&grant), capability).is_err(),
                "{capability} survived revocation"
            );
        }
    }

    #[test]
    fn revocation_is_indistinguishable_from_never_having_been_granted() {
        // Otherwise the error becomes an oracle for "is my pairing still alive",
        // which is information a device that has just been revoked should not
        // be handed.
        let revoked = DeviceGrant::new(device(), CapabilitySet::all()).revoked();
        assert_eq!(
            check(Some(&revoked), Capability::FsRead).unwrap_err(),
            check(None, Capability::FsRead).unwrap_err()
        );
    }

    #[test]
    fn a_granted_capability_is_allowed() {
        let grant = DeviceGrant::newly_paired(device());
        assert!(check(Some(&grant), Capability::FsRead).is_ok());
        assert!(check(Some(&grant), Capability::GitWrite).is_ok());
        // ...and the off-by-default ones still are not.
        assert!(check(Some(&grant), Capability::FsSecrets).is_err());
        assert!(check(Some(&grant), Capability::PolicyWrite).is_err());
    }

    // -- presence ------------------------------------------------------------

    #[test]
    fn capabilities_that_do_not_need_presence_pass_without_one() {
        let challenge = Digest::of(b"op");
        for capability in Capability::ALL {
            if !capability.requires_presence() {
                assert!(check_presence(capability, challenge, Presence::Absent).is_ok());
            }
        }
    }

    #[test]
    fn every_presence_gated_capability_demands_a_signature() {
        let challenge = Digest::of(b"op");
        for capability in Capability::ALL {
            if !capability.requires_presence() {
                continue;
            }
            let err = check_presence(capability, challenge, Presence::Absent).unwrap_err();
            assert_eq!(err.kind, ErrorKind::PresenceRequired { challenge });
        }
    }

    #[test]
    fn a_signature_for_another_operation_is_rejected() {
        // The whole point of §3.10: a compromised application prompts for a
        // fingerprint on something harmless and tries to spend the signature on
        // a force push.
        let harmless = operation_challenge(&device(), "fs.read", &Digest::of(b"README.md"));
        let destructive = operation_challenge(&device(), "git.push_force", &Digest::of(b"main"));
        assert_ne!(harmless, destructive);

        let err = check_presence(
            Capability::GitDangerous,
            destructive,
            Presence::Signed(harmless),
        )
        .unwrap_err();
        // And the error hands back the *correct* challenge, so an honest client
        // can simply re-prompt.
        assert_eq!(
            err.kind,
            ErrorKind::PresenceRequired {
                challenge: destructive
            }
        );
    }

    #[test]
    fn the_correct_signature_is_accepted() {
        let challenge = operation_challenge(&device(), "fs.read", &Digest::of(b"/p/.env"));
        assert!(check_presence(
            Capability::FsSecrets,
            challenge,
            Presence::Signed(challenge)
        )
        .is_ok());
    }

    #[test]
    fn the_challenge_binds_the_device() {
        let args = Digest::of(b"same args");
        assert_ne!(
            operation_challenge(&device(), "fs.read", &args),
            operation_challenge(&other_device(), "fs.read", &args)
        );
    }

    #[test]
    fn the_challenge_binds_the_method_and_the_arguments() {
        let args = Digest::of(b"x");
        assert_ne!(
            operation_challenge(&device(), "fs.read", &args),
            operation_challenge(&device(), "fs.write", &args)
        );
        assert_ne!(
            operation_challenge(&device(), "fs.read", &args),
            operation_challenge(&device(), "fs.read", &Digest::of(b"y"))
        );
    }

    #[test]
    fn the_challenge_is_unambiguously_framed() {
        // Without the length prefix on the method, ("ab", digest_of_c) and
        // ("a", digest_of_bc) could collide — two operations, one signature.
        let d = Digest::of(b"");
        assert_ne!(
            operation_challenge(&device(), "ab", &d),
            operation_challenge(&device(), "a", &d)
        );
        assert_ne!(
            operation_challenge(&device(), "fs.read", &d),
            operation_challenge(&device(), "fs.rea", &Digest::of(b"d"))
        );
    }

    #[test]
    fn the_challenge_is_deterministic() {
        // The phone computes it independently and signs it; if the two sides
        // disagreed, presence gating would fail permanently rather than
        // insecurely, but it would still be broken.
        let args = Digest::of(b"args");
        assert_eq!(
            operation_challenge(&device(), "fs.read", &args),
            operation_challenge(&device(), "fs.read", &args)
        );
    }

    // -- the composed pipeline ----------------------------------------------

    #[test]
    fn an_ordinary_read_inside_the_root_is_authorized() {
        let f = fixture();
        let grant = DeviceGrant::newly_paired(device());
        let path = f.root.join("src").join("main.rs");
        let resolved = f
            .engine
            .authorize_path(&request(
                Some(&grant),
                Capability::FsRead,
                &path,
                Presence::Absent,
            ))
            .unwrap();
        assert_eq!(resolved.path(), path);
    }

    #[test]
    fn the_capability_is_checked_before_the_filesystem_is_touched() {
        // A device without fs:read must get the same answer for a file that
        // exists and one that does not, or the denial is an existence oracle.
        let f = fixture();
        let grant = DeviceGrant::new(device(), CapabilitySet::EMPTY);
        let real = f.root.join("src").join("main.rs");
        let fake = f.root.join("does").join("not").join("exist");
        let a = f
            .engine
            .authorize_path(&request(
                Some(&grant),
                Capability::FsRead,
                &real,
                Presence::Absent,
            ))
            .unwrap_err();
        let b = f
            .engine
            .authorize_path(&request(
                Some(&grant),
                Capability::FsRead,
                &fake,
                Presence::Absent,
            ))
            .unwrap_err();
        assert_eq!(a, b);
        assert_eq!(a.kind.code(), "denied");
    }

    #[test]
    fn a_path_outside_the_root_is_not_found_even_with_every_capability() {
        let f = fixture();
        let grant = DeviceGrant::new(device(), CapabilitySet::all());
        let outside = f.root.parent().unwrap().join("elsewhere.txt");
        let err = f
            .engine
            .authorize_path(&request(
                Some(&grant),
                Capability::FsRead,
                &outside,
                Presence::Absent,
            ))
            .unwrap_err();
        assert_eq!(err.kind.code(), "not_found");
    }

    #[test]
    fn a_secret_inside_the_root_needs_fs_secrets() {
        let f = fixture();
        let grant = DeviceGrant::newly_paired(device());
        let key = f.root.join(".ssh").join("id_ed25519");
        let err = f
            .engine
            .authorize_path(&request(
                Some(&grant),
                Capability::FsRead,
                &key,
                Presence::Absent,
            ))
            .unwrap_err();
        assert_eq!(
            err.kind,
            ErrorKind::Denied {
                capability: Capability::FsSecrets
            }
        );
    }

    #[test]
    fn a_secret_needs_a_fingerprint_even_with_fs_secrets() {
        let f = fixture();
        let grant = DeviceGrant::new(
            device(),
            CapabilitySet::default_grant().with(Capability::FsSecrets),
        );
        let key = f.root.join(".ssh").join("id_ed25519");
        let err = f
            .engine
            .authorize_path(&request(
                Some(&grant),
                Capability::FsRead,
                &key,
                Presence::Absent,
            ))
            .unwrap_err();
        assert_eq!(err.kind.code(), "presence_required");

        // With the right signature, the read goes through.
        let challenge = operation_challenge(&device(), "fs.read", &Digest::of(b"args"));
        let resolved = f
            .engine
            .authorize_path(&request(
                Some(&grant),
                Capability::FsRead,
                &key,
                Presence::Signed(challenge),
            ))
            .unwrap();
        assert_eq!(resolved.path(), key);
    }

    #[test]
    fn the_secret_challenge_is_bound_to_this_exact_read() {
        let f = fixture();
        let grant = DeviceGrant::new(
            device(),
            CapabilitySet::default_grant().with(Capability::FsSecrets),
        );
        // A signature harvested from a read of README.md.
        let harvested = operation_challenge(&device(), "fs.read", &Digest::of(b"README.md"));
        let err = f
            .engine
            .authorize_path(&request(
                Some(&grant),
                Capability::FsRead,
                &f.root.join(".env"),
                Presence::Signed(harvested),
            ))
            .unwrap_err();
        assert_eq!(err.kind.code(), "presence_required");
    }

    #[test]
    fn a_non_secret_never_asks_for_a_fingerprint() {
        let f = fixture();
        let grant = DeviceGrant::new(
            device(),
            CapabilitySet::default_grant().with(Capability::FsSecrets),
        );
        assert!(f
            .engine
            .authorize_path(&request(
                Some(&grant),
                Capability::FsRead,
                &f.root.join("README.md"),
                Presence::Absent,
            ))
            .is_ok());
    }

    #[test]
    fn a_missing_grant_denies_the_whole_pipeline() {
        let f = fixture();
        let err = f
            .engine
            .authorize_path(&request(
                None,
                Capability::FsRead,
                &f.root.join("README.md"),
                Presence::Absent,
            ))
            .unwrap_err();
        assert_eq!(err.kind.code(), "denied");
    }

    #[test]
    fn a_write_outside_the_root_is_refused_even_though_the_parent_exists() {
        let f = fixture();
        let grant = DeviceGrant::new(device(), CapabilitySet::all());
        let target = f.root.parent().unwrap().join("planted.exe");
        assert!(f
            .engine
            .authorize_path(&request(
                Some(&grant),
                Capability::FsWrite,
                &target,
                Presence::Absent,
            ))
            .is_err());
    }

    // -- listings ------------------------------------------------------------

    #[test]
    fn listings_hide_secrets_and_anything_outside_the_roots() {
        let f = fixture();
        let grant = DeviceGrant::newly_paired(device());
        let entries = vec![
            f.root.join("README.md"),
            f.root.join(".env"),
            f.root.join(".ssh").join("id_ed25519"),
            f.root.parent().unwrap().join("escaped.txt"),
        ];
        let visible = f.engine.filter_listing(Some(&grant), entries.clone());
        assert_eq!(visible, vec![f.root.join("README.md")]);
        assert_eq!(f.engine.hidden_count(Some(&grant), &entries), 2);
    }

    #[test]
    fn a_device_with_fs_secrets_sees_the_secrets_in_a_listing() {
        let f = fixture();
        let grant = DeviceGrant::new(
            device(),
            CapabilitySet::default_grant().with(Capability::FsSecrets),
        );
        let entries = vec![f.root.join("README.md"), f.root.join(".env")];
        assert_eq!(f.engine.filter_listing(Some(&grant), entries).len(), 2);
    }

    #[test]
    fn a_listing_for_a_missing_grant_is_empty() {
        let f = fixture();
        let entries = vec![f.root.join("README.md"), f.root.join(".env")];
        // fs:read is checked separately by the caller; what this asserts is
        // that the secret filter treats "no grant" as "no fs:secrets".
        assert_eq!(
            f.engine.filter_listing(None, entries),
            vec![f.root.join("README.md")]
        );
    }

    #[test]
    fn a_revoked_device_sees_nothing_secret_in_a_listing() {
        let f = fixture();
        let grant = DeviceGrant::new(device(), CapabilitySet::all()).revoked();
        let entries = vec![f.root.join("README.md"), f.root.join(".env")];
        assert_eq!(
            f.engine.filter_listing(Some(&grant), entries),
            vec![f.root.join("README.md")]
        );
    }

    // -- serde ---------------------------------------------------------------

    #[test]
    fn a_grant_round_trips_through_cbor() {
        let grant = DeviceGrant::newly_paired(device());
        let mut buf = Vec::new();
        ciborium::into_writer(&grant, &mut buf).unwrap();
        let back: DeviceGrant = ciborium::from_reader(buf.as_slice()).unwrap();
        assert_eq!(back, grant);
    }
}
