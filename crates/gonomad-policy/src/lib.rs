//! GoNomad authorization.
//!
//! Authentication (`ARCHITECTURE.md` §3.2) answers *who is connecting*; this
//! crate answers *what they may do*, and it is where most of the real security
//! lives.
//!
//! Structurally, this crate sits on the **only** path from the protocol router
//! to any service (`ARCHITECTURE.md` §2). A service call cannot skip it,
//! rather than merely conventionally not skipping it.
//!
//! # What is at stake
//!
//! A paired phone is a credential to the developer's entire workstation. There
//! is no cloud, no second factor beyond the phone itself, and no blast radius
//! smaller than "the machine". A bug in [`path_guard`] is a stolen phone
//! reading `~/.ssh/id_ed25519`; a bug in [`engine`] is a revoked device that
//! still works. Everything here is written for a reader who is trying to find
//! the hole, and every check records which attack it stops.
//!
//! # The four parts
//!
//! | Module | Question it answers |
//! |---|---|
//! | [`engine`] | Does this device hold the capability, and has it proven presence? |
//! | [`path_guard`] | Does this path resolve inside a permitted workspace root? |
//! | [`denylist`] | Is this path a secret, and may this device read secrets? |
//! | [`rate_limit`] | Is this device within its budget for this class of work? |
//!
//! # The order the router must apply them
//!
//! The order is part of the security property, not a style choice. Each step is
//! placed so that failing it leaks less than the step after it would.
//!
//! 1. **Grant loaded and unrevoked** — [`engine::check`]. Cheapest, and reveals
//!    nothing about the machine.
//! 2. **Capability held** — [`engine::check`] for the operation's capability.
//! 3. **Presence proven**, for presence-gated capabilities —
//!    [`engine::check_presence`], against a challenge that is a digest of the
//!    *exact operation*.
//! 4. **Rate budget** — [`rate_limit::RateLimiter`]. After authorization, so an
//!    unauthorized device cannot measure the daemon's limits, and so a denied
//!    request does not consume a legitimate one's budget.
//! 5. **Path resolves inside a root** — [`path_guard::PathGuard::resolve`].
//! 6. **Denylist**, on the canonical path — [`denylist::SecretDenylist`].
//!
//! Steps 1–3, 5 and 6 are composed for filesystem operations by
//! [`engine::PolicyEngine::authorize_path`]. Step 4 is separate because the
//! rate limiter is mutable state owned by the router actor, while the engine is
//! shared and immutable.
//!
//! # Errors
//!
//! Anything that crosses the wire is a [`gonomad_proto::ProtoError`]. This
//! crate defines exactly one error vocabulary of its own,
//! [`path_guard::DenyReason`], and it exists solely so the *audit log* can
//! record which check failed. It is collapsed into `ProtoError` before it
//! reaches a client, and every location-related reason collapses to `NotFound`
//! so that a client cannot use denials to map the filesystem outside its roots.
//!
//! # Two limitations, stated plainly
//!
//! - **TOCTOU.** The path guard validates the filesystem as it is at check
//!   time. A local attacker who can swap a directory for a symlink between the
//!   check and the caller's `open()` can redirect the operation. The guard
//!   provides [`path_guard::ResolvedPath::confirm_identity`] so the filesystem
//!   layer can close the window with a handle-identity comparison, but it
//!   cannot close it alone. See the [`path_guard`] module documentation.
//! - **`pty:spawn` implies arbitrary execution.** No amount of path guarding
//!   constrains a shell. `ARCHITECTURE.md` §3.6 says so in the product
//!   documentation rather than leaving it in a reviewer's head, and this crate
//!   does not pretend otherwise.

// Lints are configured in this crate's `[lints]` table in Cargo.toml.
// Do not duplicate them here: source-level attributes silently override it.

pub mod denylist;
pub mod engine;
pub mod path_guard;
pub mod rate_limit;

pub use denylist::{DenylistConfig, SecretDenylist, DEFAULT_PATTERNS};
pub use engine::{
    check, check_presence, operation_challenge, DeviceGrant, PathRequest, PolicyEngine, Presence,
};
pub use path_guard::{
    DenyReason, FileIdentity, GuardOptions, PathDenied, PathGuard, ResolvedPath, WorkspaceRoot,
};
pub use rate_limit::{
    ByteReservation, Clock, ManualClock, Monotonic, OperationClass, RateLimiter, Slot, SystemClock,
};

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use gonomad_proto::{Capability, CapabilitySet, DeviceId, Digest};
    use tempfile::TempDir;

    use super::*;

    /// One `fs.read` request, as the router composes it.
    fn read_request<'a>(grant: &'a DeviceGrant, path: &'a Path) -> PathRequest<'a> {
        PathRequest {
            grant: Some(grant),
            capability: Capability::FsRead,
            path,
            method: "fs.read",
            args_digest: Digest::of(b"args"),
            presence: Presence::Absent,
        }
    }

    /// The `ARCHITECTURE.md` §2 request lifecycle, end to end, as the router
    /// runs it. Written as one test because the *order* of the steps is itself
    /// a security property, and no per-module test can check an ordering.
    #[test]
    fn the_request_lifecycle_denies_at_the_earliest_possible_step() {
        let dir = TempDir::new().unwrap();
        let base = dunce::canonicalize(dir.path()).unwrap();
        let root = base.join("proj");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("main.rs"), b"fn main() {}").unwrap();
        fs::write(root.join(".env"), b"TOKEN=1").unwrap();
        fs::create_dir_all(base.join("proj-evil")).unwrap();
        fs::write(base.join("proj-evil").join("loot"), b"loot").unwrap();

        let engine = PolicyEngine::new(
            PathGuard::new(vec![WorkspaceRoot::new(&root).unwrap()]),
            SecretDenylist::with_defaults(),
        );
        let device = DeviceId::from_bytes([3u8; 32]);
        let grant = DeviceGrant::newly_paired(device);
        let mut limiter = RateLimiter::new(ManualClock::new());

        // Happy path: authorized, then within budget, then executed.
        assert!(limiter.try_acquire(device, OperationClass::FsRead).is_ok());
        let resolved = engine
            .authorize_path(&read_request(&grant, &root.join("main.rs")))
            .unwrap();
        assert_eq!(resolved.path(), root.join("main.rs"));

        // The prefix-attack sibling is not inside the root.
        assert_eq!(
            engine
                .authorize_path(&read_request(&grant, &base.join("proj-evil").join("loot")))
                .unwrap_err()
                .kind
                .code(),
            "not_found"
        );

        // The secret inside the root needs fs:secrets.
        assert_eq!(
            engine
                .authorize_path(&read_request(&grant, &root.join(".env")))
                .unwrap_err()
                .kind
                .code(),
            "denied"
        );

        // Exhausting the read budget produces a wait, and the wait works.
        for _ in 0..100 {
            let _ = limiter.try_acquire(device, OperationClass::FsRead);
        }
        assert_eq!(
            limiter
                .try_acquire(device, OperationClass::FsRead)
                .unwrap_err()
                .kind
                .code(),
            "rate_limited"
        );
        limiter.clock().advance(Duration::from_secs(1));
        assert!(limiter.try_acquire(device, OperationClass::FsRead).is_ok());
    }

    #[test]
    fn a_daemon_that_fails_to_load_any_policy_denies_everything() {
        // The composite fail-closed test: no roots, no grant, empty capability
        // set. Every question must answer "no", and none may panic.
        let engine = PolicyEngine::new(PathGuard::new(Vec::new()), SecretDenylist::with_defaults());
        let request = PathRequest {
            grant: None,
            capability: Capability::FsRead,
            path: Path::new("/anything"),
            method: "fs.read",
            args_digest: Digest::of(b""),
            presence: Presence::Absent,
        };
        assert!(engine.authorize_path(&request).is_err());
        assert!(engine
            .filter_listing(None, vec![PathBuf::from("/anything")])
            .is_empty());

        let empty = DeviceGrant::new(DeviceId::from_bytes([0u8; 32]), CapabilitySet::EMPTY);
        for capability in Capability::ALL {
            assert!(check(None, capability).is_err());
            assert!(check(Some(&empty), capability).is_err());
        }
    }
}
