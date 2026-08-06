//! Filesystem service: directory listing and file reads.
//!
//! Every path arriving here is attacker-influenced — it comes from a phone that
//! may be lost, stolen, or compromised — so **nothing in this module touches the
//! disk before `gonomad-policy` has approved the path.** That ordering is the
//! security property; the code is arranged so that skipping the check would
//! require deleting a line rather than forgetting one.
//!
//! # Scope of this slice
//!
//! Read-only. Compare-and-swap writes, upload/download, search, and the FST path
//! index (`ARCHITECTURE.md` §12) land with M3. What exists here is what the
//! mobile app needs to browse a project and open a file.

use std::path::{Path, PathBuf};

use gonomad_policy::{DeviceGrant, PathRequest, PolicyEngine, Presence};
use gonomad_proto::{Capability, Digest, ProtoError};
use serde::{Deserialize, Serialize};

/// Largest file this slice will send in one response.
///
/// Well under the 32 MiB protocol frame ceiling: a phone cannot usefully render
/// a megabyte of text at once, and windowed reads (§12.5) are the real answer for
/// large files. Sending less and saying so beats sending everything and stalling.
pub const MAX_READ_BYTES: usize = 512 * 1024;

/// What a directory entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link or reparse point, not followed for display.
    Symlink,
}

/// One entry in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    /// File name only, never a full path.
    pub name: String,
    /// What it is.
    pub kind: EntryKind,
    /// Size in bytes, for files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    /// Last-modified time as unix milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_ms: Option<i64>,
    /// Whether the name marks it hidden by convention.
    pub is_hidden: bool,
}

/// A file's contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileContent {
    /// The path that was read, as the client asked for it.
    pub path: String,
    /// The contents, as UTF-8 text.
    pub text: String,
    /// BLAKE3 of the bytes actually read.
    ///
    /// The compare-and-swap baseline (§12.2). A write will carry this back so the
    /// daemon can reject it if the file changed meanwhile.
    pub content_hash: Digest,
    /// Whether the file was longer than [`MAX_READ_BYTES`].
    ///
    /// Surfaced so the client can say "showing the first 512 KB" rather than
    /// silently presenting a truncated file as complete.
    pub truncated: bool,
}

/// Read-only filesystem operations, guarded by policy.
///
/// Holds the [`PolicyEngine`] rather than a bare path guard, so that every call
/// runs the *composed* pipeline — capability check, then containment, then
/// denylist — in the order `ARCHITECTURE.md` §2 specifies. Reaching past the
/// engine to the raw guard would silently skip the capability and denylist steps.
pub struct FsService {
    engine: PolicyEngine,
}

impl FsService {
    /// Builds the service over a policy engine.
    #[must_use]
    pub fn new(engine: PolicyEngine) -> Self {
        Self { engine }
    }

    /// Lists one directory level.
    ///
    /// # Errors
    ///
    /// Any [`ProtoError`] the policy layer produces — notably `NotFound` for a
    /// path outside every workspace root, which is deliberately
    /// indistinguishable from a path that genuinely does not exist so that a
    /// client cannot map the filesystem by probing (`ARCHITECTURE.md` §3.6).
    pub fn list(
        &self,
        grant: Option<&DeviceGrant>,
        requested: &str,
    ) -> Result<Vec<DirEntry>, ProtoError> {
        let resolved = self.authorize(grant, Capability::FsRead, "fs.list", requested)?;

        let read = std::fs::read_dir(resolved.path()).map_err(|_| ProtoError::not_found())?;
        let candidates: Vec<PathBuf> = read.flatten().map(|entry| entry.path()).collect();

        // `filter_listing` drops anything outside a root and anything the
        // denylist covers. A secret's *name* is as sensitive as its contents —
        // seeing `.env` tells an attacker exactly what to ask for next — so
        // denylisted entries vanish from the listing rather than appearing
        // greyed out (§3.6).
        let visible = self.engine.filter_listing(grant, candidates);

        let mut entries = Vec::new();
        for path in visible {
            let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
                continue;
            };

            // `symlink_metadata` decides the *kind*: following the link would
            // report the target's type and size, which is both misleading and a
            // way to learn about files outside the root.
            let Ok(link_meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            let kind = if link_meta.file_type().is_symlink() {
                EntryKind::Symlink
            } else if link_meta.is_dir() {
                EntryKind::Directory
            } else {
                EntryKind::File
            };

            let meta = std::fs::metadata(&path).ok();
            entries.push(DirEntry {
                is_hidden: is_hidden(&name),
                size_bytes: match kind {
                    EntryKind::File => meta.as_ref().map(std::fs::Metadata::len),
                    _ => None,
                },
                modified_ms: meta.as_ref().and_then(modified_ms),
                name,
                kind,
            });
        }

        // Directories first, then case-insensitive by name. Matches what every
        // file browser does, and a stable order means the client's LazyColumn
        // keys stay valid across refreshes.
        entries.sort_by(|a, b| match (a.kind, b.kind) {
            (EntryKind::Directory, EntryKind::Directory) => cmp_names(&a.name, &b.name),
            (EntryKind::Directory, _) => std::cmp::Ordering::Less,
            (_, EntryKind::Directory) => std::cmp::Ordering::Greater,
            _ => cmp_names(&a.name, &b.name),
        });

        Ok(entries)
    }

    /// Reads a file as UTF-8 text.
    ///
    /// # Errors
    ///
    /// [`ProtoError`] from policy, or `NotFound` if the file cannot be read.
    /// A file that is not valid UTF-8 is reported as `BadRequest` rather than
    /// being lossily converted, because silently mangling a binary file is worse
    /// than refusing it.
    pub fn read(
        &self,
        grant: Option<&DeviceGrant>,
        requested: &str,
    ) -> Result<FileContent, ProtoError> {
        let resolved = self.authorize(grant, Capability::FsRead, "fs.read", requested)?;

        let bytes = std::fs::read(resolved.path()).map_err(|_| ProtoError::not_found())?;
        let truncated = bytes.len() > MAX_READ_BYTES;
        let slice = if truncated {
            &bytes[..MAX_READ_BYTES]
        } else {
            &bytes[..]
        };

        let text = String::from_utf8(slice.to_vec())
            .map_err(|_| ProtoError::bad_request("file is not valid UTF-8 text"))?;

        Ok(FileContent {
            path: requested.to_owned(),
            content_hash: Digest::of(slice),
            text,
            truncated,
        })
    }

    /// Runs the policy checks that must precede any disk access.
    ///
    /// Kept as one private helper so that every public method goes through the
    /// same sequence, and so a new method cannot accidentally use a different one.
    fn authorize(
        &self,
        grant: Option<&DeviceGrant>,
        capability: Capability,
        method: &str,
        requested: &str,
    ) -> Result<gonomad_policy::ResolvedPath, ProtoError> {
        // Rejected here rather than deeper: a null byte would be silently
        // truncated by the platform's path APIs, so the path the guard validates
        // would not be the path that gets opened.
        if requested.contains('\0') {
            return Err(ProtoError::bad_request("path contains a null byte"));
        }

        self.engine.authorize_path(&PathRequest {
            grant,
            capability,
            path: Path::new(requested),
            method,
            args_digest: Digest::of(requested.as_bytes()),
            // Read-only operations are never presence-gated in this slice.
            // A denylisted path is refused outright rather than unlockable,
            // because there is no biometric path on the wire yet.
            presence: Presence::Absent,
        })
    }
}

/// Case-insensitive name comparison, falling back to byte order for stability.
fn cmp_names(a: &str, b: &str) -> std::cmp::Ordering {
    a.to_lowercase()
        .cmp(&b.to_lowercase())
        .then_with(|| a.cmp(b))
}

/// Whether a name is hidden by platform convention.
///
/// The dot prefix is the Unix convention and is also how developer tooling marks
/// hidden files on Windows (`.git`, `.vscode`), which is what actually matters in
/// a source tree. The Windows hidden *attribute* is not consulted, because it is
/// set on things a developer does want to see and unset on things they do not.
fn is_hidden(name: &str) -> bool {
    name.starts_with('.')
}

fn modified_ms(meta: &std::fs::Metadata) -> Option<i64> {
    let modified = meta.modified().ok()?;
    let since_epoch = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    i64::try_from(since_epoch.as_millis()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use gonomad_policy::{PathGuard, SecretDenylist, WorkspaceRoot};
    use gonomad_proto::DeviceId;
    use tempfile::TempDir;

    /// A newly-paired device's grant: fs:read yes, fs:secrets no.
    fn grant() -> DeviceGrant {
        DeviceGrant::newly_paired(DeviceId::from_bytes([9u8; 32]))
    }

    fn service(root: &Path) -> FsService {
        let guard = PathGuard::new(vec![WorkspaceRoot::new(root).expect("root")]);
        FsService::new(PolicyEngine::new(guard, SecretDenylist::with_defaults()))
    }

    fn fixture() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src").join("main.rs"), b"fn main() {}\n").unwrap();
        std::fs::write(root.join("README.md"), b"# demo\n").unwrap();
        std::fs::write(root.join(".env"), b"SECRET=hunter2\n").unwrap();
        std::fs::write(root.join(".gitignore"), b"target\n").unwrap();
        (dir, root)
    }

    #[test]
    fn lists_a_directory_with_folders_first() {
        let (_d, root) = fixture();
        let svc = service(&root);
        let entries = svc
            .list(Some(&grant()), root.to_str().unwrap())
            .expect("list");

        assert_eq!(entries.first().map(|e| e.kind), Some(EntryKind::Directory));
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"src"));
        assert!(names.contains(&"README.md"));
    }

    #[test]
    fn secrets_are_omitted_from_listings_entirely() {
        // The name alone tells an attacker what to ask for next, so a denylisted
        // entry must not appear at all — not even greyed out.
        let (_d, root) = fixture();
        let entries = service(&root)
            .list(Some(&grant()), root.to_str().unwrap())
            .expect("list");
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(!names.contains(&".env"), "the secret was listed: {names:?}");
    }

    #[test]
    fn dotfiles_that_are_not_secrets_are_listed_but_flagged_hidden() {
        let (_d, root) = fixture();
        let entries = service(&root)
            .list(Some(&grant()), root.to_str().unwrap())
            .expect("list");
        let gitignore = entries.iter().find(|e| e.name == ".gitignore");
        assert!(
            gitignore.is_some(),
            "a harmless dotfile should still be listed"
        );
        assert!(gitignore.unwrap().is_hidden);
    }

    #[test]
    fn reads_a_file_and_returns_a_cas_baseline() {
        let (_d, root) = fixture();
        let path = root.join("src").join("main.rs");
        let content = service(&root)
            .read(Some(&grant()), path.to_str().unwrap())
            .expect("read");

        assert_eq!(content.text, "fn main() {}\n");
        assert!(!content.truncated);
        assert_eq!(content.content_hash, Digest::of(b"fn main() {}\n"));
    }

    #[test]
    fn reading_a_secret_is_refused() {
        let (_d, root) = fixture();
        let path = root.join(".env");
        // The path resolves inside the root, so this must be stopped by the
        // denylist rather than by containment.
        let err = service(&root)
            .read(Some(&grant()), path.to_str().unwrap())
            .unwrap_err();
        assert!(
            matches!(err.kind.code(), "denied" | "not_found"),
            "expected a refusal, got {:?}",
            err.kind
        );
    }

    #[test]
    fn a_path_outside_the_root_is_not_found() {
        // Deliberately indistinguishable from a missing file, so probing cannot
        // map the filesystem.
        let (_d, root) = fixture();
        let outside = root.parent().unwrap().join("elsewhere.txt");
        std::fs::write(&outside, b"x").ok();
        let err = service(&root)
            .list(Some(&grant()), outside.to_str().unwrap())
            .unwrap_err();
        assert_eq!(err.kind.code(), "not_found");
    }

    #[test]
    fn the_prefix_attack_is_refused() {
        // `<root>-evil` must not be treated as inside `<root>`.
        let (_d, root) = fixture();
        let sibling = root.with_file_name(format!(
            "{}-evil",
            root.file_name().unwrap().to_string_lossy()
        ));
        std::fs::create_dir_all(&sibling).ok();
        std::fs::write(sibling.join("loot"), b"loot").ok();

        let err = service(&root)
            .list(Some(&grant()), sibling.to_str().unwrap())
            .unwrap_err();
        assert_eq!(err.kind.code(), "not_found");
    }

    #[test]
    fn traversal_out_of_the_root_is_refused() {
        let (_d, root) = fixture();
        let escape = format!("{}/../..", root.display());
        assert!(service(&root).list(Some(&grant()), &escape).is_err());
    }

    #[test]
    fn a_null_byte_in_the_path_is_rejected_before_any_syscall() {
        let (_d, root) = fixture();
        let err = service(&root)
            .read(Some(&grant()), "some\0path")
            .unwrap_err();
        assert_eq!(err.kind.code(), "bad_request");
    }

    #[test]
    fn binary_files_are_refused_rather_than_mangled() {
        let (_d, root) = fixture();
        // 0xFF is never valid UTF-8.
        std::fs::write(root.join("blob.bin"), [0xFFu8, 0xFE, 0x00, 0x01]).unwrap();
        let path = root.join("blob.bin");
        let err = service(&root)
            .read(Some(&grant()), path.to_str().unwrap())
            .unwrap_err();
        assert_eq!(err.kind.code(), "bad_request");
    }

    #[test]
    fn oversized_files_are_truncated_and_say_so() {
        let (_d, root) = fixture();
        let big = "x".repeat(MAX_READ_BYTES + 1000);
        std::fs::write(root.join("big.txt"), &big).unwrap();

        let path = root.join("big.txt");
        let content = service(&root)
            .read(Some(&grant()), path.to_str().unwrap())
            .expect("read");
        assert!(content.truncated, "truncation must be reported, not silent");
        assert_eq!(content.text.len(), MAX_READ_BYTES);
    }

    #[test]
    fn a_missing_file_is_not_found() {
        let (_d, root) = fixture();
        let path = root.join("nope.txt");
        let err = service(&root)
            .read(Some(&grant()), path.to_str().unwrap())
            .unwrap_err();
        assert_eq!(err.kind.code(), "not_found");
    }

    #[test]
    fn listing_order_is_stable_across_calls() {
        // The client uses names as LazyColumn keys; an unstable order would make
        // the list jump on every refresh.
        let (_d, root) = fixture();
        let svc = service(&root);
        let first = svc
            .list(Some(&grant()), root.to_str().unwrap())
            .expect("first");
        let second = svc
            .list(Some(&grant()), root.to_str().unwrap())
            .expect("second");
        assert_eq!(first, second);
    }

    #[test]
    fn entry_names_never_contain_a_path_separator() {
        // Leaking full paths would tell a client about the host's layout.
        let (_d, root) = fixture();
        for entry in service(&root)
            .list(Some(&grant()), root.to_str().unwrap())
            .expect("list")
        {
            assert!(
                !entry.name.contains('/'),
                "{} looks like a path",
                entry.name
            );
            assert!(
                !entry.name.contains('\\'),
                "{} looks like a path",
                entry.name
            );
        }
    }

    #[test]
    fn a_service_with_no_roots_denies_everything() {
        // Fail closed: a daemon that failed to load its config must not expose
        // the whole disk.
        let (_d, root) = fixture();
        let svc = FsService::new(PolicyEngine::new(
            PathGuard::new(vec![]),
            SecretDenylist::with_defaults(),
        ));
        assert!(svc.list(Some(&grant()), root.to_str().unwrap()).is_err());
        assert!(svc
            .read(Some(&grant()), root.join("README.md").to_str().unwrap())
            .is_err());
    }
}
