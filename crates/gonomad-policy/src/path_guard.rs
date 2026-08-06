//! The path guard: deciding whether a requested path is inside a workspace root.
//!
//! This is the highest-consequence code in GoNomad. A paired phone is a
//! credential to the developer's entire workstation, so a bug here is not a
//! missing feature — it is `~/.ssh/id_ed25519` in the hands of whoever picked
//! the phone up.
//!
//! # The pipeline
//!
//! Every path goes through the same sequence (`ARCHITECTURE.md` §3.6), in this
//! order, and a failure at any step denies:
//!
//! 1. **Reject null bytes and non-UTF-8 input.** A null byte truncates the path
//!    inside any C API the OS eventually reaches, so `"/allowed/x\0/../../etc"`
//!    can validate as one path and open as another.
//! 2. **Reject malformed names** — Windows reserved device names, alternate
//!    data streams, trailing dots and spaces, verbatim `\\?\` prefixes, and UNC
//!    paths that are not themselves configured roots.
//! 3. **Canonicalise**, resolving `..`, symlinks, junctions, 8.3 short names,
//!    and drive prefixes. Via [`dunce`], which returns ordinary Windows paths
//!    instead of `\\?\`-prefixed ones wherever that is lossless.
//! 4. **Check containment component-wise** against the canonicalised roots.
//!    Never by string prefix.
//! 5. (Caller's step) apply the secret denylist — see [`crate::denylist`].
//!
//! # Why component-wise containment, always
//!
//! `"/home/user/proj-evil".starts_with("/home/user/proj")` is `true`. So is
//! `"C:\\projects\\..\\Windows"` against `"C:\\projects"` before
//! canonicalisation. String prefix matching is the single most common way this
//! check is written and the single most common way it is broken. There is one
//! containment function in this module, it compares [`std::path::Component`]s,
//! and [`PathGuard::is_within`] is the only place it is used.
//!
//! # TOCTOU: the window this module cannot close
//!
//! Canonicalisation happens against the filesystem as it is *at check time*.
//! Between [`PathGuard::resolve`] returning and the caller's `open()`, another
//! process — including a cooperating local process the attacker controls —
//! can replace a directory in the resolved path with a symlink or junction
//! pointing outside every root. The check would have passed; the open would
//! land elsewhere. This module **cannot** close that window, because it does
//! not perform the open.
//!
//! What it does instead is refuse to make closing it impossible.
//! [`ResolvedPath`] carries an optional [`FileIdentity`], and
//! [`ResolvedPath::confirm_identity`] compares the identity observed through
//! the *opened handle* against the one recorded at check time. The filesystem
//! layer is expected to:
//!
//! 1. call [`PathGuard::resolve`],
//! 2. open the resolved path (`FILE_FLAG_OPEN_REPARSE_POINT` off, or `O_NOFOLLOW`
//!    on the final component where appropriate),
//! 3. read the handle's identity — `GetFileInformationByHandle` on Windows
//!    (`dwVolumeSerialNumber` + `nFileIndexHigh/Low`), `fstat` on Unix
//!    (`st_dev` + `st_ino`) — and
//! 4. call [`ResolvedPath::confirm_identity`] before reading or writing a byte.
//!
//! Acquiring the identity requires platform syscalls that this crate
//! deliberately does not take a dependency on: `gonomad-policy` must stay
//! auditable and free of `unsafe`, and it is compiled into the Android client
//! alongside the daemon. So the comparison lives here and the *observation*
//! lives in `gonomad-fs`. The honest statement of the residual risk: **until a
//! caller supplies identities, the TOCTOU window is open**, and a local
//! attacker who can win a race against a directory in a workspace root can
//! redirect a read. That attacker already has code execution on the machine,
//! which is outside the threat model's primary case (a stolen phone), but it is
//! not zero.

use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf, Prefix};

use gonomad_proto::ProtoError;
use serde::{Deserialize, Serialize};

/// Longest requested path accepted, in bytes.
///
/// Bounds the work an attacker can make the guard do per request, and stays
/// well clear of the point where platform APIs start behaving inconsistently.
pub const MAX_PATH_BYTES: usize = 4096;

/// Most components a requested path may have.
///
/// A path of ten thousand `a/` segments is not a real request; it is an attempt
/// to make canonicalisation quadratic.
pub const MAX_PATH_COMPONENTS: usize = 256;

/// Windows names that resolve to devices rather than files, in every directory.
///
/// Opening one of these does not touch the filesystem at all: it opens the
/// console, a serial port, or the null device. The consequences range from a
/// hung read on `CON` to writing a phone's request straight out of a serial
/// port. They are rejected on every platform, not only Windows — see
/// [`GuardOptions::windows_name_rules`].
///
/// The superscript forms are not a typo. Win32 normalises `COM¹`, `COM²`, and
/// `COM³` to `COM1`, `COM2`, and `COM3` when resolving device names, so a
/// filter that only knows about ASCII digits can be walked straight past.
const RESERVED_DEVICE_NAMES: &[&str] = &[
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "CONIN$",
    "CONOUT$",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
];

// ---------------------------------------------------------------------------
// Denial reasons
// ---------------------------------------------------------------------------

/// Why a path was refused.
///
/// This vocabulary is **local to the daemon**. It exists for the audit log and
/// for the laptop-side operator, who needs to know that a device tried to reach
/// `\\evil\share` rather than merely that "something was not found". It never
/// crosses the wire: [`DenyReason::to_proto_error`] collapses it into the
/// protocol's own errors, and every location-related reason collapses to
/// [`gonomad_proto::ErrorKind::NotFound`] so that a client cannot map the
/// filesystem outside its roots one probe at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DenyReason {
    /// The path was not valid UTF-8.
    NotUtf8,
    /// The path contained a null byte, which truncates it inside the OS.
    NullByte,
    /// The path exceeded [`MAX_PATH_BYTES`].
    TooLong,
    /// The path exceeded [`MAX_PATH_COMPONENTS`].
    TooManyComponents,
    /// The path was relative; the guard has no cwd to resolve it against.
    NotAbsolute,
    /// A component named a Windows device such as `CON` or `LPT1`.
    ReservedDeviceName,
    /// A component contained `:`, naming an NTFS alternate data stream.
    AlternateDataStream,
    /// A component ended in a dot or a space, which Windows silently strips.
    TrailingDotOrSpace,
    /// The path used a `\\?\` or `\\.\` prefix, which bypasses Win32 name
    /// normalisation entirely.
    VerbatimPrefix,
    /// The path was a UNC network path and no configured root is on that share.
    UncNotConfigured,
    /// No workspace roots are configured, so nothing is reachable.
    NoRootsConfigured,
    /// The deepest existing ancestor could not be canonicalised.
    UnresolvableAncestor,
    /// A `..` appeared in the not-yet-existing tail of the path.
    TraversalIntoMissingPath,
    /// The canonical path is not a descendant of any configured root.
    OutsideRoots,
}

impl DenyReason {
    /// A stable identifier for audit entries and metrics.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotUtf8 => "not_utf8",
            Self::NullByte => "null_byte",
            Self::TooLong => "too_long",
            Self::TooManyComponents => "too_many_components",
            Self::NotAbsolute => "not_absolute",
            Self::ReservedDeviceName => "reserved_device_name",
            Self::AlternateDataStream => "alternate_data_stream",
            Self::TrailingDotOrSpace => "trailing_dot_or_space",
            Self::VerbatimPrefix => "verbatim_prefix",
            Self::UncNotConfigured => "unc_not_configured",
            Self::NoRootsConfigured => "no_roots_configured",
            Self::UnresolvableAncestor => "unresolvable_ancestor",
            Self::TraversalIntoMissingPath => "traversal_into_missing_path",
            Self::OutsideRoots => "outside_roots",
        }
    }

    /// Whether the refusal is about the *shape* of the name rather than about
    /// where it points.
    ///
    /// Drives the error mapping: a malformed name is a client bug and saying so
    /// leaks nothing, whereas anything about *location* must be indistinguishable
    /// from "does not exist".
    #[must_use]
    pub const fn is_malformed_name(self) -> bool {
        matches!(
            self,
            Self::NotUtf8
                | Self::NullByte
                | Self::TooLong
                | Self::TooManyComponents
                | Self::NotAbsolute
                | Self::ReservedDeviceName
                | Self::AlternateDataStream
                | Self::TrailingDotOrSpace
                | Self::VerbatimPrefix
        )
    }

    /// Collapses into the protocol's error vocabulary.
    ///
    /// Location-related reasons all become `NotFound`. This is deliberate and
    /// costs a little clarity for a legitimate user: distinguishing "outside
    /// your root" from "does not exist" would turn the guard into an oracle for
    /// enumerating the filesystem outside the roots.
    #[must_use]
    pub fn to_proto_error(self) -> ProtoError {
        if self.is_malformed_name() {
            ProtoError::bad_request("invalid path")
        } else {
            ProtoError::not_found()
        }
    }
}

/// A refused path, carrying the reason for the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("path denied: {reason:?}")]
pub struct PathDenied {
    /// Why the path was refused.
    pub reason: DenyReason,
}

impl PathDenied {
    /// Wraps a reason.
    #[must_use]
    pub const fn new(reason: DenyReason) -> Self {
        Self { reason }
    }
}

impl From<PathDenied> for ProtoError {
    fn from(denied: PathDenied) -> Self {
        denied.reason.to_proto_error()
    }
}

// ---------------------------------------------------------------------------
// File identity (the TOCTOU hook)
// ---------------------------------------------------------------------------

/// The identity of a filesystem object as seen through an open handle.
///
/// Not a path. Two paths can name the same object (hard links, junctions,
/// bind mounts) and one path can name two different objects a microsecond
/// apart — which is exactly the race this type exists to detect.
///
/// The fields are named generically because the platforms disagree on
/// vocabulary but agree on the shape:
///
/// | Field | Windows | Unix |
/// |---|---|---|
/// | `volume` | `dwVolumeSerialNumber` | `st_dev` |
/// | `object` | `nFileIndexHigh:nFileIndexLow` | `st_ino` |
///
/// This crate never *reads* an identity — that needs platform syscalls it
/// deliberately does not depend on. It only compares them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FileIdentity {
    /// The volume or device the object lives on.
    pub volume: u64,
    /// The object's index within the volume.
    pub object: u128,
}

impl FileIdentity {
    /// Constructs an identity from its two parts.
    #[must_use]
    pub const fn new(volume: u64, object: u128) -> Self {
        Self { volume, object }
    }
}

// ---------------------------------------------------------------------------
// Resolved paths
// ---------------------------------------------------------------------------

/// A path that has passed every check in [`PathGuard::resolve`].
///
/// Construction is private to this module, so a `ResolvedPath` cannot be
/// forged: possessing one *is* the proof that the guard approved it. Service
/// code should take `&ResolvedPath` rather than `&Path` so that skipping the
/// guard is a compile error rather than a code-review miss.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPath {
    path: PathBuf,
    root: PathBuf,
    exists: bool,
    expected_identity: Option<FileIdentity>,
}

impl ResolvedPath {
    /// The canonical path the caller may operate on.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The workspace root this path was found under.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether the path existed at check time.
    ///
    /// `false` means the parent existed and the leaf did not — the create-a-new-
    /// file case. A read of such a path will fail; a write may create it.
    #[must_use]
    pub const fn exists(&self) -> bool {
        self.exists
    }

    /// Consumes into the canonical path.
    #[must_use]
    pub fn into_path_buf(self) -> PathBuf {
        self.path
    }

    /// Records the identity of the object this path named at check time.
    ///
    /// Supplied by the filesystem layer after it stats the resolved path, so
    /// that the identity observed after opening can be compared against it.
    #[must_use]
    pub fn with_expected_identity(mut self, identity: FileIdentity) -> Self {
        self.expected_identity = Some(identity);
        self
    }

    /// The identity recorded at check time, if any.
    #[must_use]
    pub const fn expected_identity(&self) -> Option<FileIdentity> {
        self.expected_identity
    }

    /// Confirms that an opened handle refers to the object that was validated.
    ///
    /// This is the second half of the TOCTOU defence described in the module
    /// documentation. Call it after `open()` and before the first read or
    /// write.
    ///
    /// # Errors
    ///
    /// [`gonomad_proto::ErrorKind::NotFound`] when the identities differ: the
    /// object was swapped between check and use, and the operation must not
    /// proceed. `NotFound` rather than a distinct variant, for the same
    /// no-oracle reason as every other location failure.
    ///
    /// Returns `Ok(())` when no identity was recorded. That is a *documented
    /// weakening*: a caller that never calls
    /// [`ResolvedPath::with_expected_identity`] gets no TOCTOU protection at
    /// all. It is not an error here because the guard cannot tell the
    /// difference between a caller that forgot and a platform where the
    /// identity is unavailable; enforcement belongs in `gonomad-fs`, which
    /// knows which of the two it is.
    pub fn confirm_identity(&self, observed: FileIdentity) -> Result<(), ProtoError> {
        match self.expected_identity {
            Some(expected) if expected != observed => Err(ProtoError::not_found()),
            _ => Ok(()),
        }
    }
}

// ---------------------------------------------------------------------------
// Roots and options
// ---------------------------------------------------------------------------

/// A directory a device is permitted to reach into.
///
/// Canonicalised at construction and stored canonicalised, so the containment
/// check never compares a canonical path against a non-canonical root — which
/// would fail open for a root reached through a symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRoot {
    canonical: PathBuf,
    configured: PathBuf,
}

impl WorkspaceRoot {
    /// Canonicalises `path` and adopts it as a root.
    ///
    /// The root must exist. A root that does not exist cannot be canonicalised,
    /// and accepting it uncanonicalised would mean comparing canonical
    /// candidates against a non-canonical root — a comparison that fails to
    /// match anything, or worse, matches the wrong thing once the directory is
    /// created as a symlink.
    ///
    /// # Errors
    ///
    /// Any [`io::Error`] from canonicalisation, most often `NotFound`.
    pub fn new(path: impl AsRef<Path>) -> io::Result<Self> {
        let configured = path.as_ref().to_path_buf();
        let canonical = dunce::canonicalize(&configured)?;
        Ok(Self {
            canonical,
            configured,
        })
    }

    /// The canonical form used for containment checks.
    #[must_use]
    pub fn canonical(&self) -> &Path {
        &self.canonical
    }

    /// The form the user wrote in their configuration, for display.
    #[must_use]
    pub fn configured(&self) -> &Path {
        &self.configured
    }

    /// Whether this root lives on a UNC network share.
    #[must_use]
    pub fn is_unc(&self) -> bool {
        path_is_unc(&self.canonical)
    }
}

/// Tunables for [`PathGuard`]. Every default is the strict choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardOptions {
    /// Apply the Windows name rules — reserved devices, alternate data
    /// streams, trailing dots and spaces — on every platform.
    ///
    /// Default `true`, including on Linux and macOS, for two reasons. A policy
    /// decision that differs by host is a policy decision nobody can reason
    /// about or test once. And a repository is routinely edited on Windows and
    /// served from a Linux daemon or the reverse, so a name that is a weapon on
    /// one host should not be creatable from the other.
    ///
    /// The cost is real but small: a Unix file legitimately named `a:b` or
    /// `report.` becomes unreachable. A Unix-only deployment may set this
    /// `false`; nothing else in the guard depends on it.
    pub windows_name_rules: bool,

    /// Permit paths that resolve onto a UNC share.
    ///
    /// Independently of this flag, a UNC path is refused unless some configured
    /// root is itself on a UNC share (§3.6). This flag is the second lock: it
    /// must be turned on deliberately, because a UNC path is a request for the
    /// daemon to authenticate to an arbitrary remote SMB server, which is an
    /// NTLM-relay primitive handed to whoever holds the phone.
    pub allow_unc: bool,
}

impl Default for GuardOptions {
    fn default() -> Self {
        Self {
            windows_name_rules: true,
            allow_unc: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Syntactic checks (pure, testable on every platform)
// ---------------------------------------------------------------------------

/// Whether a single path component names a Windows device.
///
/// Matches the way Win32 actually resolves them, which is looser than most
/// filters assume:
///
/// - the extension is ignored, so `CON.txt` is `CON`;
/// - trailing dots and spaces are stripped first, so `"CON . "` is `CON`;
/// - matching is case-insensitive, so `cOn` is `CON`;
/// - a trailing `:` is a device-namespace marker, so `CON:` is `CON`.
///
/// The attack this stops: a phone asks to write `C:\proj\LPT1`, and instead of
/// creating a file the daemon writes the payload to a parallel port, or hangs
/// forever reading `CON` and takes a request slot with it.
#[must_use]
pub fn is_reserved_device_name(component: &str) -> bool {
    let stem = component.split(['.', ':']).next().unwrap_or(component);
    let stem = stem.trim_matches(|c: char| c == ' ' || c == '\t');
    RESERVED_DEVICE_NAMES
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved) || stem == *reserved)
}

/// Whether a component names an NTFS alternate data stream.
///
/// `secrets.txt:hidden` is a second, invisible stream on the same file. Two
/// reasons to refuse it outright: content written there is not visible to any
/// ordinary listing, making it an exfiltration channel that the audit log
/// records as a write to `secrets.txt`; and `file::$DATA` is an alias for the
/// file's main stream, so any denylist that matches on the name can be walked
/// past by appending it.
#[must_use]
pub fn has_alternate_data_stream(component: &str) -> bool {
    component.contains(':')
}

/// Whether a component ends in a dot or a space.
///
/// Windows strips both when resolving a name, so `"secret.txt "` and
/// `"secret.txt"` are the same file while being different strings. Any check
/// that compares strings — a denylist, an allowlist, an audit entry — can be
/// evaded by appending a space.
#[must_use]
pub fn has_trailing_dot_or_space(component: &str) -> bool {
    component.ends_with('.') || component.ends_with(' ')
}

/// Whether `path` uses a UNC prefix (`\\server\share`).
#[must_use]
pub fn path_is_unc(path: &Path) -> bool {
    matches!(
        path.components().next(),
        Some(Component::Prefix(p))
            if matches!(p.kind(), Prefix::UNC(..) | Prefix::VerbatimUNC(..))
    )
}

/// Whether `path` uses a verbatim (`\\?\`) or device (`\\.\`) prefix.
#[must_use]
fn path_is_verbatim(path: &Path) -> bool {
    matches!(
        path.components().next(),
        Some(Component::Prefix(p))
            if matches!(
                p.kind(),
                Prefix::Verbatim(..) | Prefix::VerbatimUNC(..) | Prefix::VerbatimDisk(..) | Prefix::DeviceNS(..)
            )
    )
}

/// Compares two path components for equality as the host filesystem would.
///
/// Case-insensitive on Windows only. That asymmetry is load-bearing in both
/// directions. On Windows, `C:\Proj` and `c:\proj` are the same directory, so a
/// case-sensitive comparison would deny legitimate requests — and, worse, would
/// let a root recorded in one casing fail to match a path canonicalised in
/// another. On Linux, `~/proj` and `~/PROJ` are two different directories, so a
/// case-insensitive comparison would treat one root as covering the other and
/// hand out access that was never granted.
fn components_eq(a: &Component<'_>, b: &Component<'_>) -> bool {
    if a == b {
        return true;
    }
    #[cfg(windows)]
    {
        let (x, y) = (a.as_os_str(), b.as_os_str());
        match (x.to_str(), y.to_str()) {
            // `to_lowercase` rather than `eq_ignore_ascii_case`: NTFS folds
            // non-ASCII too, so an ASCII-only fold would make `Ä` and `ä`
            // compare unequal when the filesystem considers them one file.
            (Some(x), Some(y)) => x.to_lowercase() == y.to_lowercase(),
            // A non-UTF-8 component cannot be folded safely, and the exact
            // comparison above already failed. Deny.
            _ => false,
        }
    }
    #[cfg(not(windows))]
    {
        false
    }
}

// ---------------------------------------------------------------------------
// The guard
// ---------------------------------------------------------------------------

/// Decides whether a requested path is inside an allowed workspace root.
///
/// See the module documentation for the pipeline, the reasoning behind
/// component-wise containment, and the TOCTOU limitation.
#[derive(Debug, Clone)]
pub struct PathGuard {
    roots: Vec<WorkspaceRoot>,
    options: GuardOptions,
    has_unc_root: bool,
}

impl PathGuard {
    /// Builds a guard over `roots` with the strict default options.
    #[must_use]
    pub fn new(roots: Vec<WorkspaceRoot>) -> Self {
        Self::with_options(roots, GuardOptions::default())
    }

    /// Builds a guard over `roots`.
    ///
    /// An empty root list is legal and denies everything. That is the correct
    /// behaviour for a device whose roots failed to load: no roots means no
    /// access, never all access.
    #[must_use]
    pub fn with_options(roots: Vec<WorkspaceRoot>, options: GuardOptions) -> Self {
        let has_unc_root = roots.iter().any(WorkspaceRoot::is_unc);
        Self {
            roots,
            options,
            has_unc_root,
        }
    }

    /// The configured roots.
    #[must_use]
    pub fn roots(&self) -> &[WorkspaceRoot] {
        &self.roots
    }

    /// The options in force.
    #[must_use]
    pub const fn options(&self) -> GuardOptions {
        self.options
    }

    /// Runs the full pipeline and returns the canonical path.
    ///
    /// Accepts paths that do not yet exist, so that creating a file is possible:
    /// the deepest existing ancestor is canonicalised and the missing tail is
    /// validated separately. See [`PathGuard::resolve_existing`] when the path
    /// must already be there.
    ///
    /// # Errors
    ///
    /// [`PathDenied`] carrying the specific [`DenyReason`] for the audit log.
    /// Convert with `ProtoError::from` before it crosses the wire.
    pub fn resolve(&self, requested: impl AsRef<Path>) -> Result<ResolvedPath, PathDenied> {
        let requested = requested.as_ref();
        self.check_syntax(requested)?;

        if self.roots.is_empty() {
            return Err(PathDenied::new(DenyReason::NoRootsConfigured));
        }
        if path_is_unc(requested) && !(self.options.allow_unc && self.has_unc_root) {
            return Err(PathDenied::new(DenyReason::UncNotConfigured));
        }

        let (ancestor, tail) = canonicalise_deepest_ancestor(requested)?;
        let exists = tail.is_empty();
        let mut canonical = ancestor;
        for part in &tail {
            canonical.push(part);
        }

        // A UNC root may be configured, but a path that *resolves* onto a share
        // via a junction must still be caught — hence the re-check on the
        // canonical form rather than only on the input.
        if path_is_unc(&canonical) && !(self.options.allow_unc && self.has_unc_root) {
            return Err(PathDenied::new(DenyReason::UncNotConfigured));
        }

        let root = self
            .roots
            .iter()
            .find(|root| Self::is_within(root.canonical(), &canonical))
            .ok_or(PathDenied::new(DenyReason::OutsideRoots))?;

        Ok(ResolvedPath {
            path: canonical,
            root: root.canonical().to_path_buf(),
            exists,
            expected_identity: None,
        })
    }

    /// As [`PathGuard::resolve`], but refuses a path that does not exist.
    ///
    /// # Errors
    ///
    /// As [`PathGuard::resolve`], plus [`DenyReason::OutsideRoots`] when the
    /// path is absent — indistinguishable, on purpose, from a path that exists
    /// outside the roots.
    pub fn resolve_existing(
        &self,
        requested: impl AsRef<Path>,
    ) -> Result<ResolvedPath, PathDenied> {
        let resolved = self.resolve(requested)?;
        if resolved.exists() {
            Ok(resolved)
        } else {
            Err(PathDenied::new(DenyReason::OutsideRoots))
        }
    }

    /// Resolves a path expressed relative to one of the configured roots.
    ///
    /// The reason this exists rather than leaving callers to write
    /// `root.join(relative)`: in Rust, as in Win32, joining an *absolute* path
    /// onto a base discards the base entirely. `Path::new("C:\\proj").join("C:\\Windows\\System32")`
    /// is `C:\Windows\System32`. A router that joins a client-supplied string
    /// onto a root has therefore handed the client the whole disk. This
    /// function rejects any `relative` that is absolute or carries a prefix,
    /// before joining.
    ///
    /// # Errors
    ///
    /// [`DenyReason::NotAbsolute`] when `relative` is not in fact relative,
    /// then as [`PathGuard::resolve`].
    pub fn resolve_in_root(
        &self,
        root: &WorkspaceRoot,
        relative: impl AsRef<Path>,
    ) -> Result<ResolvedPath, PathDenied> {
        let relative = relative.as_ref();
        let escapes = relative.is_absolute()
            || relative.has_root()
            || matches!(
                relative.components().next(),
                Some(Component::Prefix(_) | Component::RootDir)
            );
        if escapes {
            // Reported as NotAbsolute because that is literally the violated
            // precondition: a relative path was required and an absolute one
            // was supplied.
            return Err(PathDenied::new(DenyReason::NotAbsolute));
        }
        self.resolve(root.canonical().join(relative))
    }

    /// Whether `candidate` is `root` or lives beneath it, compared component by
    /// component.
    ///
    /// The one containment predicate in the crate. `/home/user/proj-evil` is
    /// not within `/home/user/proj`, because `proj-evil` and `proj` are
    /// different components — which a `starts_with` on the string forms would
    /// have missed.
    #[must_use]
    pub fn is_within(root: &Path, candidate: &Path) -> bool {
        let mut root_parts = root.components();
        let mut candidate_parts = candidate.components();
        loop {
            match (root_parts.next(), candidate_parts.next()) {
                // Root exhausted: every one of its components matched, so the
                // candidate is the root itself or a descendant.
                (None, _) => return true,
                // Candidate ran out first: it is an ancestor, not a descendant.
                (Some(_), None) => return false,
                (Some(r), Some(c)) => {
                    if !components_eq(&r, &c) {
                        return false;
                    }
                }
            }
        }
    }

    /// Steps 1 and 2 of the pipeline: everything decidable from the string.
    fn check_syntax(&self, requested: &Path) -> Result<(), PathDenied> {
        // `to_str` is the UTF-8 gate. On Unix an OsStr may be arbitrary bytes;
        // on Windows it may contain unpaired surrogates. Either way a path we
        // cannot examine as text is a path we cannot check, so it is refused
        // rather than passed through unexamined.
        let text = requested
            .to_str()
            .ok_or(PathDenied::new(DenyReason::NotUtf8))?;

        if text.contains('\0') {
            return Err(PathDenied::new(DenyReason::NullByte));
        }
        if text.len() > MAX_PATH_BYTES {
            return Err(PathDenied::new(DenyReason::TooLong));
        }
        if path_is_verbatim(requested) {
            // `\\?\` disables all Win32 name processing, which is precisely the
            // processing that makes reserved names and trailing dots
            // unreachable. Accepting one would mean every rule below can be
            // switched off by the caller. Canonicalisation may still *produce*
            // a verbatim path for a legitimately long path; that is fine,
            // because it is produced by the OS rather than chosen by the client.
            return Err(PathDenied::new(DenyReason::VerbatimPrefix));
        }
        if !requested.is_absolute() {
            // There is no cwd to resolve against that would not be a footgun:
            // the daemon's own working directory is not the user's workspace.
            // Callers with a relative request use `resolve_in_root`.
            return Err(PathDenied::new(DenyReason::NotAbsolute));
        }

        let mut count = 0usize;
        for component in requested.components() {
            count += 1;
            if count > MAX_PATH_COMPONENTS {
                return Err(PathDenied::new(DenyReason::TooManyComponents));
            }
            let Component::Normal(part) = component else {
                // Prefix, RootDir, CurDir, and ParentDir carry no name to
                // check. `..` is not rejected here: it is legitimate inside an
                // existing tree and is resolved by canonicalisation. What must
                // never happen is `..` surviving into a path that is used, and
                // that is guaranteed by canonicalisation plus the tail check.
                continue;
            };
            let Some(name) = part.to_str() else {
                return Err(PathDenied::new(DenyReason::NotUtf8));
            };
            self.check_component(name)?;
        }
        Ok(())
    }

    /// The Windows name rules, applied to one component.
    fn check_component(&self, name: &str) -> Result<(), PathDenied> {
        if !self.options.windows_name_rules {
            return Ok(());
        }
        if has_alternate_data_stream(name) {
            return Err(PathDenied::new(DenyReason::AlternateDataStream));
        }
        if has_trailing_dot_or_space(name) {
            return Err(PathDenied::new(DenyReason::TrailingDotOrSpace));
        }
        if is_reserved_device_name(name) {
            return Err(PathDenied::new(DenyReason::ReservedDeviceName));
        }
        Ok(())
    }
}

/// Canonicalises the deepest existing ancestor of `path`, returning it along
/// with the components that do not exist yet.
///
/// Canonicalisation requires existence, but creating a file requires naming
/// something that does not exist, so the two have to be reconciled. The
/// reconciliation must not become an escape hatch, and three properties keep it
/// from becoming one:
///
/// - Only `NotFound` is treated as "keep walking up". Any other error —
///   permission denied, a reparse point that cannot be followed — denies
///   outright. Otherwise a symlink that merely fails to resolve would be
///   trimmed off and its *name* validated against the roots, while the open
///   would follow it wherever it points.
/// - `Path::file_name` returns `None` for `.` and `..`, so a path whose missing
///   tail contains a traversal cannot be trimmed and is denied. That closes
///   `<root>/does-not-exist/../../../etc/passwd`.
/// - The shallowest missing component is probed with `symlink_metadata`. If it
///   exists after all, canonicalisation failed for a reason other than absence
///   — a dangling symlink, or a concurrent modification — and the path is
///   denied rather than guessed at.
fn canonicalise_deepest_ancestor(path: &Path) -> Result<(PathBuf, Vec<OsString>), PathDenied> {
    let mut tail: Vec<OsString> = Vec::new();
    let mut cursor = path.to_path_buf();

    // Bounded by the component limit already enforced, plus slack for the
    // prefix and root. An unbounded loop here would be a hang waiting for a
    // pathological input.
    for _ in 0..=MAX_PATH_COMPONENTS + 2 {
        match dunce::canonicalize(&cursor) {
            Ok(canonical) => {
                tail.reverse();
                if let Some(first_missing) = tail.first() {
                    verify_still_missing(&canonical.join(first_missing))?;
                }
                return Ok((canonical, tail));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                let Some(name) = cursor.file_name() else {
                    // Either we walked up past the filesystem root, or the last
                    // component is `.`/`..`, which cannot be trimmed safely.
                    return Err(PathDenied::new(if cursor.parent().is_none() {
                        DenyReason::UnresolvableAncestor
                    } else {
                        DenyReason::TraversalIntoMissingPath
                    }));
                };
                tail.push(name.to_os_string());
                let Some(parent) = cursor.parent().map(Path::to_path_buf) else {
                    return Err(PathDenied::new(DenyReason::UnresolvableAncestor));
                };
                cursor = parent;
            }
            Err(_) => return Err(PathDenied::new(DenyReason::UnresolvableAncestor)),
        }
    }
    Err(PathDenied::new(DenyReason::TooManyComponents))
}

/// Confirms that a component canonicalisation reported as absent really is.
fn verify_still_missing(probe: &Path) -> Result<(), PathDenied> {
    match std::fs::symlink_metadata(probe) {
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        // It exists as a link but did not canonicalise: a dangling symlink or
        // junction, or something changed underneath us. Either way the guard
        // cannot say where it points, so it says no.
        Ok(_) | Err(_) => Err(PathDenied::new(DenyReason::UnresolvableAncestor)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// A workspace with a real directory tree, used by most tests below.
    struct Fixture {
        _dir: TempDir,
        root: PathBuf,
        outside: PathBuf,
        guard: PathGuard,
    }

    fn fixture() -> Fixture {
        let dir = TempDir::new().expect("tempdir");
        let base = dunce::canonicalize(dir.path()).expect("canonicalise tempdir");

        let root = base.join("proj");
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src").join("main.rs"), b"fn main() {}").unwrap();

        // The prefix-attack sibling: `proj-evil` shares a string prefix with
        // `proj` but is not inside it.
        let evil = base.join("proj-evil");
        fs::create_dir_all(&evil).unwrap();
        fs::write(evil.join("loot.txt"), b"secrets").unwrap();

        let outside = base.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("id_ed25519"), b"PRIVATE KEY").unwrap();

        let guard = PathGuard::new(vec![WorkspaceRoot::new(&root).unwrap()]);
        Fixture {
            _dir: dir,
            root,
            outside,
            guard,
        }
    }

    // -- the prefix attack ---------------------------------------------------

    #[test]
    fn proj_evil_does_not_match_root_proj() {
        // The canonical form of this bug: `"/home/user/proj-evil"` passes
        // `starts_with("/home/user/proj")`. It must not pass here.
        let f = fixture();
        let target = f.root.with_file_name("proj-evil").join("loot.txt");
        assert!(
            target
                .to_string_lossy()
                .starts_with(&*f.root.to_string_lossy()),
            "fixture is not exercising the prefix attack"
        );
        let denied = f.guard.resolve(&target).unwrap_err();
        assert_eq!(denied.reason, DenyReason::OutsideRoots);
    }

    #[test]
    fn is_within_is_component_wise_not_string_wise() {
        let root = Path::new("/home/user/proj");
        assert!(PathGuard::is_within(root, Path::new("/home/user/proj")));
        assert!(PathGuard::is_within(root, Path::new("/home/user/proj/src")));
        assert!(!PathGuard::is_within(
            root,
            Path::new("/home/user/proj-evil")
        ));
        assert!(!PathGuard::is_within(
            root,
            Path::new("/home/user/projevil")
        ));
        assert!(!PathGuard::is_within(root, Path::new("/home/user/proj2")));
        assert!(!PathGuard::is_within(root, Path::new("/home/user")));
        assert!(!PathGuard::is_within(root, Path::new("/home/user/pro")));
        assert!(!PathGuard::is_within(root, Path::new("/other/proj")));
    }

    // -- traversal -----------------------------------------------------------

    #[test]
    fn dot_dot_cannot_escape_the_root() {
        let f = fixture();
        let escape = f.root.join("src").join("..").join("..").join("outside");
        assert_eq!(
            f.guard.resolve(&escape).unwrap_err().reason,
            DenyReason::OutsideRoots
        );
    }

    #[test]
    fn dot_dot_inside_the_root_is_fine() {
        let f = fixture();
        let inside = f.root.join("src").join("..").join("src").join("main.rs");
        let resolved = f.guard.resolve(inside).unwrap();
        assert_eq!(resolved.path(), f.root.join("src").join("main.rs"));
        assert!(resolved.exists());
    }

    #[test]
    fn dot_dot_in_a_missing_tail_is_refused() {
        // `<root>/nope/../../outside`: nothing to canonicalise, and lexically
        // normalising it here would be unsound in the presence of symlinks. So
        // it is refused outright.
        let f = fixture();
        let sneaky = f.root.join("nope").join("..").join("..").join("outside");
        let reason = f.guard.resolve(sneaky).unwrap_err().reason;
        assert!(
            matches!(
                reason,
                DenyReason::TraversalIntoMissingPath | DenyReason::OutsideRoots
            ),
            "unexpected reason {reason:?}"
        );
    }

    #[test]
    fn absolute_paths_outside_every_root_are_refused() {
        let f = fixture();
        assert_eq!(
            f.guard
                .resolve(f.outside.join("id_ed25519"))
                .unwrap_err()
                .reason,
            DenyReason::OutsideRoots
        );
    }

    // -- create-a-new-file ---------------------------------------------------

    #[test]
    fn a_new_file_inside_the_root_resolves() {
        let f = fixture();
        let target = f.root.join("src").join("new_module.rs");
        let resolved = f.guard.resolve(&target).unwrap();
        assert!(!resolved.exists());
        assert_eq!(resolved.path(), target);
        assert_eq!(resolved.root(), f.root);
    }

    #[test]
    fn several_missing_directories_deep_still_resolves_inside_the_root() {
        let f = fixture();
        let target = f.root.join("a").join("b").join("c").join("d.txt");
        let resolved = f.guard.resolve(&target).unwrap();
        assert!(!resolved.exists());
        assert!(PathGuard::is_within(f.root.as_path(), resolved.path()));
    }

    #[test]
    fn a_new_file_outside_the_root_is_refused() {
        let f = fixture();
        assert_eq!(
            f.guard
                .resolve(f.outside.join("planted.txt"))
                .unwrap_err()
                .reason,
            DenyReason::OutsideRoots
        );
    }

    #[test]
    fn resolve_existing_refuses_a_missing_path() {
        let f = fixture();
        assert!(f.guard.resolve(f.root.join("ghost.txt")).is_ok());
        assert!(f.guard.resolve_existing(f.root.join("ghost.txt")).is_err());
    }

    // -- relative joins ------------------------------------------------------

    #[test]
    fn resolve_in_root_accepts_a_relative_path() {
        let f = fixture();
        let root = WorkspaceRoot::new(&f.root).unwrap();
        let resolved = f.guard.resolve_in_root(&root, "src/main.rs").unwrap();
        assert_eq!(resolved.path(), f.root.join("src").join("main.rs"));
    }

    #[test]
    fn resolve_in_root_refuses_an_absolute_path_instead_of_swallowing_the_root() {
        // `Path::join` with an absolute argument throws the base away. If this
        // check were missing, a client could send an absolute path as the
        // "relative" one and reach the entire disk.
        let f = fixture();
        let root = WorkspaceRoot::new(&f.root).unwrap();
        let absolute = f.outside.join("id_ed25519");
        assert_eq!(
            f.guard
                .resolve_in_root(&root, &absolute)
                .unwrap_err()
                .reason,
            DenyReason::NotAbsolute
        );
    }

    #[test]
    fn resolve_in_root_still_denies_traversal_out_of_the_root() {
        let f = fixture();
        let root = WorkspaceRoot::new(&f.root).unwrap();
        assert_eq!(
            f.guard
                .resolve_in_root(&root, Path::new("..").join("outside"))
                .unwrap_err()
                .reason,
            DenyReason::OutsideRoots
        );
    }

    // -- fail closed ---------------------------------------------------------

    #[test]
    fn a_guard_with_no_roots_denies_everything() {
        let f = fixture();
        let guard = PathGuard::new(Vec::new());
        assert_eq!(
            guard
                .resolve(f.root.join("src").join("main.rs"))
                .unwrap_err()
                .reason,
            DenyReason::NoRootsConfigured
        );
    }

    #[test]
    fn a_root_that_does_not_exist_is_rejected_at_construction() {
        let f = fixture();
        assert!(WorkspaceRoot::new(f.root.join("no-such-dir")).is_err());
    }

    // -- Windows name rules --------------------------------------------------

    #[test]
    fn every_reserved_device_name_is_recognised() {
        for name in RESERVED_DEVICE_NAMES {
            assert!(is_reserved_device_name(name), "{name} not recognised");
            assert!(
                is_reserved_device_name(&name.to_lowercase()),
                "lowercase {name} not recognised"
            );
            assert!(
                is_reserved_device_name(&format!("{name}.txt")),
                "{name}.txt not recognised"
            );
            assert!(
                is_reserved_device_name(&format!("{name}.tar.gz")),
                "{name}.tar.gz not recognised"
            );
            assert!(
                is_reserved_device_name(&format!("{name} ")),
                "trailing-space {name} not recognised"
            );
            assert!(
                is_reserved_device_name(&format!("{name}:")),
                "{name}: not recognised"
            );
        }
    }

    #[test]
    fn superscript_device_names_are_recognised() {
        // Win32 folds these to COM1..COM3. A filter that only knows ASCII
        // digits is walked straight past by them.
        assert!(is_reserved_device_name("COM\u{b9}"));
        assert!(is_reserved_device_name("LPT\u{b3}"));
    }

    #[test]
    fn ordinary_names_are_not_mistaken_for_devices() {
        for name in [
            "console",
            "config",
            "com",
            "com10",
            "lpt0",
            "auxiliary",
            "nullable.rs",
            "printer",
            "CONTRIBUTING.md",
        ] {
            assert!(!is_reserved_device_name(name), "{name} wrongly rejected");
        }
    }

    #[test]
    fn reserved_device_names_are_refused_in_a_full_path() {
        let f = fixture();
        for name in ["CON", "con.txt", "NUL", "COM1", "lpt9.log", "AUX"] {
            let denied = f.guard.resolve(f.root.join(name)).unwrap_err();
            assert_eq!(
                denied.reason,
                DenyReason::ReservedDeviceName,
                "{name} was not refused as a device name"
            );
        }
    }

    #[test]
    fn a_reserved_name_in_the_middle_of_a_path_is_refused() {
        let f = fixture();
        let denied = f
            .guard
            .resolve(f.root.join("CON").join("x.txt"))
            .unwrap_err();
        assert_eq!(denied.reason, DenyReason::ReservedDeviceName);
    }

    #[test]
    fn alternate_data_streams_are_refused() {
        let f = fixture();
        for name in ["file.txt:hidden", "notes:$DATA", "secret.pem:0"] {
            assert_eq!(
                f.guard.resolve(f.root.join(name)).unwrap_err().reason,
                DenyReason::AlternateDataStream,
                "{name} was not refused"
            );
        }
        assert!(has_alternate_data_stream("secrets.txt:hidden"));
        assert!(!has_alternate_data_stream("secrets.txt"));

        // A stream name whose first segment is a single letter — `a:b:c` — is
        // parsed by Windows as the *drive-relative* path `b:c` on drive `a:`,
        // and `Path::join` therefore discards the root entirely. It is still
        // refused, by the absolute-path rule rather than the stream rule. Both
        // are asserted, because a future change that made this reach the
        // stream check would also have to have made `join` stop swallowing the
        // root, and that is worth noticing.
        assert!(has_alternate_data_stream("a:b:c"));
        assert!(f.guard.resolve(f.root.join("a:b:c")).is_err());
    }

    #[test]
    fn trailing_dots_and_spaces_are_refused() {
        let f = fixture();
        for name in ["report.", "report ", "secret.txt ", "dir."] {
            assert_eq!(
                f.guard.resolve(f.root.join(name)).unwrap_err().reason,
                DenyReason::TrailingDotOrSpace,
                "{name} was not refused"
            );
        }
        assert!(!has_trailing_dot_or_space(".env"));
        assert!(!has_trailing_dot_or_space("normal.txt"));
    }

    #[test]
    fn the_windows_rules_can_be_switched_off_deliberately() {
        let f = fixture();
        let lax = PathGuard::with_options(
            vec![WorkspaceRoot::new(&f.root).unwrap()],
            GuardOptions {
                windows_name_rules: false,
                allow_unc: false,
            },
        );
        // Still refused on Windows by the OS itself, but the *policy* layer no
        // longer objects, which is the contract of the flag.
        let result = lax.resolve(f.root.join("weird:name"));
        assert!(
            result.is_ok() || result.unwrap_err().reason != DenyReason::AlternateDataStream,
            "the flag did not disable the ADS rule"
        );
    }

    // -- prefixes ------------------------------------------------------------

    #[test]
    #[cfg(windows)]
    fn verbatim_prefixes_are_refused() {
        let f = fixture();
        let verbatim = format!("\\\\?\\{}", f.root.join("src").join("main.rs").display());
        assert_eq!(
            f.guard.resolve(&verbatim).unwrap_err().reason,
            DenyReason::VerbatimPrefix
        );
        // And the device namespace, which reaches \Device\... directly.
        assert_eq!(
            f.guard.resolve("\\\\.\\PhysicalDrive0").unwrap_err().reason,
            DenyReason::VerbatimPrefix
        );
    }

    #[test]
    #[cfg(windows)]
    fn unc_paths_are_refused_when_no_unc_root_is_configured() {
        let f = fixture();
        assert_eq!(
            f.guard
                .resolve("\\\\attacker\\share\\payload.dll")
                .unwrap_err()
                .reason,
            DenyReason::UncNotConfigured
        );
    }

    #[test]
    #[cfg(windows)]
    fn allowing_unc_without_a_unc_root_still_refuses() {
        // Both locks must be open: the flag *and* a configured UNC root.
        let f = fixture();
        let guard = PathGuard::with_options(
            vec![WorkspaceRoot::new(&f.root).unwrap()],
            GuardOptions {
                windows_name_rules: true,
                allow_unc: true,
            },
        );
        assert_eq!(
            guard
                .resolve("\\\\attacker\\share\\payload.dll")
                .unwrap_err()
                .reason,
            DenyReason::UncNotConfigured
        );
    }

    #[test]
    fn relative_paths_are_refused() {
        let f = fixture();
        for p in ["src/main.rs", "./main.rs", "../outside"] {
            assert_eq!(
                f.guard.resolve(p).unwrap_err().reason,
                DenyReason::NotAbsolute,
                "{p} was not refused"
            );
        }
    }

    // -- malformed input -----------------------------------------------------

    #[test]
    fn null_bytes_are_refused() {
        let f = fixture();
        let mut evil = f
            .root
            .join("src")
            .join("main.rs")
            .to_string_lossy()
            .into_owned();
        evil.push('\0');
        evil.push_str("/../../outside/id_ed25519");
        assert_eq!(
            f.guard.resolve(&evil).unwrap_err().reason,
            DenyReason::NullByte
        );
    }

    #[test]
    #[cfg(unix)]
    fn non_utf8_paths_are_refused() {
        use std::os::unix::ffi::OsStrExt;
        let f = fixture();
        let raw = std::ffi::OsStr::from_bytes(b"/tmp/\xff\xfe");
        assert_eq!(
            f.guard.resolve(Path::new(raw)).unwrap_err().reason,
            DenyReason::NotUtf8
        );
    }

    #[test]
    fn absurdly_long_paths_are_refused() {
        let f = fixture();
        let long = f.root.join("a".repeat(MAX_PATH_BYTES + 1));
        assert_eq!(
            f.guard.resolve(long).unwrap_err().reason,
            DenyReason::TooLong
        );
    }

    #[test]
    fn absurdly_deep_paths_are_refused() {
        let f = fixture();
        let mut deep = f.root.clone();
        for _ in 0..=MAX_PATH_COMPONENTS {
            deep.push("a");
        }
        let reason = f.guard.resolve(deep).unwrap_err().reason;
        assert!(
            matches!(reason, DenyReason::TooManyComponents | DenyReason::TooLong),
            "unexpected reason {reason:?}"
        );
    }

    // -- symlinks ------------------------------------------------------------

    /// Creates a directory symlink, returning `false` when the platform refuses
    /// (Windows without Developer Mode or `SeCreateSymbolicLinkPrivilege`).
    fn try_symlink_dir(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
        #[cfg(windows)]
        {
            // Fall back to a junction, which needs no privilege. Without the
            // fallback these tests would silently skip on the first-class
            // host, which is the worst possible place for them to skip.
            std::os::windows::fs::symlink_dir(target, link).is_ok() || try_junction(target, link)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            false
        }
    }

    fn try_symlink_file(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link).is_ok()
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            false
        }
    }

    /// Creates a Windows directory junction, returning `false` if `mklink`
    /// is unavailable.
    ///
    /// Junctions matter more than symlinks on Windows in practice: creating one
    /// needs **no** special privilege and no Developer Mode, so it is the
    /// reparse point an unprivileged local attacker actually has available.
    /// Created by shelling out to `mklink /J` because the Win32 call needs
    /// `unsafe`, which this crate forbids.
    #[cfg(windows)]
    fn try_junction(target: &Path, link: &Path) -> bool {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .is_ok_and(|out| out.status.success())
    }

    #[test]
    #[cfg(windows)]
    fn a_junction_pointing_out_of_the_root_is_refused() {
        let f = fixture();
        let junction = f.root.join("linked");
        if !try_junction(&f.outside, &junction) {
            eprintln!("skipping: mklink unavailable");
            return;
        }
        assert_eq!(
            f.guard
                .resolve(junction.join("id_ed25519"))
                .unwrap_err()
                .reason,
            DenyReason::OutsideRoots
        );
        // ...and a file that does not exist yet behind the junction is refused
        // too, so the create-a-new-file path cannot be used to plant one
        // outside the root.
        assert_eq!(
            f.guard
                .resolve(junction.join("planted.txt"))
                .unwrap_err()
                .reason,
            DenyReason::OutsideRoots
        );
    }

    #[test]
    #[cfg(windows)]
    fn a_junction_staying_inside_the_root_is_allowed() {
        let f = fixture();
        let junction = f.root.join("shortcut-j");
        if !try_junction(&f.root.join("src"), &junction) {
            eprintln!("skipping: mklink unavailable");
            return;
        }
        let resolved = f.guard.resolve(junction.join("main.rs")).unwrap();
        assert_eq!(resolved.path(), f.root.join("src").join("main.rs"));
    }

    #[test]
    fn a_symlink_pointing_out_of_the_root_is_refused() {
        let f = fixture();
        let link = f.root.join("escape");
        if !try_symlink_dir(&f.outside, &link) {
            eprintln!("skipping: symlink creation not permitted on this host");
            return;
        }
        assert_eq!(
            f.guard.resolve(link.join("id_ed25519")).unwrap_err().reason,
            DenyReason::OutsideRoots
        );
    }

    #[test]
    fn a_symlinked_file_pointing_out_of_the_root_is_refused() {
        let f = fixture();
        let link = f.root.join("key.pem");
        if !try_symlink_file(&f.outside.join("id_ed25519"), &link) {
            eprintln!("skipping: symlink creation not permitted on this host");
            return;
        }
        assert_eq!(
            f.guard.resolve(&link).unwrap_err().reason,
            DenyReason::OutsideRoots
        );
    }

    #[test]
    fn nested_symlinks_are_followed_all_the_way_out() {
        let f = fixture();
        let hop = f.root.join("hop");
        let jump = f.root.join("jump");
        if !try_symlink_dir(&f.outside, &hop) || !try_symlink_dir(&hop, &jump) {
            eprintln!("skipping: symlink creation not permitted on this host");
            return;
        }
        assert_eq!(
            f.guard.resolve(jump.join("id_ed25519")).unwrap_err().reason,
            DenyReason::OutsideRoots
        );
    }

    #[test]
    fn a_symlink_staying_inside_the_root_is_allowed() {
        let f = fixture();
        let link = f.root.join("shortcut");
        if !try_symlink_dir(&f.root.join("src"), &link) {
            eprintln!("skipping: symlink creation not permitted on this host");
            return;
        }
        let resolved = f.guard.resolve(link.join("main.rs")).unwrap();
        assert_eq!(resolved.path(), f.root.join("src").join("main.rs"));
    }

    #[test]
    fn a_dangling_symlink_is_refused_rather_than_treated_as_a_new_file() {
        // The dangerous alternative: treat it as "does not exist", trim it, and
        // validate the *name* against the roots — while the eventual open
        // follows the link to wherever it points.
        let f = fixture();
        let link = f.root.join("dangling");
        if !try_symlink_file(&f.outside.join("never-created"), &link) {
            eprintln!("skipping: symlink creation not permitted on this host");
            return;
        }
        assert_eq!(
            f.guard.resolve(&link).unwrap_err().reason,
            DenyReason::UnresolvableAncestor
        );
    }

    // -- case sensitivity ----------------------------------------------------

    #[test]
    fn case_only_differences_behave_as_the_host_filesystem_does() {
        let f = fixture();
        let shouted = f.root.join("SRC").join("MAIN.RS");
        let result = f.guard.resolve(shouted);
        if cfg!(windows) {
            // Same file on NTFS, so it must resolve — and must land inside the
            // root, which is the invariant that actually matters.
            let resolved = result.expect("windows resolves case-insensitively");
            assert!(PathGuard::is_within(f.root.as_path(), resolved.path()));
        } else {
            // A different (missing) path on Linux. Either way it must not
            // escape: it resolves inside the root, or it is denied.
            match result {
                Ok(resolved) => {
                    assert!(PathGuard::is_within(f.root.as_path(), resolved.path()));
                }
                Err(denied) => assert!(!matches!(denied.reason, DenyReason::NotUtf8)),
            }
        }
    }

    #[test]
    #[cfg(not(windows))]
    fn case_insensitive_matching_is_off_on_case_sensitive_hosts() {
        // If it were on, root `/home/user/proj` would cover `/home/user/PROJ`,
        // which is a different directory that was never granted.
        assert!(!PathGuard::is_within(
            Path::new("/home/user/proj"),
            Path::new("/home/user/PROJ/secret")
        ));
    }

    // -- multiple roots ------------------------------------------------------

    #[test]
    fn each_configured_root_is_reachable_and_nothing_else_is() {
        let dir = TempDir::new().unwrap();
        let base = dunce::canonicalize(dir.path()).unwrap();
        let a = base.join("a");
        let b = base.join("b");
        let c = base.join("c");
        for p in [&a, &b, &c] {
            fs::create_dir_all(p).unwrap();
        }
        let guard = PathGuard::new(vec![
            WorkspaceRoot::new(&a).unwrap(),
            WorkspaceRoot::new(&b).unwrap(),
        ]);
        assert_eq!(guard.resolve(a.join("f")).unwrap().root(), a);
        assert_eq!(guard.resolve(b.join("f")).unwrap().root(), b);
        assert_eq!(
            guard.resolve(c.join("f")).unwrap_err().reason,
            DenyReason::OutsideRoots
        );
    }

    #[test]
    fn the_root_itself_resolves() {
        let f = fixture();
        let resolved = f.guard.resolve(&f.root).unwrap();
        assert_eq!(resolved.path(), f.root);
        assert!(resolved.exists());
    }

    #[test]
    fn the_parent_of_a_root_is_not_reachable() {
        let f = fixture();
        assert_eq!(
            f.guard
                .resolve(f.root.parent().unwrap())
                .unwrap_err()
                .reason,
            DenyReason::OutsideRoots
        );
    }

    // -- error mapping -------------------------------------------------------

    #[test]
    fn location_failures_are_indistinguishable_on_the_wire() {
        // A client must not be able to tell "outside your root" from "does not
        // exist", or it can map the filesystem one probe at a time.
        for reason in [
            DenyReason::OutsideRoots,
            DenyReason::UncNotConfigured,
            DenyReason::NoRootsConfigured,
            DenyReason::UnresolvableAncestor,
            DenyReason::TraversalIntoMissingPath,
        ] {
            assert_eq!(reason.to_proto_error().kind.code(), "not_found");
        }
    }

    #[test]
    fn malformed_names_are_reported_as_bad_requests() {
        for reason in [
            DenyReason::NullByte,
            DenyReason::NotUtf8,
            DenyReason::ReservedDeviceName,
            DenyReason::AlternateDataStream,
            DenyReason::TrailingDotOrSpace,
            DenyReason::VerbatimPrefix,
            DenyReason::NotAbsolute,
            DenyReason::TooLong,
            DenyReason::TooManyComponents,
        ] {
            assert_eq!(reason.to_proto_error().kind.code(), "bad_request");
        }
    }

    #[test]
    fn the_wire_error_never_carries_the_reason() {
        // The audit log gets the detail; the phone gets "invalid path".
        let err = DenyReason::ReservedDeviceName.to_proto_error();
        assert!(!format!("{err}").contains("reserved"));
    }

    #[test]
    fn deny_reason_codes_are_unique() {
        let all = [
            DenyReason::NotUtf8,
            DenyReason::NullByte,
            DenyReason::TooLong,
            DenyReason::TooManyComponents,
            DenyReason::NotAbsolute,
            DenyReason::ReservedDeviceName,
            DenyReason::AlternateDataStream,
            DenyReason::TrailingDotOrSpace,
            DenyReason::VerbatimPrefix,
            DenyReason::UncNotConfigured,
            DenyReason::NoRootsConfigured,
            DenyReason::UnresolvableAncestor,
            DenyReason::TraversalIntoMissingPath,
            DenyReason::OutsideRoots,
        ];
        let mut codes: Vec<&str> = all.iter().map(|r| r.code()).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len());
    }

    // -- TOCTOU hook ---------------------------------------------------------

    #[test]
    fn confirm_identity_rejects_a_swapped_object() {
        let f = fixture();
        let resolved = f
            .guard
            .resolve(f.root.join("src").join("main.rs"))
            .unwrap()
            .with_expected_identity(FileIdentity::new(1, 42));
        assert!(resolved.confirm_identity(FileIdentity::new(1, 42)).is_ok());
        // Same volume, different object: the file was replaced between the
        // check and the open.
        assert!(resolved.confirm_identity(FileIdentity::new(1, 43)).is_err());
        // Same object number on a different volume: a junction to another disk.
        assert!(resolved.confirm_identity(FileIdentity::new(2, 42)).is_err());
    }

    #[test]
    fn confirm_identity_is_a_documented_no_op_without_an_expectation() {
        let f = fixture();
        let resolved = f.guard.resolve(f.root.join("src").join("main.rs")).unwrap();
        assert_eq!(resolved.expected_identity(), None);
        assert!(resolved.confirm_identity(FileIdentity::new(9, 9)).is_ok());
    }

    #[test]
    fn a_mismatched_identity_looks_like_not_found_on_the_wire() {
        let f = fixture();
        let resolved = f
            .guard
            .resolve(f.root.join("src").join("main.rs"))
            .unwrap()
            .with_expected_identity(FileIdentity::new(1, 1));
        let err = resolved
            .confirm_identity(FileIdentity::new(1, 2))
            .unwrap_err();
        assert_eq!(err.kind.code(), "not_found");
    }

    // -- generative ----------------------------------------------------------

    mod generative {
        use super::*;
        use proptest::prelude::*;

        /// Component fragments chosen to be adversarial: traversals, mixed
        /// separators, Windows device names, stream separators, trailing dots
        /// and spaces, unicode, and case variants of real directories.
        fn hostile_component() -> impl Strategy<Value = String> {
            prop_oneof![
                Just("..".to_owned()),
                Just(".".to_owned()),
                Just("...".to_owned()),
                Just("..\\..".to_owned()),
                Just("../..".to_owned()),
                Just("src".to_owned()),
                Just("SRC".to_owned()),
                Just("Src".to_owned()),
                Just("main.rs".to_owned()),
                Just("MAIN.RS".to_owned()),
                Just("proj-evil".to_owned()),
                Just("outside".to_owned()),
                Just("CON".to_owned()),
                Just("con.txt".to_owned()),
                Just("NUL".to_owned()),
                Just("COM1".to_owned()),
                Just("LPT9.log".to_owned()),
                Just("a:b".to_owned()),
                Just("file.txt:hidden".to_owned()),
                Just("trailing.".to_owned()),
                Just("trailing ".to_owned()),
                Just(" leading".to_owned()),
                Just("\u{00e9}\u{4e16}\u{754c}".to_owned()),
                Just("\u{0301}combining".to_owned()),
                Just("~".to_owned()),
                Just("$MFT".to_owned()),
                Just("%SYSTEMROOT%".to_owned()),
                Just("nonexistent".to_owned()),
                "[a-zA-Z0-9._-]{1,12}",
                "[\\PC]{1,8}",
            ]
        }

        fn hostile_path() -> impl Strategy<Value = Vec<String>> {
            prop::collection::vec(hostile_component(), 0..12)
        }

        // Two blocks, because the case count is per block and these tests do
        // not cost the same: the filesystem-backed ones build a real directory
        // tree per case, the pure ones do not.
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// The single invariant this whole module exists to uphold.
            #[test]
            fn no_generated_path_ever_resolves_outside_a_root(parts in hostile_path()) {
                let f = fixture();
                // Both separators, so mixed-separator inputs are exercised on
                // Windows and treated as literal component text on Unix.
                for separator in ["/", "\\"] {
                    let joined = parts.join(separator);
                    let mut candidate = f.root.to_string_lossy().into_owned();
                    candidate.push_str(separator);
                    candidate.push_str(&joined);

                    if let Ok(resolved) = f.guard.resolve(&candidate) {
                        prop_assert!(
                            PathGuard::is_within(resolved.root(), resolved.path()),
                            "resolved {:?} is not within its own root {:?}",
                            resolved.path(),
                            resolved.root()
                        );
                        prop_assert!(
                            f.guard
                                .roots()
                                .iter()
                                .any(|r| PathGuard::is_within(r.canonical(), resolved.path())),
                            "resolved {:?} escaped every configured root (input {:?})",
                            resolved.path(),
                            candidate
                        );
                        // And specifically: never the sibling that shares a
                        // string prefix with the root.
                        prop_assert!(
                            !PathGuard::is_within(
                                &f.root.with_file_name("proj-evil"),
                                resolved.path()
                            ),
                            "resolved into the prefix-attack sibling: {:?}",
                            resolved.path()
                        );
                    }
                }
            }

            /// Same invariant, but the path is built from an *arbitrary* prefix
            /// rather than from the root — nothing outside may ever be accepted.
            #[test]
            fn arbitrary_absolute_paths_never_resolve_inside(
                parts in hostile_path(),
                use_root in any::<bool>(),
            ) {
                let f = fixture();
                let base = if use_root { f.outside.clone() } else { f.root.with_file_name("proj-evil") };
                let mut candidate = base.to_string_lossy().into_owned();
                for part in &parts {
                    candidate.push(std::path::MAIN_SEPARATOR);
                    candidate.push_str(part);
                }
                if let Ok(resolved) = f.guard.resolve(&candidate) {
                    prop_assert!(
                        PathGuard::is_within(f.root.as_path(), resolved.path()),
                        "accepted {:?} which resolved to {:?}, outside the root",
                        candidate,
                        resolved.path()
                    );
                }
            }
        }

        // Its own block for its own case count: planting and then tearing down
        // a chain of real symlinks costs roughly a hundred times what a plain
        // resolve does, and the interesting variation — depth and chain length
        // — has only a dozen distinct shapes to explore.
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(48))]

            /// Symlinks built at random depths inside the tree never widen it.
            #[test]
            fn planted_symlinks_never_widen_the_root(depth in 0usize..4, hops in 1usize..4) {
                let f = fixture();
                let mut here = f.root.clone();
                for i in 0..depth {
                    here = here.join(format!("d{i}"));
                    if fs::create_dir_all(&here).is_err() {
                        return Ok(());
                    }
                }
                // A chain of links ending outside the root.
                let mut previous = f.outside.clone();
                for hop in 0..hops {
                    let link = here.join(format!("hop{hop}"));
                    if !try_symlink_dir(&previous, &link) {
                        return Ok(());
                    }
                    previous = link;
                }
                if let Ok(resolved) = f.guard.resolve(previous.join("id_ed25519")) {
                    prop_assert!(
                        PathGuard::is_within(f.root.as_path(), resolved.path()),
                        "a symlink chain reached {:?}",
                        resolved.path()
                    );
                }
            }
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(2048))]

            /// A guard with no roots is unconditionally closed.
            #[test]
            fn a_rootless_guard_never_accepts_anything(parts in hostile_path()) {
                let guard = PathGuard::new(Vec::new());
                let candidate = parts.join(std::path::MAIN_SEPARATOR_STR);
                let unix_absolute = format!("/{candidate}");
                let windows_absolute = format!("C:\\{candidate}");
                prop_assert!(guard.resolve(&candidate).is_err());
                prop_assert!(guard.resolve(&unix_absolute).is_err());
                prop_assert!(guard.resolve(&windows_absolute).is_err());
            }

            /// Containment is never satisfied by a shared string prefix.
            #[test]
            fn string_prefixes_never_imply_containment(
                stem in "[a-z]{1,8}",
                suffix in "[a-z-]{1,8}",
            ) {
                let root = PathBuf::from(format!("/base/{stem}"));
                let sibling = PathBuf::from(format!("/base/{stem}{suffix}"));
                prop_assume!(sibling != root);
                prop_assert!(sibling.to_string_lossy().starts_with(&*root.to_string_lossy()));
                prop_assert!(!PathGuard::is_within(&root, &sibling));
            }

            /// Containment holds for any genuine descendant, at any depth.
            #[test]
            fn genuine_descendants_are_always_contained(
                root_parts in prop::collection::vec("[a-z]{1,6}", 1..5),
                extra in prop::collection::vec("[a-z]{1,6}", 0..5),
            ) {
                let root = PathBuf::from(format!("/{}", root_parts.join("/")));
                let mut child = root.clone();
                for part in &extra {
                    child.push(part);
                }
                prop_assert!(PathGuard::is_within(&root, &child));
            }

            /// The syntactic rules never panic and never disagree with
            /// themselves, whatever text they are handed.
            #[test]
            fn syntactic_checks_are_total(name in "[\\PC]{0,32}") {
                let reserved = is_reserved_device_name(&name);
                let ads = has_alternate_data_stream(&name);
                let trailing = has_trailing_dot_or_space(&name);
                // Idempotent: the same input always gives the same answer.
                prop_assert_eq!(reserved, is_reserved_device_name(&name));
                prop_assert_eq!(ads, has_alternate_data_stream(&name));
                prop_assert_eq!(trailing, has_trailing_dot_or_space(&name));
                // A name Windows would fold onto a device is caught however it
                // is dressed up with extensions, spaces, and case.
                if reserved {
                    let shouted = name.to_uppercase();
                    let with_extension = format!("{name}.log");
                    prop_assert!(is_reserved_device_name(&shouted));
                    prop_assert!(is_reserved_device_name(&with_extension));
                }
            }
        }
    }
}
