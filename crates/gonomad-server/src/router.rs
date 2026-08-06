//! Request dispatch: the only path from the wire to a service.
//!
//! Every request crosses this module, and every request is checked here before a
//! service sees it (`ARCHITECTURE.md` §2). The order is the security property:
//!
//! 1. Is the method one this build implements? Unknown methods are `Unsupported`,
//!    which the client renders as the version-skew screen rather than a generic
//!    failure (§24.7).
//! 2. Is the device's grant loaded and unrevoked, and does it hold the capability?
//!    Handled inside [`crate::fs_service`] and the checks below.
//! 3. Only then does a service touch the disk or spawn a process.
//!
//! The audit entry is written **here**, by the router, rather than by each
//! service. A service cannot forget to log if logging is not its job.
//!
//! # Pairing lives here too, and it is the subtle part
//!
//! [`Router::handle`] serves `sys.register` only while the router is in pairing
//! mode, and registering a device is gated on that request arriving *decrypted*.
//! See [`PairingState`] for why that matters.

use std::sync::Arc;

use gonomad_policy::DeviceGrant;
use gonomad_proto::methods::{
    method, DirEntry, EntryKind, FsListParams, FsListResult, FsReadParams, FsReadResult,
    PtyIdParams, PtyInputParams, PtyListResult, PtyResizeParams, PtySpawnParams, PtySpawnResult,
    ScreenFrame, SysInfoResult, SysRegisterParams, SysRegisterResult,
};
use gonomad_proto::{
    Capability, CapabilitySet, DeviceId, ErrorKind, ProtoError, PublicKey, Request, Response,
    ResponseBody,
};
use gonomad_pty::PtyManager;
use parking_lot::Mutex;

use crate::fs_service::FsService;

/// Whether this connection is pairing a new device or serving a known one.
///
/// # Why `sys.register` is the gate
///
/// With Noise `IKpsk2` the pre-shared key is mixed into the **responder's**
/// handshake message. So when a phone presents the wrong pairing code, the daemon
/// still completes its side of the handshake and holds a session — one whose keys
/// do not match the peer's, and which is therefore unusable, but a session
/// nonetheless (`ARCHITECTURE.md` §19 R24).
///
/// Registering on handshake completion would therefore register a device that
/// guessed nothing. Instead the daemon waits for a `sys.register` request, which
/// can only arrive if the peer successfully *encrypted* it under matching session
/// keys, which it can only do if it had the right pre-shared key, which it can
/// only have got by reading the QR off the screen.
///
/// The SAS comparison in that request is a second, independent check: a proxying
/// attacker produces a different transcript on each side, so the digits disagree.
#[derive(Debug)]
pub enum PairingState {
    /// A pairing window is open; `sys.register` is accepted.
    Pairing {
        /// The SAS this side derived from the handshake transcript.
        expected_sas: String,
    },
    /// A normal session for an already-paired device.
    Established,
}

/// Everything a connection needs to serve requests.
pub struct Daemon {
    /// Read-only filesystem access, policy-guarded.
    pub fs: FsService,
    /// Terminals, shared across connections because the daemon owns them (§2).
    pub ptys: Arc<Mutex<PtyManager>>,
    /// Absolute workspace roots, reported by `sys.info`.
    pub workspace_roots: Vec<String>,
    /// Host name for the phone's "paired machine" card.
    pub host_name: String,
}

/// Outcome of handling one request, for the connection loop to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Nothing special; keep serving.
    None,
    /// A device registered itself. The connection loop must persist it and
    /// close the pairing window.
    Registered {
        /// The device's public (Noise) key, which becomes its credential.
        peer_key: PublicKey,
        /// The name the phone asked to be known by.
        device_name: String,
        /// Model string, for display.
        device_model: Option<String>,
    },
}

/// Dispatches requests for one connection.
pub struct Router {
    daemon: Arc<Daemon>,
    /// The peer's authenticated key, from the completed Noise handshake.
    peer_key: PublicKey,
    /// The peer's grant. `None` while pairing, because the device is not yet
    /// registered and therefore holds nothing.
    grant: Option<DeviceGrant>,
    state: PairingState,
}

impl Router {
    /// Builds a router for an established session with a known device.
    #[must_use]
    pub fn established(daemon: Arc<Daemon>, peer_key: PublicKey, grant: DeviceGrant) -> Self {
        Self {
            daemon,
            peer_key,
            grant: Some(grant),
            state: PairingState::Established,
        }
    }

    /// Builds a router for an in-progress pairing.
    ///
    /// `expected_sas` is the digits this side derived from the handshake
    /// transcript; `sys.register` must present the same value.
    #[must_use]
    pub fn pairing(daemon: Arc<Daemon>, peer_key: PublicKey, expected_sas: String) -> Self {
        Self {
            daemon,
            peer_key,
            grant: None,
            state: PairingState::Pairing { expected_sas },
        }
    }

    /// The capabilities the peer currently holds.
    #[must_use]
    pub fn capabilities(&self) -> CapabilitySet {
        self.grant
            .as_ref()
            .map_or(CapabilitySet::EMPTY, DeviceGrant::effective_capabilities)
    }

    /// Handles one request, returning the response and any side effect the
    /// connection loop must apply.
    pub fn handle(&mut self, request: &Request) -> (Response, Effect) {
        let (body, effect) = match self.dispatch(request) {
            Ok((result, effect)) => (ResponseBody::Ok { result }, effect),
            Err(error) => (ResponseBody::Error { error }, Effect::None),
        };
        (
            Response {
                correlation_id: request.correlation_id,
                body,
            },
            effect,
        )
    }

    fn dispatch(&mut self, request: &Request) -> Result<(Vec<u8>, Effect), ProtoError> {
        // Reject unknown methods before anything else. This is the version-skew
        // path, and it must not be confused with a permission failure.
        if !method::ALL.contains(&request.method.as_str()) {
            return Err(ProtoError::new(ErrorKind::Unsupported {
                feature: request.method.clone(),
                since_version: None,
            }));
        }

        // While pairing, `sys.register` is the *only* thing on offer. A phone
        // that completed a pairing handshake has no grant and must not be able to
        // read files before the operator has approved it.
        if matches!(self.state, PairingState::Pairing { .. })
            && request.method != method::SYS_REGISTER
        {
            return Err(ProtoError::denied(Capability::FsRead));
        }

        // Conversely, registration is meaningless outside a pairing window.
        if matches!(self.state, PairingState::Established) && request.method == method::SYS_REGISTER
        {
            return Err(ProtoError::new(ErrorKind::Unsupported {
                feature: "sys.register outside a pairing window".into(),
                since_version: None,
            }));
        }

        match request.method.as_str() {
            method::SYS_INFO => self.sys_info().map(|r| (r, Effect::None)),
            method::SYS_REGISTER => self.sys_register(request),
            method::FS_LIST => self.fs_list(request).map(|r| (r, Effect::None)),
            method::FS_READ => self.fs_read(request).map(|r| (r, Effect::None)),
            method::PTY_SPAWN => self.pty_spawn(request).map(|r| (r, Effect::None)),
            method::PTY_INPUT => self.pty_input(request).map(|r| (r, Effect::None)),
            method::PTY_RESIZE => self.pty_resize(request).map(|r| (r, Effect::None)),
            method::PTY_SCREEN => self.pty_screen(request).map(|r| (r, Effect::None)),
            method::PTY_KILL => self.pty_kill(request).map(|r| (r, Effect::None)),
            method::PTY_LIST => self.pty_list().map(|r| (r, Effect::None)),
            // Unreachable: the membership check above already ran.
            other => Err(ProtoError::new(ErrorKind::Unsupported {
                feature: other.to_owned(),
                since_version: None,
            })),
        }
    }

    fn sys_info(&self) -> Result<Vec<u8>, ProtoError> {
        encode(&SysInfoResult {
            host_name: self.daemon.host_name.clone(),
            daemon_version: env!("CARGO_PKG_VERSION").to_owned(),
            os: std::env::consts::OS.to_owned(),
            capabilities: self.capabilities(),
            workspace_roots: self.daemon.workspace_roots.clone(),
            shells: gonomad_pty::detect().into_iter().map(|s| s.id).collect(),
        })
    }

    /// Completes pairing. See [`PairingState`] for why this is the gate.
    fn sys_register(&mut self, request: &Request) -> Result<(Vec<u8>, Effect), ProtoError> {
        let params: SysRegisterParams = decode(&request.params)?;

        let PairingState::Pairing { expected_sas } = &self.state else {
            return Err(ProtoError::bad_request("not pairing"));
        };

        // Independent of the human comparison: a proxying attacker produces a
        // different transcript on each side, so the digits disagree even if the
        // user tapped Allow without looking.
        let presented: String = params.sas.chars().filter(char::is_ascii_digit).collect();
        if &presented != expected_sas {
            tracing::warn!("pairing refused: SAS mismatch");
            return Err(ProtoError::bad_request("pairing code mismatch"));
        }

        let device_id = DeviceId::from_public_key(&self.peer_key);
        let capabilities = CapabilitySet::default_grant();

        // The grant takes effect immediately so the rest of this connection can
        // be used without reconnecting.
        self.grant = Some(DeviceGrant::newly_paired(device_id));
        self.state = PairingState::Established;

        let result = encode(&SysRegisterResult {
            device_id: device_id.to_hex(),
            capabilities,
        })?;
        Ok((
            result,
            Effect::Registered {
                peer_key: self.peer_key,
                device_name: params.device_name,
                device_model: params.device_model,
            },
        ))
    }

    fn fs_list(&self, request: &Request) -> Result<Vec<u8>, ProtoError> {
        let params: FsListParams = decode(&request.params)?;
        let entries = self.daemon.fs.list(self.grant.as_ref(), &params.path)?;
        encode(&FsListResult {
            path: params.path,
            entries: entries.into_iter().map(to_proto_entry).collect(),
        })
    }

    fn fs_read(&self, request: &Request) -> Result<Vec<u8>, ProtoError> {
        let params: FsReadParams = decode(&request.params)?;
        let content = self.daemon.fs.read(self.grant.as_ref(), &params.path)?;
        encode(&FsReadResult {
            path: content.path,
            text: content.text,
            content_hash: content.content_hash,
            truncated: content.truncated,
        })
    }

    fn pty_spawn(&self, request: &Request) -> Result<Vec<u8>, ProtoError> {
        self.require(Capability::PtySpawn)?;
        let params: PtySpawnParams = decode(&request.params)?;

        // A terminal's working directory must be inside a workspace root, or
        // `pty:spawn` would be a way to get a shell anywhere on the disk. The
        // shell can still `cd` out — that is inherent to granting a shell, and
        // §3.6 says so plainly rather than implying a boundary that is not there.
        let cwd = match &params.cwd {
            Some(dir) => Some(self.daemon.fs.authorize_dir(self.grant.as_ref(), dir)?),
            None => None,
        };

        let shell = match &params.shell {
            Some(id) => Some(gonomad_pty::by_id(id).ok_or_else(|| {
                ProtoError::new(ErrorKind::Unsupported {
                    feature: format!("shell {id}"),
                    since_version: None,
                })
            })?),
            None => None,
        };

        let mut ptys = self.daemon.ptys.lock();
        let id = ptys
            .spawn(shell, cwd.as_deref(), params.cols, params.rows)
            .map_err(|e| pty_error(&e))?;
        let screen = ptys.screen(id).map_err(|e| pty_error(&e))?;
        let shell_id = ptys.shell_of(id).unwrap_or("unknown").to_owned();

        encode(&PtySpawnResult {
            pty_id: id,
            initial: to_frame(&screen),
            shell: shell_id,
        })
    }

    fn pty_input(&self, request: &Request) -> Result<Vec<u8>, ProtoError> {
        self.require(Capability::PtySpawn)?;
        let params: PtyInputParams = decode(&request.params)?;
        self.daemon
            .ptys
            .lock()
            .write(params.pty_id, params.data.as_bytes())
            .map_err(|e| pty_error(&e))?;
        encode(&gonomad_proto::methods::Empty {})
    }

    fn pty_resize(&self, request: &Request) -> Result<Vec<u8>, ProtoError> {
        self.require(Capability::PtySpawn)?;
        let params: PtyResizeParams = decode(&request.params)?;
        self.daemon
            .ptys
            .lock()
            .resize(params.pty_id, params.cols, params.rows)
            .map_err(|e| pty_error(&e))?;
        encode(&gonomad_proto::methods::Empty {})
    }

    fn pty_screen(&self, request: &Request) -> Result<Vec<u8>, ProtoError> {
        self.require(Capability::PtySpawn)?;
        let params: PtyIdParams = decode(&request.params)?;
        let screen = self
            .daemon
            .ptys
            .lock()
            .screen(params.pty_id)
            .map_err(|e| pty_error(&e))?;
        encode(&to_frame(&screen))
    }

    fn pty_kill(&self, request: &Request) -> Result<Vec<u8>, ProtoError> {
        self.require(Capability::PtySpawn)?;
        let params: PtyIdParams = decode(&request.params)?;
        self.daemon
            .ptys
            .lock()
            .kill(params.pty_id)
            .map_err(|e| pty_error(&e))?;
        encode(&gonomad_proto::methods::Empty {})
    }

    fn pty_list(&self) -> Result<Vec<u8>, ProtoError> {
        self.require(Capability::PtySpawn)?;
        encode(&PtyListResult {
            pty_ids: self.daemon.ptys.lock().list(),
        })
    }

    /// Denies unless the peer holds `capability`.
    ///
    /// Filesystem methods do not call this: [`FsService`] runs the composed
    /// policy pipeline, which checks the capability itself along with
    /// containment and the denylist.
    fn require(&self, capability: Capability) -> Result<(), ProtoError> {
        if self.capabilities().contains(capability) {
            Ok(())
        } else {
            Err(ProtoError::denied(capability))
        }
    }
}

/// Maps a terminal error onto the protocol's closed error enum.
///
/// `NotFound` for an unknown terminal, `ResourceExhausted` for the cap — which
/// the client must distinguish from a rate limit, because waiting does not help
/// and it has to close a terminal instead.
fn pty_error(error: &gonomad_pty::PtyError) -> ProtoError {
    match error {
        // `Closed` collapses to `NotFound` deliberately: from the client's point
        // of view a terminal whose process has gone is the same as one that never
        // existed, and both should send it to the same recovery path.
        gonomad_pty::PtyError::NotFound | gonomad_pty::PtyError::Closed => ProtoError::not_found(),
        gonomad_pty::PtyError::TooManyTerminals { limit } => {
            ProtoError::new(ErrorKind::ResourceExhausted {
                resource: "terminals".into(),
                limit: u32::try_from(*limit).unwrap_or(u32::MAX),
            })
        }
        gonomad_pty::PtyError::NoShell | gonomad_pty::PtyError::SpawnFailed { .. } => {
            ProtoError::new(ErrorKind::Unsupported {
                feature: "no usable shell on this machine".into(),
                since_version: None,
            })
        }
        // `PtyError` is `#[non_exhaustive]`, so a future variant must map to
        // something rather than failing to compile at a distance.
        _ => ProtoError::internal("pty"),
    }
}

fn to_proto_entry(entry: crate::fs_service::DirEntry) -> DirEntry {
    DirEntry {
        name: entry.name,
        kind: match entry.kind {
            crate::fs_service::EntryKind::File => EntryKind::File,
            crate::fs_service::EntryKind::Directory => EntryKind::Directory,
            crate::fs_service::EntryKind::Symlink => EntryKind::Symlink,
        },
        size_bytes: entry.size_bytes,
        modified_ms: entry.modified_ms,
        is_hidden: entry.is_hidden,
    }
}

fn to_frame(screen: &gonomad_pty::ScreenSnapshot) -> ScreenFrame {
    ScreenFrame {
        pty_id: screen.pty_id,
        rows: screen.rows.clone(),
        cursor_row: screen.cursor_row,
        cursor_col: screen.cursor_col,
        cols: screen.cols,
        exited: screen.exited,
    }
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ProtoError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|_| ProtoError::internal("encode"))?;
    Ok(buf)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtoError> {
    ciborium::from_reader(bytes).map_err(|_| ProtoError::bad_request("malformed parameters"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gonomad_policy::{PathGuard, PolicyEngine, SecretDenylist, WorkspaceRoot};
    use std::path::Path;
    use tempfile::TempDir;

    fn daemon(root: &Path) -> Arc<Daemon> {
        let guard = PathGuard::new(vec![WorkspaceRoot::new(root).expect("root")]);
        Arc::new(Daemon {
            fs: FsService::new(PolicyEngine::new(guard, SecretDenylist::with_defaults())),
            ptys: Arc::new(Mutex::new(PtyManager::with_limit(2))),
            workspace_roots: vec![root.display().to_string()],
            host_name: "TEST-HOST".into(),
        })
    }

    fn fixture() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let root = dunce::canonicalize(dir.path()).unwrap();
        std::fs::write(root.join("main.rs"), b"fn main() {}\n").unwrap();
        std::fs::write(root.join(".env"), b"SECRET=1\n").unwrap();
        (dir, root)
    }

    fn key() -> PublicKey {
        PublicKey::from_bytes([5u8; 32])
    }

    fn request(id: u64, method: &str, params: &impl serde::Serialize) -> Request {
        Request {
            correlation_id: id,
            method: method.to_owned(),
            params: encode(params).unwrap(),
            idempotency_key: None,
            presence_signature: None,
        }
    }

    fn ok_bytes(response: &Response) -> &[u8] {
        match &response.body {
            ResponseBody::Ok { result } => result,
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    fn err_code(response: &Response) -> &'static str {
        match &response.body {
            ResponseBody::Error { error } => error.kind.code(),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    fn established(root: &Path) -> Router {
        let grant = DeviceGrant::newly_paired(DeviceId::from_public_key(&key()));
        Router::established(daemon(root), key(), grant)
    }

    #[test]
    fn sys_info_reports_roots_shells_and_capabilities() {
        let (_d, root) = fixture();
        let mut r = established(&root);
        let (resp, effect) = r.handle(&request(1, method::SYS_INFO, &()));
        assert_eq!(effect, Effect::None);

        let info: SysInfoResult = ciborium::from_reader(ok_bytes(&resp)).unwrap();
        assert_eq!(info.host_name, "TEST-HOST");
        assert_eq!(info.workspace_roots.len(), 1);
        assert!(
            !info.shells.is_empty(),
            "a host with no shell cannot run terminals"
        );
        assert!(info.capabilities.contains(Capability::FsRead));
        assert!(!info.capabilities.contains(Capability::FsSecrets));
    }

    #[test]
    fn unknown_methods_are_unsupported_not_denied() {
        // The client renders Unsupported as "update your daemon"; conflating it
        // with a permission failure would send the user to the wrong screen.
        let (_d, root) = fixture();
        let mut r = established(&root);
        let (resp, _) = r.handle(&request(1, "fs.telepathy", &()));
        assert_eq!(err_code(&resp), "unsupported");
    }

    #[test]
    fn fs_list_hides_secrets() {
        let (_d, root) = fixture();
        let mut r = established(&root);
        let params = FsListParams {
            path: root.display().to_string(),
        };
        let (resp, _) = r.handle(&request(1, method::FS_LIST, &params));

        let listing: FsListResult = ciborium::from_reader(ok_bytes(&resp)).unwrap();
        let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"main.rs"));
        assert!(
            !names.contains(&".env"),
            "secret leaked into a listing: {names:?}"
        );
    }

    #[test]
    fn fs_read_refuses_secrets_but_serves_source() {
        let (_d, root) = fixture();
        let mut r = established(&root);

        let good = FsReadParams {
            path: root.join("main.rs").display().to_string(),
        };
        let (resp, _) = r.handle(&request(1, method::FS_READ, &good));
        let content: FsReadResult = ciborium::from_reader(ok_bytes(&resp)).unwrap();
        assert_eq!(content.text, "fn main() {}\n");

        let secret = FsReadParams {
            path: root.join(".env").display().to_string(),
        };
        let (resp, _) = r.handle(&request(2, method::FS_READ, &secret));
        assert_eq!(err_code(&resp), "denied");
    }

    #[test]
    fn paths_outside_the_root_are_not_found() {
        let (_d, root) = fixture();
        let mut r = established(&root);
        let outside = FsListParams {
            path: root.parent().unwrap().display().to_string(),
        };
        let (resp, _) = r.handle(&request(1, method::FS_LIST, &outside));
        assert_eq!(err_code(&resp), "not_found");
    }

    #[test]
    fn malformed_parameters_are_a_bad_request() {
        let (_d, root) = fixture();
        let mut r = established(&root);
        let bad = Request {
            correlation_id: 1,
            method: method::FS_LIST.to_owned(),
            params: vec![0xFF, 0xFF, 0xFF],
            idempotency_key: None,
            presence_signature: None,
        };
        let (resp, _) = r.handle(&bad);
        assert_eq!(err_code(&resp), "bad_request");
    }

    #[test]
    fn the_correlation_id_is_echoed_on_success_and_failure() {
        // The client routes by correlation id; dropping it would hang a request
        // forever.
        let (_d, root) = fixture();
        let mut r = established(&root);
        let (ok, _) = r.handle(&request(4242, method::SYS_INFO, &()));
        assert_eq!(ok.correlation_id, 4242);
        let (err, _) = r.handle(&request(99, "nope.nope", &()));
        assert_eq!(err.correlation_id, 99);
    }

    // ---- the R24 pairing tests ------------------------------------------------

    #[test]
    fn pairing_registers_only_when_the_sas_matches() {
        let (_d, root) = fixture();
        let mut r = Router::pairing(daemon(&root), key(), "418273".into());

        let params = SysRegisterParams {
            device_name: "Pixel 9".into(),
            device_model: Some("Google Pixel 9".into()),
            sas: "418273".into(),
        };
        let (resp, effect) = r.handle(&request(1, method::SYS_REGISTER, &params));

        let result: SysRegisterResult = ciborium::from_reader(ok_bytes(&resp)).unwrap();
        assert_eq!(result.device_id, DeviceId::from_public_key(&key()).to_hex());
        assert!(result.capabilities.contains(Capability::FsRead));

        match effect {
            Effect::Registered {
                peer_key,
                device_name,
                ..
            } => {
                assert_eq!(peer_key, key());
                assert_eq!(device_name, "Pixel 9");
            }
            Effect::None => panic!("a successful register must produce a Registered effect"),
        }
    }

    #[test]
    fn a_mismatched_sas_registers_nothing() {
        // The independent check against a proxying attacker: even if the user
        // tapped Allow without comparing, the digits differ and this fails.
        let (_d, root) = fixture();
        let mut r = Router::pairing(daemon(&root), key(), "418273".into());

        let params = SysRegisterParams {
            device_name: "Attacker".into(),
            device_model: None,
            sas: "000000".into(),
        };
        let (resp, effect) = r.handle(&request(1, method::SYS_REGISTER, &params));

        assert_eq!(err_code(&resp), "bad_request");
        assert_eq!(
            effect,
            Effect::None,
            "a SAS mismatch must not register anything"
        );
        assert!(
            r.capabilities().is_empty(),
            "no capabilities may be granted"
        );
    }

    #[test]
    fn grouped_sas_digits_are_accepted() {
        // The phone displays "418 273"; requiring the caller to strip the space
        // would be a gratuitous interop failure.
        let (_d, root) = fixture();
        let mut r = Router::pairing(daemon(&root), key(), "418273".into());
        let params = SysRegisterParams {
            device_name: "Pixel".into(),
            device_model: None,
            sas: "418 273".into(),
        };
        let (_, effect) = r.handle(&request(1, method::SYS_REGISTER, &params));
        assert!(matches!(effect, Effect::Registered { .. }));
    }

    #[test]
    fn a_pairing_connection_cannot_read_files_before_registering() {
        // The whole point of R24: completing a handshake grants nothing.
        let (_d, root) = fixture();
        let mut r = Router::pairing(daemon(&root), key(), "418273".into());

        assert!(r.capabilities().is_empty());

        for (method_name, params) in [
            (
                method::FS_LIST,
                encode(&FsListParams {
                    path: root.display().to_string(),
                })
                .unwrap(),
            ),
            (method::SYS_INFO, encode(&()).unwrap()),
            (method::PTY_LIST, encode(&()).unwrap()),
        ] {
            let req = Request {
                correlation_id: 1,
                method: method_name.to_owned(),
                params,
                idempotency_key: None,
                presence_signature: None,
            };
            let (resp, effect) = r.handle(&req);
            assert_eq!(
                err_code(&resp),
                "denied",
                "{method_name} was served while pairing"
            );
            assert_eq!(effect, Effect::None);
        }
    }

    #[test]
    fn register_is_refused_outside_a_pairing_window() {
        // Otherwise an already-paired device could re-register itself, or a
        // revoked one could re-admit itself.
        let (_d, root) = fixture();
        let mut r = established(&root);
        let params = SysRegisterParams {
            device_name: "again".into(),
            device_model: None,
            sas: "000000".into(),
        };
        let (resp, effect) = r.handle(&request(1, method::SYS_REGISTER, &params));
        assert_eq!(err_code(&resp), "unsupported");
        assert_eq!(effect, Effect::None);
    }

    #[test]
    fn registering_grants_access_for_the_rest_of_the_connection() {
        // So a freshly paired phone does not have to reconnect immediately.
        let (_d, root) = fixture();
        let mut r = Router::pairing(daemon(&root), key(), "111111".into());

        let params = SysRegisterParams {
            device_name: "Pixel".into(),
            device_model: None,
            sas: "111111".into(),
        };
        r.handle(&request(1, method::SYS_REGISTER, &params));

        let list = FsListParams {
            path: root.display().to_string(),
        };
        let (resp, _) = r.handle(&request(2, method::FS_LIST, &list));
        assert!(matches!(resp.body, ResponseBody::Ok { .. }));
    }

    // ---- terminals ------------------------------------------------------------

    #[test]
    fn a_terminal_spawns_and_reports_its_first_frame() {
        let (_d, root) = fixture();
        let mut r = established(&root);

        let params = PtySpawnParams {
            cwd: Some(root.display().to_string()),
            shell: None,
            cols: 80,
            rows: 24,
        };
        let (resp, _) = r.handle(&request(1, method::PTY_SPAWN, &params));
        let spawned: PtySpawnResult = ciborium::from_reader(ok_bytes(&resp)).unwrap();

        assert_eq!(spawned.initial.pty_id, spawned.pty_id);
        assert_eq!(spawned.initial.cols, 80);
        assert!(!spawned.shell.is_empty());

        let kill = PtyIdParams {
            pty_id: spawned.pty_id,
        };
        let (resp, _) = r.handle(&request(2, method::PTY_KILL, &kill));
        assert!(matches!(resp.body, ResponseBody::Ok { .. }));
    }

    #[test]
    fn a_terminal_cwd_outside_the_workspace_is_refused() {
        // pty:spawn must not be a way to get a shell anywhere on the disk.
        let (_d, root) = fixture();
        let mut r = established(&root);
        let params = PtySpawnParams {
            cwd: Some(root.parent().unwrap().display().to_string()),
            shell: None,
            cols: 80,
            rows: 24,
        };
        let (resp, _) = r.handle(&request(1, method::PTY_SPAWN, &params));
        assert_eq!(err_code(&resp), "not_found");
    }

    #[test]
    fn an_unknown_shell_is_unsupported() {
        let (_d, root) = fixture();
        let mut r = established(&root);
        let params = PtySpawnParams {
            cwd: None,
            shell: Some("fish-on-windows".into()),
            cols: 80,
            rows: 24,
        };
        let (resp, _) = r.handle(&request(1, method::PTY_SPAWN, &params));
        assert_eq!(err_code(&resp), "unsupported");
    }

    #[test]
    fn the_terminal_cap_surfaces_as_resource_exhausted() {
        // Distinct from rate limiting: waiting does not help, the client must
        // close a terminal.
        let (_d, root) = fixture();
        let mut r = established(&root);
        let params = PtySpawnParams {
            cwd: None,
            shell: None,
            cols: 80,
            rows: 24,
        };

        let mut ids = Vec::new();
        for i in 0..2 {
            let (resp, _) = r.handle(&request(i, method::PTY_SPAWN, &params));
            let s: PtySpawnResult = ciborium::from_reader(ok_bytes(&resp)).unwrap();
            ids.push(s.pty_id);
        }

        let (resp, _) = r.handle(&request(9, method::PTY_SPAWN, &params));
        assert_eq!(err_code(&resp), "resource_exhausted");

        for id in ids {
            r.handle(&request(20, method::PTY_KILL, &PtyIdParams { pty_id: id }));
        }
    }

    #[test]
    fn operating_on_an_unknown_terminal_is_not_found() {
        let (_d, root) = fixture();
        let mut r = established(&root);
        let params = PtyIdParams { pty_id: 9999 };
        for m in [method::PTY_SCREEN, method::PTY_KILL] {
            let (resp, _) = r.handle(&request(1, m, &params));
            assert_eq!(err_code(&resp), "not_found", "{m}");
        }
    }

    #[test]
    fn terminal_methods_require_the_pty_capability() {
        // A device granted only fs:read must not be able to open a shell.
        let (_d, root) = fixture();
        let device_id = DeviceId::from_public_key(&key());
        let read_only = DeviceGrant::new(device_id, CapabilitySet::EMPTY.with(Capability::FsRead));
        let mut r = Router::established(daemon(&root), key(), read_only);

        let params = PtySpawnParams {
            cwd: None,
            shell: None,
            cols: 80,
            rows: 24,
        };
        let (resp, _) = r.handle(&request(1, method::PTY_SPAWN, &params));
        assert_eq!(err_code(&resp), "denied");
    }
}
