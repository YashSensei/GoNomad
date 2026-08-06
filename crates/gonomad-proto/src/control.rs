//! Control-stream messages: the handshake, and the request/response envelope.
//!
//! Every connection opens a control stream first (`ARCHITECTURE.md` §10.2).
//! It carries the hello exchange, then request/response traffic, server-pushed
//! events, cancellation, and heartbeats. Bulk transfers and PTY traffic get
//! their own streams so a 40 MB download cannot head-of-line-block a keystroke.
//!
//! # Why method names are strings
//!
//! [`Request::method`] is a `String` (`"fs.read"`, `"pty.spawn"`), which sits
//! oddly beside [`crate::ErrorKind`] being a deliberately closed enum. The
//! difference is intentional:
//!
//! - **Errors are closed** because the client must react correctly to every
//!   failure it can receive, and an unrecognised error leaves it with nothing
//!   useful to do (§11.2).
//! - **Methods are open** because the surface grows every milestone, and an
//!   unrecognised method has an obviously correct response:
//!   [`crate::ErrorKind::Unsupported`], which the client already renders as the
//!   version-skew screen (§24.7).
//!
//! A closed method enum would force phone and daemon to update in lockstep, and
//! version skew between them is guaranteed rather than exceptional.

use serde::{Deserialize, Serialize};

use crate::{CapabilitySet, Digest, ProtoError, PublicKey};

/// Correlates a response with the request that produced it.
///
/// Assigned by the client and unique for the lifetime of a connection. A `u64`
/// at even an implausible one million requests per second takes ~580,000 years
/// to wrap, so reuse is not a case that needs handling.
pub type CorrelationId = u64;

/// Identifies a logical session, which may outlive any single connection.
///
/// The daemon owns all long-lived state (`ARCHITECTURE.md` §2), so reconnecting
/// with a known session id restores a *view* of terminals and agents that never
/// stopped running.
pub type SessionId = u64;

/// The client's opening message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Protocol version the client speaks.
    pub proto_version: u32,
    /// Oldest protocol version the client can still accept.
    pub min_supported: u32,
    /// Human-readable client build, for diagnostics and the devices screen.
    pub client_version: String,
    /// The device's Ed25519 public key — its credential (§3.2).
    pub device_key: PublicKey,
    /// Capabilities the client would like to exercise this session.
    ///
    /// A *request*, never a grant. The daemon replies with what it actually
    /// permits, which is the intersection with the stored grant. A client
    /// asking for more than it holds is answered, not trusted.
    pub capabilities_requested: CapabilitySet,
    /// Compression dictionary ids the client holds (§10.3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub compression_dicts: Vec<u32>,
    /// Optional feature flags for negotiated extensions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    /// A prior session to resume, when reconnecting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_session: Option<SessionId>,
}

/// The daemon's acceptance of a [`Hello`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloOk {
    /// Protocol version the daemon will use for this connection.
    pub proto_version: u32,
    /// Human-readable daemon build.
    pub server_version: String,
    /// Capabilities actually granted — the authoritative set for this session.
    pub granted_capabilities: CapabilitySet,
    /// Workspace roots this device may reach. Paths outside these are denied
    /// regardless of capability (§3.6).
    pub workspace_roots: Vec<String>,
    /// Compression dictionary the daemon selected, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression_dict: Option<u32>,
    /// Extensions the daemon supports.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_features: Vec<String>,
    /// The session id for this connection.
    pub session_id: SessionId,
}

/// Why a [`Hello`] was refused.
///
/// Each variant maps to a distinct, actionable client screen. In particular
/// [`Self::VersionTooOld`] and [`Self::VersionTooNew`] are separated because the
/// remedy differs — upgrade the daemon versus upgrade the app — and telling a
/// user to update the wrong half is worse than saying nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RejectReason {
    /// The client's protocol version predates this daemon's floor.
    VersionTooOld {
        /// The minimum version the daemon accepts.
        server_min: u32,
    },
    /// The client speaks a newer protocol than this daemon understands.
    VersionTooNew {
        /// The newest version the daemon understands.
        server_max: u32,
    },
    /// This key has never been paired.
    ///
    /// Returned only after the QUIC handshake authenticated *some* key. An
    /// unpaired key is normally dropped before application data (§3.7); this
    /// variant exists for the pairing-window edge case.
    Unpaired,
    /// The device was paired but has since been revoked.
    Revoked,
    /// Too many handshake attempts from this key.
    RateLimited {
        /// How long to wait before retrying.
        retry_after_ms: u32,
    },
}

/// The daemon's refusal of a [`Hello`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloReject {
    /// Why the connection was refused.
    pub reason: RejectReason,
    /// The daemon's build, so the client can show a precise upgrade message
    /// even though the connection is being closed.
    pub server_version: String,
}

/// A client request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Correlates the eventual response.
    pub correlation_id: CorrelationId,
    /// Namespaced method name, e.g. `"fs.read"`.
    pub method: String,
    /// CBOR-encoded, method-specific parameters.
    ///
    /// Opaque here so this crate's envelope does not have to change every time
    /// a method is added.
    #[serde(with = "serde_bytes_compat")]
    pub params: Vec<u8>,
    /// Deduplicates retries of a mutating request.
    ///
    /// The daemon retains recently seen keys, so a network-level retry cannot
    /// double-apply a commit or a file write (§11.2). Absent for reads, where
    /// repetition is harmless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<Digest>,
    /// A presence-key signature over the operation digest, when the operation
    /// requires biometric confirmation (§3.10).
    ///
    /// The signature covers the digest of *this specific operation*, so one
    /// harvested from an innocuous action cannot be replayed onto a destructive
    /// one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence_signature: Option<Vec<u8>>,
}

/// The outcome of a request.
///
/// A single request may produce many `Progress` frames and exactly one terminal
/// `Ok` or `Error`. Streaming is modelled here rather than left to stream
/// framing so that a long operation can report progress on the control stream
/// while its bulk data flows elsewhere.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ResponseBody {
    /// Terminal success, carrying a CBOR-encoded result.
    Ok {
        /// CBOR-encoded, method-specific result.
        #[serde(with = "serde_bytes_compat")]
        result: Vec<u8>,
    },
    /// A non-terminal progress update.
    Progress {
        /// Completed units, when known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        done: Option<u64>,
        /// Total units, when known. Absent for genuinely unbounded work —
        /// reporting a fabricated total produces a progress bar that lies.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        total: Option<u64>,
        /// A short status line, e.g. `"Resolving deltas"`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// Terminal failure.
    Error {
        /// What went wrong.
        error: ProtoError,
    },
}

impl ResponseBody {
    /// Whether this is the last message for its correlation id.
    ///
    /// The client uses this to release the pending-request slot. Getting it
    /// wrong leaks slots (on a false negative) or drops later frames (on a
    /// false positive), so it is derived from the variant rather than from a
    /// separate flag that could disagree.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Ok { .. } | Self::Error { .. })
    }
}

/// A response to a [`Request`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    /// The request this answers.
    pub correlation_id: CorrelationId,
    /// The outcome.
    pub body: ResponseBody,
}

/// An application-level heartbeat.
///
/// QUIC has its own keepalive; this rides above it to measure end-to-end
/// liveness including the daemon's task scheduler. A responsive transport in
/// front of a wedged event loop looks identical to a healthy connection at the
/// QUIC layer, and the user experiences it as the app being broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Echoed back unchanged, so a sender can match reply to probe and compute
    /// round-trip time.
    pub nonce: u64,
}

/// Any message on the control stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ControlMessage {
    /// Client → daemon: open the session.
    Hello(Hello),
    /// Daemon → client: session accepted.
    HelloOk(HelloOk),
    /// Daemon → client: session refused.
    HelloReject(HelloReject),
    /// Client → daemon: perform an operation.
    Request(Request),
    /// Daemon → client: progress or outcome.
    Response(Response),
    /// Client → daemon: abandon an in-flight request.
    ///
    /// Universal cancellation is a requirement, not a nicety: users navigate
    /// away constantly, and uncancellable work on a phone drains battery for a
    /// result nobody will read (§11.2).
    Cancel {
        /// The request to abandon.
        correlation_id: CorrelationId,
    },
    /// Either direction: liveness probe.
    Ping(Heartbeat),
    /// Either direction: liveness reply.
    Pong(Heartbeat),
}

impl ControlMessage {
    /// The correlation id this message belongs to, when it has one.
    #[must_use]
    pub const fn correlation_id(&self) -> Option<CorrelationId> {
        match self {
            Self::Request(r) => Some(r.correlation_id),
            Self::Response(r) => Some(r.correlation_id),
            Self::Cancel { correlation_id } => Some(*correlation_id),
            Self::Hello(_)
            | Self::HelloOk(_)
            | Self::HelloReject(_)
            | Self::Ping(_)
            | Self::Pong(_) => None,
        }
    }

    /// Whether this message is permitted before the handshake completes.
    ///
    /// The daemon rejects everything else pre-handshake. Without this check a
    /// peer could issue requests before its capabilities were established,
    /// which would make the entire authorization layer optional (§3.7).
    #[must_use]
    pub const fn allowed_before_handshake(&self) -> bool {
        matches!(
            self,
            Self::Hello(_) | Self::HelloOk(_) | Self::HelloReject(_)
        )
    }
}

/// Serializes `Vec<u8>` as a CBOR byte string rather than an array of integers.
///
/// Without this, `ciborium` emits each byte as a separate CBOR integer, roughly
/// doubling the size of every request payload — on the hot path, over cellular.
mod serde_bytes_compat {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        // `ciborium` hands byte strings back as `Vec<u8>` via this path; the
        // explicit annotation keeps it from resolving to a sequence of ints.
        let value = ciborium::value::Value::deserialize(d)?;
        match value {
            ciborium::value::Value::Bytes(b) => Ok(b),
            // Tolerated on the read side so a peer that encoded an array of
            // integers still interoperates. Being strict here would turn a
            // harmless encoding difference into a dropped connection.
            ciborium::value::Value::Array(items) => items
                .into_iter()
                .map(|v| {
                    v.as_integer()
                        .and_then(|i| u8::try_from(i).ok())
                        .ok_or_else(|| serde::de::Error::custom("expected byte"))
                })
                .collect(),
            _ => Err(serde::de::Error::custom("expected a CBOR byte string")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Capability, ErrorKind, PROTOCOL_VERSION};

    fn key() -> PublicKey {
        PublicKey::from_bytes([7u8; 32])
    }

    fn hello() -> Hello {
        Hello {
            proto_version: PROTOCOL_VERSION,
            min_supported: 1,
            client_version: "gonomad-android/0.0.1".into(),
            device_key: key(),
            capabilities_requested: CapabilitySet::default_grant(),
            compression_dicts: vec![1],
            features: vec![],
            resume_session: None,
        }
    }

    fn round_trip(msg: &ControlMessage) -> ControlMessage {
        let mut buf = Vec::new();
        ciborium::into_writer(msg, &mut buf).expect("serialize");
        ciborium::from_reader(buf.as_slice()).expect("deserialize")
    }

    #[test]
    fn hello_round_trips() {
        let msg = ControlMessage::Hello(hello());
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn hello_ok_round_trips() {
        let msg = ControlMessage::HelloOk(HelloOk {
            proto_version: PROTOCOL_VERSION,
            server_version: "gonomad/0.0.1".into(),
            granted_capabilities: CapabilitySet::default_grant(),
            workspace_roots: vec!["C:/dev/gonomad".into()],
            compression_dict: Some(1),
            server_features: vec!["pty.passthrough".into()],
            session_id: 42,
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn every_reject_reason_round_trips() {
        for reason in [
            RejectReason::VersionTooOld { server_min: 2 },
            RejectReason::VersionTooNew { server_max: 1 },
            RejectReason::Unpaired,
            RejectReason::Revoked,
            RejectReason::RateLimited {
                retry_after_ms: 5000,
            },
        ] {
            let msg = ControlMessage::HelloReject(HelloReject {
                reason: reason.clone(),
                server_version: "gonomad/0.0.1".into(),
            });
            assert_eq!(round_trip(&msg), msg, "failed for {reason:?}");
        }
    }

    #[test]
    fn version_too_old_and_too_new_are_distinct() {
        // The remedies differ — upgrade the daemon versus upgrade the app — and
        // telling a user to update the wrong half is worse than silence.
        assert_ne!(
            RejectReason::VersionTooOld { server_min: 2 },
            RejectReason::VersionTooNew { server_max: 2 }
        );
    }

    #[test]
    fn request_round_trips_with_all_optional_fields_present() {
        let msg = ControlMessage::Request(Request {
            correlation_id: 9,
            method: "fs.write".into(),
            params: vec![0xA1, 0x62, 0x68, 0x69],
            idempotency_key: Some(Digest::of(b"once")),
            presence_signature: Some(vec![0xEE; 64]),
        });
        assert_eq!(round_trip(&msg), msg);
    }

    #[test]
    fn request_omits_absent_optional_fields_on_the_wire() {
        let req = Request {
            correlation_id: 1,
            method: "fs.read".into(),
            params: vec![],
            idempotency_key: None,
            presence_signature: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("idempotency_key"), "got {json}");
        assert!(!json.contains("presence_signature"), "got {json}");
    }

    #[test]
    fn params_are_encoded_as_a_cbor_byte_string_not_an_integer_array() {
        // Encoding bytes as an array of integers roughly doubles every payload,
        // on the hot path, over cellular.
        let req = Request {
            correlation_id: 1,
            method: "x".into(),
            params: vec![0xFF; 64],
            idempotency_key: None,
            presence_signature: None,
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&req, &mut buf).unwrap();
        // A 64-byte byte string costs 2 header bytes + 64. As an integer array
        // each 0xFF byte would need 2 bytes, so >128 for the payload alone.
        assert!(
            buf.len() < 128,
            "params encoded inefficiently: {} bytes",
            buf.len()
        );
    }

    #[test]
    fn large_params_round_trip_exactly() {
        let params: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        let msg = ControlMessage::Request(Request {
            correlation_id: 3,
            method: "fs.write".into(),
            params: params.clone(),
            idempotency_key: None,
            presence_signature: None,
        });
        match round_trip(&msg) {
            ControlMessage::Request(r) => assert_eq!(r.params, params),
            other => panic!("expected Request, got {other:?}"),
        }
    }

    #[test]
    fn all_response_bodies_round_trip() {
        for body in [
            ResponseBody::Ok {
                result: vec![1, 2, 3],
            },
            ResponseBody::Progress {
                done: Some(5),
                total: Some(10),
                message: Some("Resolving deltas".into()),
            },
            ResponseBody::Progress {
                done: None,
                total: None,
                message: None,
            },
            ResponseBody::Error {
                error: ProtoError::denied(Capability::FsWrite),
            },
        ] {
            let msg = ControlMessage::Response(Response {
                correlation_id: 1,
                body: body.clone(),
            });
            assert_eq!(round_trip(&msg), msg, "failed for {body:?}");
        }
    }

    #[test]
    fn only_ok_and_error_are_terminal() {
        assert!(ResponseBody::Ok { result: vec![] }.is_terminal());
        assert!(ResponseBody::Error {
            error: ProtoError::not_found()
        }
        .is_terminal());
        assert!(
            !ResponseBody::Progress {
                done: None,
                total: None,
                message: None
            }
            .is_terminal(),
            "progress must not release the pending-request slot"
        );
    }

    #[test]
    fn correlation_id_is_exposed_for_routable_messages_only() {
        assert_eq!(
            ControlMessage::Request(Request {
                correlation_id: 11,
                method: "x".into(),
                params: vec![],
                idempotency_key: None,
                presence_signature: None,
            })
            .correlation_id(),
            Some(11)
        );
        assert_eq!(
            ControlMessage::Cancel { correlation_id: 12 }.correlation_id(),
            Some(12)
        );
        assert_eq!(
            ControlMessage::Response(Response {
                correlation_id: 13,
                body: ResponseBody::Ok { result: vec![] },
            })
            .correlation_id(),
            Some(13)
        );
        assert_eq!(ControlMessage::Hello(hello()).correlation_id(), None);
        assert_eq!(
            ControlMessage::Ping(Heartbeat { nonce: 1 }).correlation_id(),
            None
        );
    }

    #[test]
    fn only_handshake_messages_are_allowed_before_the_handshake() {
        // If a Request were permitted here, a peer could act before its
        // capabilities were established, making authorization optional.
        assert!(ControlMessage::Hello(hello()).allowed_before_handshake());
        assert!(ControlMessage::HelloReject(HelloReject {
            reason: RejectReason::Unpaired,
            server_version: "v".into(),
        })
        .allowed_before_handshake());

        assert!(!ControlMessage::Request(Request {
            correlation_id: 1,
            method: "fs.read".into(),
            params: vec![],
            idempotency_key: None,
            presence_signature: None,
        })
        .allowed_before_handshake());
        assert!(!ControlMessage::Ping(Heartbeat { nonce: 1 }).allowed_before_handshake());
        assert!(!ControlMessage::Cancel { correlation_id: 1 }.allowed_before_handshake());
    }

    #[test]
    fn requested_capabilities_are_a_request_not_a_grant() {
        // A client may ask for anything; the daemon's HelloOk is authoritative.
        let mut h = hello();
        h.capabilities_requested = CapabilitySet::all();
        let granted = CapabilitySet::default_grant();
        assert!(h.capabilities_requested.contains(Capability::PolicyWrite));
        assert!(!granted.contains(Capability::PolicyWrite));
    }

    #[test]
    fn heartbeat_nonce_is_echoed_so_rtt_can_be_measured() {
        let probe = Heartbeat { nonce: 0xDEAD_BEEF };
        match round_trip(&ControlMessage::Pong(probe)) {
            ControlMessage::Pong(h) => assert_eq!(h.nonce, probe.nonce),
            other => panic!("expected Pong, got {other:?}"),
        }
    }

    #[test]
    fn error_responses_preserve_the_error_kind() {
        let err = ProtoError::conflict(Digest::of(b"disk"));
        let msg = ControlMessage::Response(Response {
            correlation_id: 1,
            body: ResponseBody::Error { error: err.clone() },
        });
        match round_trip(&msg) {
            ControlMessage::Response(Response {
                body: ResponseBody::Error { error },
                ..
            }) => {
                assert_eq!(error, err);
                assert!(matches!(error.kind, ErrorKind::Conflict { .. }));
            }
            other => panic!("expected an error response, got {other:?}"),
        }
    }

    #[test]
    fn resume_session_survives_a_round_trip() {
        let mut h = hello();
        h.resume_session = Some(99);
        match round_trip(&ControlMessage::Hello(h)) {
            ControlMessage::Hello(got) => assert_eq!(got.resume_session, Some(99)),
            other => panic!("expected Hello, got {other:?}"),
        }
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_params_round_trip(params: Vec<u8>) {
            let msg = ControlMessage::Request(Request {
                correlation_id: 1,
                method: "m".into(),
                params: params.clone(),
                idempotency_key: None,
                presence_signature: None,
            });
            match round_trip(&msg) {
                ControlMessage::Request(r) => proptest::prop_assert_eq!(r.params, params),
                other => proptest::prop_assert!(false, "expected Request, got {:?}", other),
            }
        }

        #[test]
        fn arbitrary_method_names_round_trip(method: String) {
            let msg = ControlMessage::Request(Request {
                correlation_id: 1,
                method: method.clone(),
                params: vec![],
                idempotency_key: None,
                presence_signature: None,
            });
            match round_trip(&msg) {
                ControlMessage::Request(r) => proptest::prop_assert_eq!(r.method, method),
                other => proptest::prop_assert!(false, "expected Request, got {:?}", other),
            }
        }

        /// Deserializing arbitrary bytes as a control message must never panic:
        /// this runs on data from a peer that may be hostile.
        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes: Vec<u8>) {
            let _ = ciborium::from_reader::<ControlMessage, _>(bytes.as_slice());
        }
    }
}
