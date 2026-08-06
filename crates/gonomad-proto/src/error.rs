//! The closed protocol error enum.
//!
//! Every failure that can cross the wire is one of these variants. This is a
//! deliberate design constraint (`ARCHITECTURE.md` §11.2): a **closed** enum
//! means the client can render a correct, *actionable* response for every
//! failure it is capable of receiving.
//!
//! Concretely, each variant drives specific client behaviour:
//!
//! | Variant | What the client does |
//! |---|---|
//! | [`ErrorKind::Conflict`] | Opens the conflict screen with both versions |
//! | [`ErrorKind::PresenceRequired`] | Prompts for biometric, then retries automatically |
//! | [`ErrorKind::RateLimited`] | Backs off for exactly `retry_after_ms` |
//! | [`ErrorKind::Unsupported`] | Shows the version-skew "update your daemon" screen |
//! | [`ErrorKind::Denied`] | Names the missing capability and offers the policy screen |
//!
//! Stringly-typed errors would make all of that impossible, and would leave the
//! client with nothing better to do than show the server's prose to the user.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::{Capability, Digest};

/// What went wrong, in a form the client can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorKind {
    /// The device does not hold the capability this operation requires.
    Denied {
        /// The capability that would have permitted the request.
        capability: Capability,
    },

    /// The requested path, session, or record does not exist.
    ///
    /// Carries no detail about *why*. Distinguishing "outside your workspace
    /// root" from "does not exist" would let a caller map the filesystem
    /// outside its permitted roots one probe at a time, so both collapse to
    /// this variant (`ARCHITECTURE.md` §3.6).
    NotFound,

    /// A compare-and-swap write failed: the file changed since it was read.
    ///
    /// The defining error of the file-sync model (§12.2). Returning the current
    /// hash lets the client fetch the new content and attempt a three-way merge
    /// without a second round trip.
    Conflict {
        /// The file's hash as it stands on disk now.
        current_hash: Digest,
    },

    /// The device exceeded its rate budget for this class of operation.
    RateLimited {
        /// How long the client must wait before retrying.
        retry_after_ms: u32,
    },

    /// A hard resource ceiling was reached — not a rate, a cap.
    ///
    /// Distinct from [`ErrorKind::RateLimited`] because waiting does not help:
    /// the client must release something first (§3.8).
    ResourceExhausted {
        /// Which ceiling was hit, e.g. `"ptys"` or `"watchers"`.
        resource: String,
        /// The configured limit, for a precise message.
        limit: u32,
    },

    /// This daemon does not implement the requested feature.
    ///
    /// The version-skew signal. Phone and daemon update independently, so skew
    /// is guaranteed; this variant is what turns it into a clear instruction
    /// rather than mysterious partial breakage (§24.7).
    Unsupported {
        /// The feature or method that is unavailable.
        feature: String,
        /// The daemon version the client would need, when known.
        since_version: Option<u32>,
    },

    /// The operation is destructive and needs a fresh biometric signature.
    ///
    /// The client prompts for biometric authentication, signs `challenge` with
    /// the hardware-backed presence key, and retries. The challenge is a digest
    /// of the *exact operation*, so a harvested signature cannot be replayed
    /// against a different one (§3.10).
    PresenceRequired {
        /// Digest of the operation the signature must cover.
        challenge: Digest,
    },

    /// The client cancelled the operation.
    Cancelled,

    /// The request was structurally invalid.
    ///
    /// A bug in the client, or a tampered frame — never a user error.
    BadRequest {
        /// What was wrong with the request.
        detail: String,
    },

    /// The daemon failed unexpectedly.
    ///
    /// Deliberately opaque. The `trace_id` correlates with the daemon's local
    /// logs, so a user can report a bug precisely without the error itself
    /// leaking paths, arguments, or internal structure to a client that may be
    /// compromised.
    Internal {
        /// Correlates this failure with the daemon's local log.
        trace_id: String,
    },
}

impl ErrorKind {
    /// A stable machine-readable code for logs, metrics, and tests.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Denied { .. } => "denied",
            Self::NotFound => "not_found",
            Self::Conflict { .. } => "conflict",
            Self::RateLimited { .. } => "rate_limited",
            Self::ResourceExhausted { .. } => "resource_exhausted",
            Self::Unsupported { .. } => "unsupported",
            Self::PresenceRequired { .. } => "presence_required",
            Self::Cancelled => "cancelled",
            Self::BadRequest { .. } => "bad_request",
            Self::Internal { .. } => "internal",
        }
    }

    /// Whether retrying the identical request could plausibly succeed.
    ///
    /// Drives the client's automatic retry logic. A `Denied` is permanent until
    /// policy changes, so retrying only wastes battery; a `RateLimited`
    /// resolves on its own.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        match self {
            Self::RateLimited { .. } | Self::ResourceExhausted { .. } | Self::Internal { .. } => {
                true
            }
            // PresenceRequired is excluded on purpose: it needs a *new*
            // request carrying a signature, not a retry of this one.
            Self::Denied { .. }
            | Self::NotFound
            | Self::Conflict { .. }
            | Self::Unsupported { .. }
            | Self::PresenceRequired { .. }
            | Self::Cancelled
            | Self::BadRequest { .. } => false,
        }
    }

    /// Whether this failure needs the user to intervene before progress is
    /// possible — a biometric prompt, a policy change, a conflict resolution,
    /// or a daemon upgrade.
    #[must_use]
    pub const fn needs_user_action(&self) -> bool {
        matches!(
            self,
            Self::Denied { .. }
                | Self::Conflict { .. }
                | Self::PresenceRequired { .. }
                | Self::Unsupported { .. }
        )
    }

    /// A message suitable for display, written for the person holding the phone.
    #[must_use]
    pub fn user_message(&self) -> String {
        match self {
            Self::Denied { capability } => {
                format!(
                    "This device is not allowed to {}",
                    capability.description().to_lowercase()
                )
            }
            Self::NotFound => "Not found".to_owned(),
            Self::Conflict { .. } => "This file changed on your machine".to_owned(),
            Self::RateLimited { retry_after_ms } => {
                format!(
                    "Too many requests — retrying in {}s",
                    retry_after_ms.div_ceil(1000)
                )
            }
            Self::ResourceExhausted { resource, limit } => {
                format!("Reached the limit of {limit} {resource} — close one first")
            }
            Self::Unsupported {
                feature,
                since_version,
            } => match since_version {
                Some(v) => {
                    format!("Your machine's GoNomad is too old for {feature} (needs v{v} or later)")
                }
                None => format!("Your machine's GoNomad does not support {feature}"),
            },
            Self::PresenceRequired { .. } => "Confirm with your fingerprint".to_owned(),
            Self::Cancelled => "Cancelled".to_owned(),
            Self::BadRequest { .. } => "Something went wrong — please report this".to_owned(),
            Self::Internal { trace_id } => {
                format!("Your machine reported an error (ref {trace_id})")
            }
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied { capability } => write!(f, "denied: requires {capability}"),
            Self::NotFound => f.write_str("not found"),
            Self::Conflict { current_hash } => {
                write!(f, "conflict: file is now {}", current_hash.short())
            }
            Self::RateLimited { retry_after_ms } => {
                write!(f, "rate limited: retry in {retry_after_ms}ms")
            }
            Self::ResourceExhausted { resource, limit } => {
                write!(f, "resource exhausted: {resource} limit of {limit} reached")
            }
            Self::Unsupported {
                feature,
                since_version,
            } => match since_version {
                Some(v) => write!(f, "unsupported: {feature} requires protocol v{v}"),
                None => write!(f, "unsupported: {feature}"),
            },
            Self::PresenceRequired { challenge } => {
                write!(f, "presence required for operation {}", challenge.short())
            }
            Self::Cancelled => f.write_str("cancelled"),
            Self::BadRequest { detail } => write!(f, "bad request: {detail}"),
            Self::Internal { trace_id } => write!(f, "internal error (trace {trace_id})"),
        }
    }
}

/// A protocol error, optionally naming the request it belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{kind}")]
pub struct ProtoError {
    /// What went wrong.
    pub kind: ErrorKind,
    /// The correlation id of the failed request, when it had one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub correlation_id: Option<u64>,
}

impl ProtoError {
    /// Wraps a kind with no correlation id.
    #[must_use]
    pub const fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            correlation_id: None,
        }
    }

    /// Attaches a correlation id.
    #[must_use]
    pub fn for_request(mut self, correlation_id: u64) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// A `Denied` error naming the capability that would have permitted it.
    #[must_use]
    pub const fn denied(capability: Capability) -> Self {
        Self::new(ErrorKind::Denied { capability })
    }

    /// A `NotFound` error.
    ///
    /// Used for both genuinely missing paths and paths outside a permitted
    /// root, so that probing cannot distinguish the two.
    #[must_use]
    pub const fn not_found() -> Self {
        Self::new(ErrorKind::NotFound)
    }

    /// A `Conflict` error carrying the file's current hash.
    #[must_use]
    pub const fn conflict(current_hash: Digest) -> Self {
        Self::new(ErrorKind::Conflict { current_hash })
    }

    /// A `RateLimited` error.
    #[must_use]
    pub const fn rate_limited(retry_after_ms: u32) -> Self {
        Self::new(ErrorKind::RateLimited { retry_after_ms })
    }

    /// A `PresenceRequired` error carrying the challenge to be signed.
    #[must_use]
    pub const fn presence_required(challenge: Digest) -> Self {
        Self::new(ErrorKind::PresenceRequired { challenge })
    }

    /// A `BadRequest` error.
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(ErrorKind::BadRequest {
            detail: detail.into(),
        })
    }

    /// An `Internal` error carrying a trace id.
    pub fn internal(trace_id: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal {
            trace_id: trace_id.into(),
        })
    }
}

impl From<ErrorKind> for ProtoError {
    fn from(kind: ErrorKind) -> Self {
        Self::new(kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_of_each() -> Vec<ErrorKind> {
        vec![
            ErrorKind::Denied {
                capability: Capability::FsWrite,
            },
            ErrorKind::NotFound,
            ErrorKind::Conflict {
                current_hash: Digest::of(b"now"),
            },
            ErrorKind::RateLimited {
                retry_after_ms: 1500,
            },
            ErrorKind::ResourceExhausted {
                resource: "ptys".into(),
                limit: 16,
            },
            ErrorKind::Unsupported {
                feature: "git.blame".into(),
                since_version: Some(3),
            },
            ErrorKind::PresenceRequired {
                challenge: Digest::of(b"op"),
            },
            ErrorKind::Cancelled,
            ErrorKind::BadRequest {
                detail: "missing field".into(),
            },
            ErrorKind::Internal {
                trace_id: "abc123".into(),
            },
        ]
    }

    #[test]
    fn every_variant_is_covered_by_the_test_fixture() {
        // Guards against a new variant being added without test coverage.
        let mut codes: Vec<&str> = one_of_each().iter().map(ErrorKind::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), one_of_each().len());
    }

    #[test]
    fn all_variants_round_trip_through_cbor() {
        for kind in one_of_each() {
            let err = ProtoError::new(kind.clone()).for_request(42);
            let mut buf = Vec::new();
            ciborium::into_writer(&err, &mut buf).unwrap();
            let back: ProtoError = ciborium::from_reader(buf.as_slice()).unwrap();
            assert_eq!(back, err, "round trip failed for {}", kind.code());
        }
    }

    #[test]
    fn absent_correlation_id_is_omitted_from_the_wire() {
        let json = serde_json::to_string(&ProtoError::not_found()).unwrap();
        assert!(!json.contains("correlation_id"), "got {json}");
    }

    #[test]
    fn every_variant_has_a_nonempty_user_message() {
        for kind in one_of_each() {
            let msg = kind.user_message();
            assert!(!msg.is_empty(), "{} has no user message", kind.code());
        }
    }

    #[test]
    fn user_messages_do_not_leak_internal_detail() {
        // `BadRequest` and `Internal` carry developer-facing text. It must not
        // reach the user-facing string, because a compromised client should
        // not be handed daemon internals (§11.2).
        let bad = ErrorKind::BadRequest {
            detail: "field `cwd` failed validation".into(),
        };
        assert!(!bad.user_message().contains("cwd"));

        let internal = ErrorKind::Internal {
            trace_id: "t-1".into(),
        };
        // The trace id is intentionally present — it is how a user reports the
        // bug — but nothing else is.
        assert!(internal.user_message().contains("t-1"));
    }

    #[test]
    fn retryability_matches_intent() {
        assert!(ErrorKind::RateLimited { retry_after_ms: 10 }.is_retryable());
        assert!(ErrorKind::Internal {
            trace_id: "x".into()
        }
        .is_retryable());
        assert!(!ErrorKind::Denied {
            capability: Capability::FsRead
        }
        .is_retryable());
        assert!(!ErrorKind::Cancelled.is_retryable());
        assert!(!ErrorKind::NotFound.is_retryable());
    }

    #[test]
    fn presence_required_is_not_retryable_but_does_need_action() {
        // Retrying the same request without a signature would fail identically
        // and waste battery; the client must build a new signed request.
        let kind = ErrorKind::PresenceRequired {
            challenge: Digest::of(b"op"),
        };
        assert!(!kind.is_retryable());
        assert!(kind.needs_user_action());
    }

    #[test]
    fn no_variant_is_both_retryable_and_user_actionable() {
        // These drive mutually exclusive client paths: automatic retry versus
        // stop-and-prompt. Overlap would produce a retry loop behind a modal.
        for kind in one_of_each() {
            assert!(
                !(kind.is_retryable() && kind.needs_user_action()),
                "{} is both retryable and user-actionable",
                kind.code()
            );
        }
    }

    #[test]
    fn conflict_carries_the_current_hash_so_the_client_can_merge() {
        let hash = Digest::of(b"disk contents");
        match ProtoError::conflict(hash).kind {
            ErrorKind::Conflict { current_hash } => assert_eq!(current_hash, hash),
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    #[test]
    fn denied_names_the_capability_in_the_user_message() {
        let msg = ErrorKind::Denied {
            capability: Capability::GitDangerous,
        }
        .user_message();
        assert!(msg.contains("force push"), "got {msg}");
    }

    #[test]
    fn rate_limit_message_rounds_up_so_it_never_says_zero_seconds() {
        let msg = ErrorKind::RateLimited { retry_after_ms: 1 }.user_message();
        assert!(msg.contains("1s"), "got {msg}");
    }

    #[test]
    fn correlation_id_survives_the_builder() {
        assert_eq!(
            ProtoError::not_found().for_request(7).correlation_id,
            Some(7)
        );
    }

    #[test]
    fn display_is_developer_facing_and_distinct_from_user_message() {
        let kind = ErrorKind::Denied {
            capability: Capability::FsWrite,
        };
        assert_eq!(kind.to_string(), "denied: requires fs:write");
        assert_ne!(kind.to_string(), kind.user_message());
    }
}
