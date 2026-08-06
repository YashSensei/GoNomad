//! Server-pushed events.
//!
//! Events are unsolicited messages from the daemon: a file changed on disk, an
//! agent is waiting for approval, a test run finished (`ARCHITECTURE.md` §10.5).
//!
//! # Why every event carries a sequence number
//!
//! [`Event::seq`] is monotonic and gap-free per connection. A client that
//! receives `seq` 7 immediately after 5 knows it missed 6 and can resynchronise
//! by refetching state, rather than silently rendering a stale view.
//!
//! This matters more than it might seem. The daemon coalesces and drops
//! *intermediate* states deliberately — the phone only needs the latest terminal
//! grid, not every frame (§13.2) — so "did I miss something that mattered?" is a
//! question the protocol must be able to answer. A client showing a file tree
//! that silently stopped updating is worse than one that knows it is stale and
//! says so (§15.5).

use serde::{Deserialize, Serialize};

use crate::{CapabilitySet, DeviceId, Digest};

/// Identifies a terminal session.
pub type PtyId = u64;
/// Identifies an AI agent session.
pub type AgentSessionId = u64;
/// Identifies a long-running tracked operation.
pub type TaskId = u64;

/// What happened to a path on disk.
///
/// Editors do not write files simply — they write a temp file, rename it over
/// the target, and sometimes truncate first. The daemon coalesces those bursts
/// into one logical change before emitting (§12.6), so these variants describe
/// *intent*, not raw filesystem syscalls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FileChangeKind {
    /// The file or directory came into existence.
    Created,
    /// Contents changed.
    Modified,
    /// The file or directory went away.
    Deleted,
    /// The entry moved; `from` on the event carries the old path.
    Renamed,
}

/// A single filesystem change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChange {
    /// Workspace-relative path.
    pub path: String,
    /// What happened.
    pub kind: FileChangeKind,
    /// Previous path, for [`FileChangeKind::Renamed`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Whether the entry is a directory, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_dir: Option<bool>,
    /// New content hash, when cheaply available.
    ///
    /// Lets a client holding this file open decide whether its cached copy is
    /// still current without a round trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<Digest>,
}

/// Lifecycle state of an AI agent session.
///
/// Uniform across every agent regardless of integration level, so the phone
/// never learns which vendor is running (`ARCHITECTURE.md` §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AgentState {
    /// The process is launching.
    Starting,
    /// Ready for input.
    Idle,
    /// Working. The UI shows a live indicator.
    Thinking,
    /// Blocked on an approval decision.
    ///
    /// The state where the *user* is the bottleneck, so sessions in it sort to
    /// the top of the list and are visually loudest (§23.3).
    AwaitingApproval,
    /// Blocked on ordinary input, not an approval.
    AwaitingInput,
    /// The agent reported an error.
    Error,
    /// The process exited.
    Exited,
}

impl AgentState {
    /// Whether this state needs the user before work can continue.
    #[must_use]
    pub const fn blocks_on_user(self) -> bool {
        matches!(self, Self::AwaitingApproval | Self::AwaitingInput)
    }

    /// Whether the session is finished and will produce no further output.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Exited)
    }
}

/// How damaging an agent's proposed action would be if wrong.
///
/// Drives whether a fresh biometric signature is demanded and how loudly the
/// approval sheet presents itself (§7.5). Classified by the daemon, never by the
/// agent — an agent under prompt injection would classify its own destructive
/// action as routine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Destructiveness {
    /// Reads only; no state change.
    ReadOnly,
    /// Ordinary edits inside a workspace root.
    Routine,
    /// Deletes files, installs packages, or reaches the network.
    Elevated,
    /// Irreversible: history rewrite, bulk delete, or secret access.
    ///
    /// Always requires a fresh presence signature.
    Destructive,
}

impl Destructiveness {
    /// Whether approving this requires a fresh biometric signature.
    #[must_use]
    pub const fn requires_presence(self) -> bool {
        matches!(self, Self::Elevated | Self::Destructive)
    }
}

/// An agent's request for permission to act.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Identifies this decision, so a stale approval cannot be applied.
    pub approval_id: u64,
    /// A one-line classification, e.g. `"Modify 3 files"`.
    pub summary: String,
    /// The **actual** proposed change — a unified diff or verbatim command.
    ///
    /// Never the agent's own description of what it intends. A prompt-injected
    /// agent will describe a malicious edit benignly, so the only defence that
    /// does not depend on trusting the thing being audited is to render the real
    /// change (§7.5).
    pub detail: String,
    /// How damaging this would be, as classified by the daemon.
    pub destructiveness: Destructiveness,
    /// Digest of the exact operation, to be signed by the presence key.
    ///
    /// Binding the signature to this digest is what stops one harvested from an
    /// innocuous approval being replayed onto a destructive one (§3.10).
    pub operation_digest: Digest,
}

/// Why a tracked long-running operation ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
#[non_exhaustive]
pub enum TaskOutcome {
    /// Finished successfully.
    Succeeded,
    /// Finished unsuccessfully.
    Failed {
        /// Short reason, suitable for a notification body.
        reason: String,
    },
    /// Cancelled by the user.
    Cancelled,
}

/// What an event is reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventPayload {
    /// One or more files changed inside a watched root.
    ///
    /// Batched because a `cargo build` or `npm install` produces thousands of
    /// changes; one event per change would saturate the connection (§12.6).
    FsChanged {
        /// The workspace root these paths are relative to.
        root: String,
        /// The coalesced changes.
        changes: Vec<FileChange>,
    },

    /// A terminal's process exited.
    ///
    /// Terminal *output* is not an event: it flows on the PTY's own stream as
    /// cell diffs (§10.2), so a noisy build cannot delay control traffic.
    PtyExited {
        /// Which terminal.
        pty_id: PtyId,
        /// Process exit code, absent if killed by a signal.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
    },

    /// Git state changed for a workspace — branch, dirty files, ahead/behind.
    ///
    /// Carries no detail, deliberately: it is a hint to refetch. Including a
    /// full status snapshot would mean recomputing it on every one of the
    /// hundreds of index writes a `git rebase` performs.
    GitStateChanged {
        /// The affected workspace root.
        root: String,
    },

    /// An agent session changed state.
    AgentStateChanged {
        /// Which session.
        session_id: AgentSessionId,
        /// Its new state.
        state: AgentState,
    },

    /// An agent is blocked awaiting an approval decision.
    AgentApprovalRequired {
        /// Which session.
        session_id: AgentSessionId,
        /// What is being asked.
        request: ApprovalRequest,
    },

    /// A tracked long-running operation finished.
    TaskFinished {
        /// Which task.
        task_id: TaskId,
        /// A short label, e.g. `"cargo test"`.
        label: String,
        /// How it ended.
        outcome: TaskOutcome,
    },

    /// Security policy changed; the client should refresh its view.
    ///
    /// Carries the new capability set so a client learns immediately that it has
    /// been restricted, rather than discovering it on the next denial.
    PolicyChanged {
        /// This device's capabilities after the change.
        capabilities: CapabilitySet,
    },

    /// Another device connected or disconnected.
    ///
    /// Surfaced so a user can see, from the phone, that something else is
    /// attached to their machine.
    DevicePresence {
        /// Which device.
        device_id: DeviceId,
        /// `true` on connect, `false` on disconnect.
        connected: bool,
    },
}

impl EventPayload {
    /// A stable code for logs, metrics, and per-type notification muting.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::FsChanged { .. } => "fs.changed",
            Self::PtyExited { .. } => "pty.exited",
            Self::GitStateChanged { .. } => "git.state_changed",
            Self::AgentStateChanged { .. } => "agent.state_changed",
            Self::AgentApprovalRequired { .. } => "agent.approval_required",
            Self::TaskFinished { .. } => "task.finished",
            Self::PolicyChanged { .. } => "policy.changed",
            Self::DevicePresence { .. } => "device.presence",
        }
    }

    /// Whether this event should reach the user while the app is backgrounded.
    ///
    /// The gate for the notification ladder (§24.1). Kept narrow on purpose: a
    /// tool that buzzes for every file save gets its notifications disabled
    /// wholesale, and then the approval that actually mattered is missed too.
    #[must_use]
    pub fn warrants_notification(&self) -> bool {
        match self {
            // `AgentApprovalRequired`: the user is the blocker — an agent waits
            // indefinitely until they answer.
            // `PolicyChanged` / `DevicePresence`: security-relevant. Learning
            // you have been restricted, or that an unexpected device attached to
            // your machine, should not wait for the app to be reopened.
            Self::AgentApprovalRequired { .. }
            | Self::PolicyChanged { .. }
            | Self::DevicePresence { .. } => true,

            // Report failures and successes, but not a cancellation the user
            // performed themselves and therefore already knows about.
            Self::TaskFinished { outcome, .. } => !matches!(outcome, TaskOutcome::Cancelled),

            // High-frequency and uninteresting while backgrounded.
            Self::FsChanged { .. }
            | Self::PtyExited { .. }
            | Self::GitStateChanged { .. }
            | Self::AgentStateChanged { .. } => false,
        }
    }
}

/// A sequenced server-pushed event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Monotonic, gap-free per connection. A gap means the client missed an
    /// event and must resynchronise.
    pub seq: u64,
    /// What happened.
    pub payload: EventPayload,
}

impl Event {
    /// Wraps a payload with a sequence number.
    #[must_use]
    pub const fn new(seq: u64, payload: EventPayload) -> Self {
        Self { seq, payload }
    }

    /// Whether `self` directly follows `previous_seq`.
    ///
    /// A client calls this on every event; `false` means resynchronise.
    #[must_use]
    pub const fn follows(&self, previous_seq: u64) -> bool {
        self.seq == previous_seq + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(event: &Event) -> Event {
        let mut buf = Vec::new();
        ciborium::into_writer(event, &mut buf).expect("serialize");
        ciborium::from_reader(buf.as_slice()).expect("deserialize")
    }

    fn one_of_each() -> Vec<EventPayload> {
        vec![
            EventPayload::FsChanged {
                root: "C:/dev/gonomad".into(),
                changes: vec![FileChange {
                    path: "src/main.rs".into(),
                    kind: FileChangeKind::Modified,
                    from: None,
                    is_dir: Some(false),
                    content_hash: Some(Digest::of(b"new")),
                }],
            },
            EventPayload::PtyExited {
                pty_id: 1,
                exit_code: Some(0),
            },
            EventPayload::GitStateChanged {
                root: "C:/dev/gonomad".into(),
            },
            EventPayload::AgentStateChanged {
                session_id: 2,
                state: AgentState::Thinking,
            },
            EventPayload::AgentApprovalRequired {
                session_id: 2,
                request: ApprovalRequest {
                    approval_id: 5,
                    summary: "Modify 3 files".into(),
                    detail: "diff --git a/x b/x".into(),
                    destructiveness: Destructiveness::Routine,
                    operation_digest: Digest::of(b"op"),
                },
            },
            EventPayload::TaskFinished {
                task_id: 3,
                label: "cargo test".into(),
                outcome: TaskOutcome::Failed {
                    reason: "2 tests failed".into(),
                },
            },
            EventPayload::PolicyChanged {
                capabilities: CapabilitySet::default_grant(),
            },
            EventPayload::DevicePresence {
                device_id: DeviceId::from_bytes([3u8; 32]),
                connected: true,
            },
        ]
    }

    #[test]
    fn every_payload_variant_is_covered_by_the_fixture() {
        let mut codes: Vec<&str> = one_of_each().iter().map(EventPayload::code).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(
            codes.len(),
            one_of_each().len(),
            "a variant is missing from the fixture"
        );
    }

    #[test]
    fn all_events_round_trip() {
        for (i, payload) in one_of_each().into_iter().enumerate() {
            let event = Event::new(i as u64, payload);
            assert_eq!(
                round_trip(&event),
                event,
                "round trip failed for {}",
                event.payload.code()
            );
        }
    }

    #[test]
    fn event_codes_are_unique_and_dotted() {
        for payload in one_of_each() {
            let code = payload.code();
            assert!(code.contains('.'), "{code} is not namespaced");
            assert_eq!(code, code.to_lowercase(), "{code} is not lowercase");
        }
    }

    #[test]
    fn sequence_gaps_are_detectable() {
        assert!(Event::new(6, EventPayload::GitStateChanged { root: "r".into() }).follows(5));
        // A gap: 5 then 7 means 6 was lost, and the client must resynchronise
        // rather than silently render a stale view.
        assert!(!Event::new(7, EventPayload::GitStateChanged { root: "r".into() }).follows(5));
        // A replay must not look like progress either.
        assert!(!Event::new(5, EventPayload::GitStateChanged { root: "r".into() }).follows(5));
    }

    #[test]
    fn only_user_relevant_events_warrant_a_notification() {
        // Kept narrow deliberately: buzzing for every file save gets
        // notifications disabled wholesale, and then approvals are missed too.
        let notifying: Vec<&str> = one_of_each()
            .iter()
            .filter(|p| p.warrants_notification())
            .map(EventPayload::code)
            .collect();
        assert!(notifying.contains(&"agent.approval_required"));
        assert!(notifying.contains(&"task.finished"));
        assert!(notifying.contains(&"policy.changed"));
        assert!(!notifying.contains(&"fs.changed"));
        assert!(!notifying.contains(&"agent.state_changed"));
    }

    #[test]
    fn cancelled_tasks_do_not_notify() {
        // The user cancelled it, so they already know.
        let cancelled = EventPayload::TaskFinished {
            task_id: 1,
            label: "build".into(),
            outcome: TaskOutcome::Cancelled,
        };
        assert!(!cancelled.warrants_notification());

        let failed = EventPayload::TaskFinished {
            task_id: 1,
            label: "build".into(),
            outcome: TaskOutcome::Failed {
                reason: "boom".into(),
            },
        };
        assert!(failed.warrants_notification());
    }

    #[test]
    fn approval_required_always_notifies() {
        // The one event where the user is the bottleneck: an agent blocks
        // indefinitely until they answer.
        for level in [
            Destructiveness::ReadOnly,
            Destructiveness::Routine,
            Destructiveness::Elevated,
            Destructiveness::Destructive,
        ] {
            let payload = EventPayload::AgentApprovalRequired {
                session_id: 1,
                request: ApprovalRequest {
                    approval_id: 1,
                    summary: "s".into(),
                    detail: "d".into(),
                    destructiveness: level,
                    operation_digest: Digest::of(b"o"),
                },
            };
            assert!(payload.warrants_notification(), "failed for {level:?}");
        }
    }

    #[test]
    fn destructiveness_gating_matches_the_threat_model() {
        assert!(!Destructiveness::ReadOnly.requires_presence());
        assert!(!Destructiveness::Routine.requires_presence());
        assert!(Destructiveness::Elevated.requires_presence());
        assert!(Destructiveness::Destructive.requires_presence());
    }

    #[test]
    fn destructiveness_orders_from_least_to_most_severe() {
        // Ordering is relied on for `>=` comparisons in policy checks.
        assert!(Destructiveness::ReadOnly < Destructiveness::Routine);
        assert!(Destructiveness::Routine < Destructiveness::Elevated);
        assert!(Destructiveness::Elevated < Destructiveness::Destructive);
    }

    #[test]
    fn agent_states_classify_correctly() {
        assert!(AgentState::AwaitingApproval.blocks_on_user());
        assert!(AgentState::AwaitingInput.blocks_on_user());
        assert!(!AgentState::Thinking.blocks_on_user());
        assert!(!AgentState::Idle.blocks_on_user());

        assert!(AgentState::Exited.is_terminal());
        assert!(
            !AgentState::Error.is_terminal(),
            "an errored agent may still recover"
        );
    }

    #[test]
    fn fs_changes_are_batched_in_a_single_event() {
        // One event per change would saturate the link during a build.
        let payload = EventPayload::FsChanged {
            root: "r".into(),
            changes: (0..500)
                .map(|i| FileChange {
                    path: format!("target/debug/{i}.o"),
                    kind: FileChangeKind::Created,
                    from: None,
                    is_dir: Some(false),
                    content_hash: None,
                })
                .collect(),
        };
        match round_trip(&Event::new(1, payload)) {
            Event {
                payload: EventPayload::FsChanged { changes, .. },
                ..
            } => {
                assert_eq!(changes.len(), 500);
            }
            other => panic!("expected FsChanged, got {other:?}"),
        }
    }

    #[test]
    fn renames_carry_the_previous_path() {
        let change = FileChange {
            path: "src/new.rs".into(),
            kind: FileChangeKind::Renamed,
            from: Some("src/old.rs".into()),
            is_dir: Some(false),
            content_hash: None,
        };
        let event = Event::new(
            1,
            EventPayload::FsChanged {
                root: "r".into(),
                changes: vec![change],
            },
        );
        match round_trip(&event) {
            Event {
                payload: EventPayload::FsChanged { changes, .. },
                ..
            } => {
                assert_eq!(changes[0].from.as_deref(), Some("src/old.rs"));
            }
            other => panic!("expected FsChanged, got {other:?}"),
        }
    }

    #[test]
    fn absent_optional_fields_are_omitted_from_the_wire() {
        let change = FileChange {
            path: "a".into(),
            kind: FileChangeKind::Created,
            from: None,
            is_dir: None,
            content_hash: None,
        };
        let json = serde_json::to_string(&change).unwrap();
        assert!(!json.contains("from"), "got {json}");
        assert!(!json.contains("is_dir"), "got {json}");
        assert!(!json.contains("content_hash"), "got {json}");
    }

    #[test]
    fn approval_detail_holds_the_real_change_not_a_summary() {
        // Documents the invariant: `detail` is the verbatim diff. A test cannot
        // enforce that the daemon populates it honestly, but it can pin the
        // intent so a future change to a summary string is deliberate.
        let request = ApprovalRequest {
            approval_id: 1,
            summary: "Modify config".into(),
            detail: "diff --git a/.env b/.env\n+SECRET=1".into(),
            destructiveness: Destructiveness::Destructive,
            operation_digest: Digest::of(b"op"),
        };
        assert!(request.detail.starts_with("diff --git"));
        assert_ne!(request.detail, request.summary);
    }

    proptest::proptest! {
        /// Deserializing arbitrary bytes as an event must never panic.
        #[test]
        fn decoding_arbitrary_bytes_never_panics(bytes: Vec<u8>) {
            let _ = ciborium::from_reader::<Event, _>(bytes.as_slice());
        }

        #[test]
        fn follows_is_true_only_for_the_immediate_successor(prev: u64, next: u64) {
            proptest::prop_assume!(prev < u64::MAX);
            let event = Event::new(next, EventPayload::GitStateChanged { root: "r".into() });
            proptest::prop_assert_eq!(event.follows(prev), next == prev + 1);
        }
    }
}
