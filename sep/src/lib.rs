#![forbid(unsafe_code)]

use blake3::Hasher;
use limits::StoreLimits;
use log::warn;
use std::collections::HashMap;
use thiserror::Error;
use ucf_protocol::ucf::v1::ReasonCodes;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// SEP event type enumeration.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SepEventType {
    EvIncident,
    EvDecision,
    EvRecoveryGov,
    EvRecovery,
    EvPevUpdate,
    EvKeyEpoch,
    EvToolOnboarding,
    EvCharterUpdate,
    EvControlFrame,
    EvSignalFrame,
    EvOutcome,
    EvDlpDecision,
    EvOutput,
    EvProfileChange,
    EvAgentStep,
    EvIntent,
    EvReplay,
}

impl SepEventType {
    fn as_str(&self) -> &'static str {
        match self {
            SepEventType::EvIncident => "EV_INCIDENT",
            SepEventType::EvDecision => "EV_DECISION",
            SepEventType::EvRecoveryGov => "EV_RECOVERY_GOV",
            SepEventType::EvRecovery => "EV_RECOVERY",
            SepEventType::EvPevUpdate => "EV_PEV_UPDATE",
            SepEventType::EvKeyEpoch => "EV_KEY_EPOCH",
            SepEventType::EvToolOnboarding => "EV_TOOL_ONBOARDING",
            SepEventType::EvCharterUpdate => "EV_CHARTER_UPDATE",
            SepEventType::EvControlFrame => "EV_CONTROL_FRAME",
            SepEventType::EvSignalFrame => "EV_SIGNAL_FRAME",
            SepEventType::EvOutcome => "EV_OUTCOME",
            SepEventType::EvDlpDecision => "EV_DLP_DECISION",
            SepEventType::EvOutput => "EV_OUTPUT",
            SepEventType::EvProfileChange => "EV_PROFILE_CHANGE",
            SepEventType::EvAgentStep => "EV_AGENT_STEP",
            SepEventType::EvIntent => "EV_INTENT",
            SepEventType::EvReplay => "EV_REPLAY",
        }
    }
}

/// Frame event kind used for frame evidence logging.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameEventKind {
    ControlFrame,
    SignalFrame,
}

/// Internal representation of SEP events with digests.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SepEventInternal {
    pub session_id: String,
    pub event_type: SepEventType,
    pub object_digest: [u8; 32],
    pub reason_codes: Vec<String>,
    pub prev_event_digest: [u8; 32],
    pub event_digest: [u8; 32],
}

/// Append-only SEP log.
#[derive(Debug, Default, Clone)]
pub struct SepLog {
    pub events: Vec<SepEventInternal>,
    pub limits: StoreLimits,
}

impl SepLog {
    pub fn new(limits: StoreLimits) -> Self {
        Self {
            events: Vec::new(),
            limits,
        }
    }

    /// Append a new event to the log, computing the chained digest.
    pub fn append_event(
        &mut self,
        session_id: String,
        event_type: SepEventType,
        object_digest: [u8; 32],
        reason_codes: Vec<String>,
    ) -> Result<SepEventInternal, SepError> {
        if self.events.len() >= self.limits.max_sep_events {
            let mut failure_reason_codes = reason_codes;
            failure_reason_codes.push(ReasonCodes::RE_INTEGRITY_FAIL.to_string());
            let event =
                self.build_event(session_id, event_type, object_digest, failure_reason_codes);
            self.events.push(event.clone());
            return Err(SepError::Overflow);
        }

        let event = self.build_event(session_id, event_type, object_digest, reason_codes);
        self.events.push(event.clone());
        Ok(event)
    }

    /// Append a control or signal frame event to the log.
    pub fn append_frame_event(
        &mut self,
        session_id: String,
        kind: FrameEventKind,
        frame_digest: [u8; 32],
        reason_codes: Vec<String>,
    ) -> Result<SepEventInternal, SepError> {
        let event_type = match kind {
            FrameEventKind::ControlFrame => SepEventType::EvControlFrame,
            FrameEventKind::SignalFrame => SepEventType::EvSignalFrame,
        };

        self.append_event(session_id, event_type, frame_digest, reason_codes)
    }

    /// Validate the entire event chain for tamper evidence.
    pub fn validate_chain(&self) -> Result<(), SepError> {
        for idx in 0..self.events.len() {
            let event = &self.events[idx];
            if idx == 0 {
                if event.prev_event_digest != [0u8; 32] {
                    return Err(SepError::ChainBroken(idx));
                }
            } else {
                let prev = &self.events[idx - 1];
                if event.prev_event_digest != prev.event_digest {
                    return Err(SepError::ChainBroken(idx));
                }
            }

            let computed = compute_event_digest(
                &event.session_id,
                &event.event_type,
                &event.object_digest,
                &event.reason_codes,
                event.prev_event_digest,
            );
            if computed != event.event_digest {
                return Err(SepError::ChainBroken(idx));
            }
        }
        Ok(())
    }

    fn build_event(
        &self,
        session_id: String,
        event_type: SepEventType,
        object_digest: [u8; 32],
        reason_codes: Vec<String>,
    ) -> SepEventInternal {
        let prev_event_digest = self
            .events
            .last()
            .map(|e| e.event_digest)
            .unwrap_or([0u8; 32]);
        let event_digest = compute_event_digest(
            &session_id,
            &event_type,
            &object_digest,
            &reason_codes,
            prev_event_digest,
        );

        SepEventInternal {
            session_id,
            event_type,
            object_digest,
            reason_codes,
            prev_event_digest,
            event_digest,
        }
    }
}

/// Canonical node identifier for causal graph nodes.
pub type NodeKey = [u8; 32];

/// Edge relationship between two nodes.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EdgeType {
    Causes,
    Decides,
    Authorizes,
    Dispatches,
    Finalizes,
    References,
}

/// In-memory causal graph index with forward and reverse adjacency.
#[derive(Debug, Clone, Default)]
pub struct CausalGraph {
    pub adj: HashMap<NodeKey, Vec<(EdgeType, NodeKey)>>,
    pub rev: HashMap<NodeKey, Vec<(EdgeType, NodeKey)>>,
    pub limits: StoreLimits,
}

const EMPTY_EDGES: &[(EdgeType, NodeKey)] = &[];

impl CausalGraph {
    /// Create a new empty graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new empty graph that respects the provided limits.
    pub fn with_limits(limits: StoreLimits) -> Self {
        Self {
            limits,
            ..Default::default()
        }
    }

    /// Add an edge to the graph, enforcing per-node limits and dropping the
    /// oldest edge when the limit is exceeded.
    pub fn add_edge(
        &mut self,
        from: NodeKey,
        et: EdgeType,
        to: NodeKey,
        sep_log: Option<(&mut SepLog, &str)>,
    ) {
        if self.edge_exists(&from, et, &to) {
            return;
        }

        let mut sep_log = sep_log;

        if let Some((old_et, old_to)) = self.prune_if_needed(&from, true) {
            self.remove_edge_from(&old_to, old_et, &from, false);
            self.log_trimmed_edge(sep_log.as_mut(), &from, (old_et, old_to), true);
        }
        self.adj.entry(from).or_default().push((et, to));

        if let Some((old_et, old_from)) = self.prune_if_needed(&to, false) {
            self.remove_edge_from(&old_from, old_et, &to, true);
            self.log_trimmed_edge(sep_log.as_mut(), &to, (old_et, old_from), false);
        }
        self.rev.entry(to).or_default().push((et, from));
    }

    /// Forward neighbors for a node.
    pub fn neighbors(&self, node: NodeKey) -> &[(EdgeType, NodeKey)] {
        self.adj
            .get(&node)
            .map(|v| v.as_slice())
            .unwrap_or(EMPTY_EDGES)
    }

    /// Reverse neighbors for a node.
    pub fn reverse_neighbors(&self, node: NodeKey) -> &[(EdgeType, NodeKey)] {
        self.rev
            .get(&node)
            .map(|v| v.as_slice())
            .unwrap_or(EMPTY_EDGES)
    }

    fn edge_exists(&self, from: &NodeKey, et: EdgeType, to: &NodeKey) -> bool {
        self.adj
            .get(from)
            .map(|edges| edges.iter().any(|(e, dst)| *e == et && dst == to))
            .unwrap_or(false)
    }

    fn prune_if_needed(&mut self, node: &NodeKey, forward: bool) -> Option<(EdgeType, NodeKey)> {
        let map = if forward {
            &mut self.adj
        } else {
            &mut self.rev
        };
        let edges = map.get_mut(node)?;
        if edges.len() < self.limits.max_graph_edges_per_node {
            return None;
        }

        let removed = edges.remove(0);
        warn!(
            "edge limit exceeded for node {:?} (forward={}), dropping oldest edge",
            node, forward
        );
        Some(removed)
    }

    fn log_trimmed_edge(
        &self,
        sep_log: Option<&mut (&mut SepLog, &str)>,
        trimmed_node: &NodeKey,
        removed_edge: (EdgeType, NodeKey),
        forward: bool,
    ) {
        if let Some((log, session_id)) = sep_log {
            let (_, neighbor) = removed_edge;
            if let Err(err) = log.append_event(
                session_id.to_string(),
                SepEventType::EvOutcome,
                *trimmed_node,
                vec![ReasonCodes::GV_GRAPH_TRIMMED.to_string()],
            ) {
                warn!(
                    "failed to log graph trim for node {:?} (neighbor={:?}, forward={}): {}",
                    trimmed_node, neighbor, forward, err
                );
            }
        }
    }

    fn remove_edge_from(&mut self, node: &NodeKey, et: EdgeType, target: &NodeKey, forward: bool) {
        let map = if forward {
            &mut self.adj
        } else {
            &mut self.rev
        };
        if let Some(edges) = map.get_mut(node) {
            if let Some(pos) = edges
                .iter()
                .position(|(edge_type, neighbor)| *edge_type == et && neighbor == target)
            {
                edges.remove(pos);
            }
        }
    }
}

/// Session seal capturing the final event digest.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSeal {
    pub seal_id: String,
    pub session_id: String,
    pub final_event_digest: [u8; 32],
    pub created_at_ms: u64,
}

/// Create a session seal using the last event digest for the given session.
pub fn seal(session_id: &str, log: &SepLog) -> SessionSeal {
    let final_event_digest = log
        .events
        .iter()
        .rev()
        .find(|e| e.session_id == session_id)
        .map(|e| e.event_digest)
        .unwrap_or([0u8; 32]);

    let created_at_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let digest_prefix: String = final_event_digest
        .iter()
        .take(4)
        .map(|b| format!("{:02x}", b))
        .collect();
    let seal_id = format!("seal:{session_id}:{digest_prefix}");

    SessionSeal {
        seal_id,
        session_id: session_id.to_string(),
        final_event_digest,
        created_at_ms,
    }
}

fn compute_event_digest(
    session_id: &str,
    event_type: &SepEventType,
    object_digest: &[u8; 32],
    reason_codes: &[String],
    prev_event_digest: [u8; 32],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(b"UCF:SEP:EVENT");
    hasher.update(session_id.as_bytes());
    hasher.update(event_type.as_str().as_bytes());
    hasher.update(object_digest);
    for rc in reason_codes {
        hasher.update(rc.as_bytes());
    }
    hasher.update(&prev_event_digest);
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SepError {
    #[error("event chain broken at index {0}")]
    ChainBroken(usize),
    #[error("sep log overflow")]
    Overflow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_sep_chain() {
        let mut log = SepLog::default();
        let e1 = log
            .append_event("s".to_string(), SepEventType::EvDecision, [1u8; 32], vec![])
            .unwrap();
        let _ = log
            .append_event(
                "s".to_string(),
                SepEventType::EvRecoveryGov,
                [2u8; 32],
                vec![],
            )
            .unwrap();
        let _ = log
            .append_event("s".to_string(), SepEventType::EvDecision, [3u8; 32], vec![])
            .unwrap();

        assert!(log.validate_chain().is_ok());

        // Tamper with prev digest
        let mut tampered = log.clone();
        tampered.events[1].prev_event_digest = e1.prev_event_digest;
        assert!(tampered.validate_chain().is_err());
    }

    #[test]
    fn seal_uses_last_event_digest() {
        let mut log = SepLog::default();
        log.append_event(
            "session-1".to_string(),
            SepEventType::EvDecision,
            [1u8; 32],
            vec![],
        )
        .unwrap();
        log.append_event(
            "session-1".to_string(),
            SepEventType::EvDecision,
            [9u8; 32],
            vec![],
        )
        .unwrap();

        let seal = seal("session-1", &log);
        assert_eq!(
            seal.final_event_digest,
            log.events.last().unwrap().event_digest
        );
    }

    #[test]
    fn sep_log_overflow_adds_integrity_failure_reason() {
        let mut log = SepLog::new(StoreLimits {
            max_sep_events: 1,
            ..Default::default()
        });

        log.append_event(
            "overflow".to_string(),
            SepEventType::EvDecision,
            [1u8; 32],
            vec!["RC.TEST.ONE".to_string()],
        )
        .unwrap();

        let err = log
            .append_event(
                "overflow".to_string(),
                SepEventType::EvDecision,
                [2u8; 32],
                Vec::new(),
            )
            .unwrap_err();

        assert_eq!(err, SepError::Overflow);
        let last = log.events.last().expect("overflow event");
        assert!(last
            .reason_codes
            .contains(&ReasonCodes::RE_INTEGRITY_FAIL.to_string()));
    }

    #[test]
    fn causal_graph_prunes_edges_and_logs_sep_event() {
        let mut graph = CausalGraph::with_limits(StoreLimits {
            max_graph_edges_per_node: 1,
            ..Default::default()
        });
        let mut sep_log = SepLog::default();

        let node_a = [1u8; 32];
        let node_b = [2u8; 32];
        let node_c = [3u8; 32];
        let node_d = [4u8; 32];

        graph.add_edge(
            node_a,
            EdgeType::Causes,
            node_b,
            Some((&mut sep_log, "graph-test")),
        );
        graph.add_edge(
            node_a,
            EdgeType::Causes,
            node_c,
            Some((&mut sep_log, "graph-test")),
        );

        assert_eq!(graph.neighbors(node_a), &[(EdgeType::Causes, node_c)]);
        assert!(graph.reverse_neighbors(node_b).is_empty());

        graph.add_edge(
            node_d,
            EdgeType::Causes,
            node_c,
            Some((&mut sep_log, "graph-test")),
        );

        assert!(graph.neighbors(node_a).is_empty());
        assert_eq!(
            graph.reverse_neighbors(node_c),
            &[(EdgeType::Causes, node_d)]
        );

        let trimmed_events = sep_log
            .events
            .iter()
            .filter(|event| {
                event
                    .reason_codes
                    .contains(&ReasonCodes::GV_GRAPH_TRIMMED.to_string())
            })
            .count();
        assert!(trimmed_events >= 2);
    }

    #[test]
    fn causal_graph_trimming_is_deterministic() {
        fn build_graph() -> (CausalGraph, SepLog) {
            let mut graph = CausalGraph::with_limits(StoreLimits {
                max_graph_edges_per_node: 1,
                ..Default::default()
            });
            let mut sep_log = SepLog::default();

            let node_a = [1u8; 32];
            let node_b = [2u8; 32];
            let node_c = [3u8; 32];

            graph.add_edge(
                node_a,
                EdgeType::References,
                node_b,
                Some((&mut sep_log, "graph-determinism")),
            );
            graph.add_edge(
                node_a,
                EdgeType::References,
                node_c,
                Some((&mut sep_log, "graph-determinism")),
            );

            (graph, sep_log)
        }

        let (graph_one, log_one) = build_graph();
        let (graph_two, log_two) = build_graph();

        assert_eq!(graph_one.adj, graph_two.adj);
        assert_eq!(graph_one.rev, graph_two.rev);
        assert_eq!(log_one.events.len(), log_two.events.len());
        for (first, second) in log_one.events.iter().zip(log_two.events.iter()) {
            assert_eq!(first.event_digest, second.event_digest);
            assert!(first
                .reason_codes
                .contains(&ReasonCodes::GV_GRAPH_TRIMMED.to_string()));
        }
    }
}
