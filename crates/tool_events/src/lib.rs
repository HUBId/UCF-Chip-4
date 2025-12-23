#![forbid(unsafe_code)]

use blake3::Hasher;
use limits::StoreLimits;
use prost::Message;
use std::collections::HashMap;
use std::convert::TryFrom;
use thiserror::Error;
use ucf_protocol::ucf::v1::{ToolOnboardingEvent, ToolOnboardingStage};

const TOOL_EVENT_DOMAIN: &[u8] = b"UCF:HASH:TOOL_ONBOARDING_EVENT";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ToolEventError {
    #[error("event id is required")]
    MissingEventId,
    #[error("tool id is required")]
    MissingToolId,
    #[error("invalid stage")]
    InvalidStage,
    #[error("too many reason codes")]
    TooManyReasonCodes,
    #[error("too many signatures")]
    TooManySignatures,
    #[error("invalid event digest length")]
    InvalidDigestLength,
    #[error("event digest mismatch")]
    DigestMismatch,
}

#[derive(Debug, Clone, Default)]
pub struct ToolEventStore {
    events: Vec<ToolOnboardingEvent>,
    by_tool_action: HashMap<(String, String), Vec<[u8; 32]>>,
    by_digest: HashMap<[u8; 32], ToolOnboardingEvent>,
    limits: StoreLimits,
}

impl ToolEventStore {
    pub fn with_limits(limits: StoreLimits) -> Self {
        Self {
            limits,
            ..Default::default()
        }
    }

    pub fn insert(&mut self, mut event: ToolOnboardingEvent) -> Result<[u8; 32], ToolEventError> {
        validate_event(&event, &self.limits)?;
        normalize_event(&mut event);

        let computed = compute_event_digest(&event)?;
        if let Some(provided) = event
            .event_digest
            .as_deref()
            .and_then(|digest| digest_from_bytes(Some(digest)))
        {
            if provided != computed {
                return Err(ToolEventError::DigestMismatch);
            }
        }

        event.event_digest = Some(computed.to_vec());

        self.events.push(event.clone());
        self.by_digest.insert(computed, event.clone());

        let key = (event.tool_id.clone(), event.action_id.clone());
        let entry = self.by_tool_action.entry(key).or_default();
        entry.push(computed);
        if self.limits.max_tool_events_per_action > 0
            && entry.len() > self.limits.max_tool_events_per_action
        {
            entry.remove(0);
        }

        Ok(computed)
    }

    pub fn get(&self, digest: [u8; 32]) -> Option<&ToolOnboardingEvent> {
        self.by_digest.get(&digest)
    }

    pub fn list_for(&self, tool_id: &str, action_id: &str) -> Vec<ToolOnboardingEvent> {
        let mut events: Vec<_> = self
            .events
            .iter()
            .filter(|event| event.tool_id == tool_id && event.action_id == action_id)
            .cloned()
            .collect();

        events.sort_by(|a, b| {
            a.event_id.cmp(&b.event_id).then_with(|| {
                digest_from_bytes(a.event_digest.as_deref())
                    .cmp(&digest_from_bytes(b.event_digest.as_deref()))
            })
        });

        events
    }

    pub fn latest_for(
        &self,
        tool_id: &str,
        action_id: &str,
    ) -> Option<(&ToolOnboardingEvent, usize)> {
        let mut latest: Option<(&ToolOnboardingEvent, usize)> = None;

        for (idx, event) in self.events.iter().enumerate() {
            if event.tool_id != tool_id || event.action_id != action_id {
                continue;
            }

            if let Some((prev, prev_idx)) = latest {
                if is_newer(event, idx, prev, prev_idx) {
                    latest = Some((event, idx));
                }
            } else {
                latest = Some((event, idx));
            }
        }

        latest
    }

    pub fn iter(&self) -> impl Iterator<Item = &ToolOnboardingEvent> {
        self.events.iter()
    }
}

fn is_newer(
    current: &ToolOnboardingEvent,
    current_idx: usize,
    prev: &ToolOnboardingEvent,
    prev_idx: usize,
) -> bool {
    match (current.created_at_ms, prev.created_at_ms) {
        (Some(a), Some(b)) => a > b || (a == b && current_idx > prev_idx),
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => current_idx > prev_idx,
    }
}

fn validate_event(event: &ToolOnboardingEvent, limits: &StoreLimits) -> Result<(), ToolEventError> {
    if event.event_id.is_empty() {
        return Err(ToolEventError::MissingEventId);
    }

    if event.tool_id.is_empty() {
        return Err(ToolEventError::MissingToolId);
    }

    if ToolOnboardingStage::try_from(event.stage).is_err() {
        return Err(ToolEventError::InvalidStage);
    }

    if limits.max_tool_event_reason_codes > 0
        && event.reason_codes.len() > limits.max_tool_event_reason_codes
    {
        return Err(ToolEventError::TooManyReasonCodes);
    }

    if limits.max_tool_event_signatures > 0
        && event.signatures.len() > limits.max_tool_event_signatures
    {
        return Err(ToolEventError::TooManySignatures);
    }

    if event
        .event_digest
        .as_ref()
        .is_some_and(|digest| digest.len() != 32)
    {
        return Err(ToolEventError::InvalidDigestLength);
    }

    Ok(())
}

pub fn compute_event_digest(event: &ToolOnboardingEvent) -> Result<[u8; 32], ToolEventError> {
    let mut canonical = event.clone();
    canonical.event_digest = None;
    normalize_event(&mut canonical);

    let mut hasher = Hasher::new();
    hasher.update(TOOL_EVENT_DOMAIN);
    let bytes = canonical.encode_to_vec();
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

fn normalize_event(event: &mut ToolOnboardingEvent) {
    event.reason_codes.sort();
    event.reason_codes.dedup();
    event.signatures.sort();
}

fn digest_from_bytes(bytes: Option<&[u8]>) -> Option<[u8; 32]> {
    let data = bytes?;
    if data.len() != 32 {
        return None;
    }

    let mut digest = [0u8; 32];
    digest.copy_from_slice(data);
    Some(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(stage: ToolOnboardingStage) -> ToolOnboardingEvent {
        ToolOnboardingEvent {
            event_id: "evt".to_string(),
            stage: stage as i32,
            tool_id: "tool".to_string(),
            action_id: "action".to_string(),
            reason_codes: vec!["b".to_string(), "a".to_string()],
            signatures: vec![vec![1, 2, 3]],
            event_digest: None,
            created_at_ms: Some(10),
        }
    }

    #[test]
    fn computes_stable_digest() {
        let event = sample_event(ToolOnboardingStage::To6Suspended);
        let digest = compute_event_digest(&event).unwrap();
        let digest_again = compute_event_digest(&event).unwrap();
        assert_eq!(digest, digest_again);
    }

    #[test]
    fn rejects_missing_fields() {
        let mut store = ToolEventStore::default();
        let mut event = sample_event(ToolOnboardingStage::To6Suspended);
        event.tool_id.clear();
        let err = store.insert(event).unwrap_err();
        assert_eq!(err, ToolEventError::MissingToolId);
    }

    #[test]
    fn sorts_event_fields_and_indexes() {
        let mut store = ToolEventStore::with_limits(StoreLimits::default());
        let mut event = sample_event(ToolOnboardingStage::To6Suspended);
        event.reason_codes.push("a".to_string());
        event.signatures.push(vec![0]);

        let digest = store.insert(event).unwrap();
        let stored = store.get(digest).unwrap();
        assert_eq!(stored.reason_codes, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(stored.signatures, vec![vec![0], vec![1, 2, 3]]);

        let events = store.list_for("tool", "action");
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn latest_prefers_created_at_then_insertion() {
        let mut store = ToolEventStore::default();
        let mut early = sample_event(ToolOnboardingStage::To1Validated);
        early.created_at_ms = Some(5);
        let mut late = sample_event(ToolOnboardingStage::To6Suspended);
        late.created_at_ms = Some(6);
        late.event_id = "evt-2".to_string();

        store.insert(early).unwrap();
        store.insert(late.clone()).unwrap();

        let (latest, _) = store.latest_for("tool", "action").expect("missing latest");
        assert_eq!(latest.event_id, late.event_id);
    }

    #[test]
    fn index_is_bounded() {
        let mut store = ToolEventStore::with_limits(StoreLimits {
            max_tool_events_per_action: 1,
            ..Default::default()
        });

        store
            .insert(sample_event(ToolOnboardingStage::To1Validated))
            .unwrap();
        store
            .insert(sample_event(ToolOnboardingStage::To2Enabled))
            .unwrap();

        let digests = store
            .by_tool_action
            .get(&("tool".to_string(), "action".to_string()))
            .expect("missing index");
        assert_eq!(digests.len(), 1);
    }
}
