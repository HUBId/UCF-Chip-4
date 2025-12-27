#![forbid(unsafe_code)]

#[cfg(feature = "rpp-proof-envelope")]
mod envelope {
    use blake3::Hasher;

    pub const DIGEST_LENGTH: usize = 32;
    pub const MAX_PROOF_BYTES: usize = 1_048_576;
    pub const ACCUMULATOR_DOMAIN: &[u8] = b"UCF:RPP:ACC";

    pub type Digest = [u8; DIGEST_LENGTH];

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RppPublicInputs {
        pub prev_acc_digest: Digest,
        pub acc_digest: Digest,
        pub prev_root: Digest,
        pub new_root: Digest,
        pub payload_digest: Digest,
        pub ruleset_digest: Digest,
        pub asset_manifest_digest_or_zero: Digest,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RppProofEnvelope {
        pub prev_acc_digest: Digest,
        pub acc_digest: Digest,
        pub prev_root_proof: Vec<u8>,
        pub new_root_proof: Vec<u8>,
        pub payload_proof: Vec<u8>,
        pub ruleset_proof: Vec<u8>,
        pub asset_manifest_proof: Vec<u8>,
    }

    impl RppProofEnvelope {
        #[allow(clippy::missing_const_for_fn)]
        fn proofs_within_limits(&self) -> bool {
            self.prev_root_proof.len() <= MAX_PROOF_BYTES
                && self.new_root_proof.len() <= MAX_PROOF_BYTES
                && self.payload_proof.len() <= MAX_PROOF_BYTES
                && self.ruleset_proof.len() <= MAX_PROOF_BYTES
                && self.asset_manifest_proof.len() <= MAX_PROOF_BYTES
        }
    }

    #[must_use]
    pub fn verify_transition(pub_inputs: &RppPublicInputs, envelope: &RppProofEnvelope) -> bool {
        if pub_inputs.prev_acc_digest != envelope.prev_acc_digest {
            return false;
        }

        if pub_inputs.acc_digest != envelope.acc_digest {
            return false;
        }

        if !envelope.proofs_within_limits() {
            return false;
        }

        let recomputed = compute_accumulator_digest(
            pub_inputs.prev_acc_digest,
            pub_inputs.prev_root,
            pub_inputs.new_root,
            pub_inputs.payload_digest,
            pub_inputs.ruleset_digest,
            pub_inputs.asset_manifest_digest_or_zero,
        );

        recomputed == pub_inputs.acc_digest
    }

    #[must_use]
    pub fn compute_accumulator_digest(
        prev_acc_digest: Digest,
        prev_root: Digest,
        new_root: Digest,
        payload_digest: Digest,
        ruleset_digest: Digest,
        asset_manifest_digest_or_zero: Digest,
    ) -> Digest {
        let mut hasher = Hasher::new();
        hasher.update(ACCUMULATOR_DOMAIN);
        hasher.update(&prev_acc_digest);
        hasher.update(&prev_root);
        hasher.update(&new_root);
        hasher.update(&payload_digest);
        hasher.update(&ruleset_digest);
        hasher.update(&asset_manifest_digest_or_zero);
        *hasher.finalize().as_bytes()
    }
}

#[cfg(feature = "rpp-proof-envelope")]
pub use envelope::{
    compute_accumulator_digest, verify_transition, Digest, RppProofEnvelope, RppPublicInputs,
    ACCUMULATOR_DOMAIN, DIGEST_LENGTH, MAX_PROOF_BYTES,
};

#[cfg(all(test, feature = "rpp-proof-envelope"))]
mod tests {
    use super::{compute_accumulator_digest, verify_transition, Digest, RppProofEnvelope, RppPublicInputs};

    #[test]
    fn accumulator_digest_is_deterministic() {
        let prev_acc = [1u8; 32];
        let prev_root = [2u8; 32];
        let new_root = [3u8; 32];
        let payload = [4u8; 32];
        let ruleset = [5u8; 32];
        let asset = [6u8; 32];

        let first = compute_accumulator_digest(prev_acc, prev_root, new_root, payload, ruleset, asset);
        let second = compute_accumulator_digest(prev_acc, prev_root, new_root, payload, ruleset, asset);

        assert_eq!(first, second);
    }

    #[test]
    fn verifier_fails_closed_on_mismatched_digest() {
        let prev_acc = [7u8; 32];
        let prev_root = [8u8; 32];
        let new_root = [9u8; 32];
        let payload = [10u8; 32];
        let ruleset = [11u8; 32];
        let asset = [12u8; 32];

        let acc = compute_accumulator_digest(prev_acc, prev_root, new_root, payload, ruleset, asset);
        let pub_inputs = RppPublicInputs {
            prev_acc_digest: prev_acc,
            acc_digest: acc,
            prev_root,
            new_root,
            payload_digest: payload,
            ruleset_digest: ruleset,
            asset_manifest_digest_or_zero: asset,
        };

        let mut envelope = RppProofEnvelope {
            prev_acc_digest: prev_acc,
            acc_digest: acc,
            prev_root_proof: Vec::new(),
            new_root_proof: Vec::new(),
            payload_proof: Vec::new(),
            ruleset_proof: Vec::new(),
            asset_manifest_proof: Vec::new(),
        };

        assert!(verify_transition(&pub_inputs, &envelope));

        envelope.acc_digest = Digest::from([0u8; 32]);
        assert!(!verify_transition(&pub_inputs, &envelope));
    }
}
