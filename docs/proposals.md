# Proposal evidence payloads

`ProposalEvidenceAppend` commits carry a deterministic binary payload representing a
`ProposalEvidence` entry. The payload is append-only and must be encoded identically by all
participants.

## Encoding

All integers are big-endian. Strings are UTF-8 and length-prefixed with a `u16`. String length
caps are enforced during validation and decoding.

Field order:

1. `proposal_id` (u16 length + bytes, max 128 bytes)
2. `proposal_digest` (32 bytes)
3. `kind` (u8)
   - `1` = `MappingUpdate`
   - `2` = `SaePackUpdate`
   - `3` = `LiquidParamsUpdate`
   - `4` = `InjectionLimitsUpdate`
4. `base_evidence_digest` (32 bytes)
5. `payload_digest` (32 bytes)
6. `created_at_ms` (u64)
7. `score` (i32)
8. `verdict` (u8)
   - `0` = `NEUTRAL`
   - `1` = `PROMISING`
   - `2` = `RISKY`
9. `reason_codes` count (u16, max 16)
10. `reason_codes` entries (each is a u16 length + bytes, max 64 bytes each)

`reason_codes` must be sorted lexicographically and de-duplicated before encoding.
