# Evaluation Report

Generated from the participant-visible public sample and current pipeline output.

## Public sample

| Metric | Result |
|---|---:|
| Deletion-status accuracy | 28 / 32 (87.50%) |
| Position-aligned exact step recall | 66 / 193 (34.20%) |
| Position-aligned exact step precision | 66 / 123 (53.66%) |
| Field accuracy | 640 / 1351 (47.37%) |
| Exact ordered status and sequence accuracy | 1 / 32 (3.12%) |

The evaluator compares decoded JSON arrays in order; whitespace and object-key order do not affect its score. The public sample was used during development and is not a blind holdout.

## Participant-created regression scenarios

The current suite has 41 tests. Condition-specific cases exercise active, inactive, missing, and conflicting legal-hold evidence; support messages with shared context, without shared context, and with unknown/ambiguous context; and verify the resulting finding, remediation, verification, and status.

Other tests cover historical identifiers, missing evidence, retention boundaries, anonymization, tombstones, active flows, restore risk, equal-time replica conflicts, and deterministic step ordering.

## Findings and limitations

Policy conditions now use three-valued evaluation. Actions are selected only when supported facts establish the condition; explicitly false conditions use a documented fallback where the erasure rules support one; missing or contradictory facts remain unresolved and cannot support `COMPLETE`.

This pass yields 28/32 public statuses and 1/32 exact sequences. The public sample was used as a diagnostic during development; no sample IDs or expected outputs are special-cased.

Exact-step mismatches remain concentrated in incomplete identity/resource links and unresolved policy conditions. Missing or conflicting evidence remains unresolved rather than being treated as proof of deletion or retention.

The evidence inventory is open-world. A `COMPLETE` result covers discovered resources only; supplied evidence does not establish that every company system or restore path has been inventoried. Hidden-set accuracy is unknown.

Final generated output has 518 rows: 94 `COMPLETE`, 414 `INCOMPLETE`, 10 `NOT_APPLICABLE`. The independent output validator and full test suite must pass on this same artifact before submission.
