# Policy Condition Audit

Condition text comes directly from `dataset/deletion_rules.csv`. The evaluator does not treat an absent fact as false.

| Rule condition | Implemented evidence | False / unknown handling |
|---|---|---|
| `Always` | Unconditional true. | Applies the rule action. |
| Shared support context | Explicit shared-context flags or literal order references; excerpts that explicitly mention a customer or agent also establish shared conversation context. | False falls back to deleting the message; conflicting explicit classification is unresolved. |
| Attachment belongs only to subject | Explicit ownership boolean (`belongs_only_to_subject`, `subject_only`, or `exclusive_to_subject`). | False or unknown stays unresolved because deleting shared material is not authorized by this rule. |
| Analytics/telemetry attributable | Explicit attribution flag or parsed subject identifiers. | False is no-action only when the observed record is already absent/redacted/anonymized; otherwise status remains incomplete. |
| Email delivery log contains email | Explicit email-presence flag or parsed email field. | False is no-action; unknown remains unresolved. |
| Security record within retention | Valid `retention_until` / `retained_until` compared with `audit_at`; boundary is exclusive. | Before deadline: retain. At/after deadline: delete. Missing/invalid date: unresolved. |
| Legal hold active | Explicit `hold_active`, `legal_hold_active`, or `active` boolean only. A retention date is not silently converted into a hold-status fact. | Inactive falls back to deletion; missing/ambiguous status is unresolved. |
| Backup access can be blocked | Explicit `restore_blockable` / `can_block_restore` attestation. `restore_allowed=false` proves current block state, not general capability. | False or missing is unresolved; no unsupported successful control is claimed. |
| Tombstone condition | Explicit deleted status and stable-reference requirement, or deleted account plus a linked retained record using the stable `user_id`. | False falls back to deletion; missing evidence is unresolved. |

Condition-unresolved cases are forced to `INCOMPLETE`. Because the CSV contract has no UNKNOWN state or policy-condition step, the reason is recorded in the reason-coded diagnostic artifact; unresolved obligations may not have a representable step in `steps_json`.
