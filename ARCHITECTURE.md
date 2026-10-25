# Architecture

The solution is a deterministic, local deletion-audit pipeline.

1. `code/main.py` loads each request, checks deletion authorization, resolves the Data Subject using current and historical identity claims, retrieves linked resources through evidence and catalog lineage, applies policy, and emits ordered steps.
2. `code/identity.py` indexes identity attributes and historical change events with temporal ownership windows. Ambiguous identity resolution fails closed.
3. `code/ingestion.py` reads participant-facing evidence files and global activity into normalized evidence records with manifest provenance, observation times, and resource locations.
4. `code/evidence.py` associates evidence with subjects and resources, carries explicit source-resource lineage, reconciles snapshots by observation time, marks equal-time state conflicts `UNKNOWN`, and evaluates state at the request's `audit_at` cutoff.
5. `code/policy.py` loads deletion and retention rules from `dataset/deletion_rules.csv` and orders actions by phase.
6. `code/validate_output.py` independently checks the generated submission's structure, operation/state vocabulary, evidence identifiers, time cutoff, and phase sequence.
7. `code/diagnostics.py` emits reason-coded unresolved proof obligations and per-case data-flow/restore reachability graphs with concrete resurrection-risk paths.

The pipeline distinguishes evidence-backed compliant states from unresolved obligations. A missing evidence set cannot prove deletion. Planned actions in an `INCOMPLETE` result are proposals and have empty evidence references; they are not reported as executed. Manifest capture time bounds when an item is available, while parsed observation time orders repeated states inside captured logs.

## Known limitations

Replica copies and inconsistent SQL snapshots still need stronger location-aware reconciliation. Public sample scores are not a substitute for hidden-set labels or a full proof of case-level obligation completeness.
