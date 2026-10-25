"""Independent structural and evidence-reference validator for output.csv.

This module deliberately does not import or call the prediction pipeline.
It checks the submission contract and catches unsupported citations, malformed
steps, and temporal violations independently of inference.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED = {
    ("REPORT_REMAINING_RECORD", "PRESENT"), ("REPORT_EXPOSED_PII", "PRESENT"),
    ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE"), ("REPORT_RESTORE_RISK", "ACTIVE"),
    ("DISABLE_DATA_FLOW", "DISABLED"), ("BLOCK_RESTORE", "BLOCKED"),
    ("DELETE_RECORD", "ABSENT"), ("REDACT_RECORD", "REDACTED"),
    ("ANONYMIZE_RECORD", "ANONYMIZED"),
    ("VERIFY_RECORD_ABSENT", "ABSENT"), ("VERIFY_RECORD_PRESENT", "PRESENT"),
    ("VERIFY_RECORD_REDACTED", "REDACTED"), ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
    ("VERIFY_DATA_FLOW_DISABLED", "DISABLED"), ("VERIFY_RESTORE_BLOCKED", "BLOCKED"),
}
PHASE = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {op: i for i, op in enumerate((
    "REPORT_REMAINING_RECORD", "REPORT_EXPOSED_PII", "REPORT_ACTIVE_DATA_FLOW", "REPORT_RESTORE_RISK",
    "DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD",
    "VERIFY_RECORD_ABSENT", "VERIFY_RECORD_PRESENT", "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED", "VERIFY_RESTORE_BLOCKED",
))}
FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}


def validate(output_path: Path = ROOT / "output.csv", dataset_dir: Path = ROOT / "dataset") -> list[str]:
    errors: list[str] = []
    with (dataset_dir / "deletion_requests.csv").open(encoding="utf-8-sig", newline="") as f:
        requests = {r["case_id"]: r for r in csv.DictReader(f)}
    with (dataset_dir / "evidence_files.csv").open(encoding="utf-8-sig", newline="") as f:
        manifest = {r["file_id"]: r for r in csv.DictReader(f)}
    with (dataset_dir / "system_activity.csv").open(encoding="utf-8-sig", newline="") as f:
        activity = {r["activity_id"]: r for r in csv.DictReader(f)}
    with (dataset_dir / "user_audit_log.csv").open(encoding="utf-8-sig", newline="") as f:
        audits = {r["audit_id"]: r for r in csv.DictReader(f)}
    known_evidence = set(manifest) | set(activity) | set(audits)
    if not output_path.exists():
        return [f"Output is missing: {output_path}"]
    with output_path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != ["case_id", "deletion_status", "steps_json"]:
            errors.append("Output header/column order is invalid")
        rows = list(reader)
    ids = [r.get("case_id", "") for r in rows]
    expected = sorted(requests)
    if ids != expected:
        errors.append(f"Case coverage/order mismatch: got {len(ids)}, expected {len(expected)} sorted rows")
    for row in rows:
        cid, status = row.get("case_id", ""), row.get("deletion_status", "")
        if cid not in requests:
            errors.append(f"Unknown case_id {cid}"); continue
        if status not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}:
            errors.append(f"{cid}: invalid status {status}")
        try:
            steps = json.loads(row.get("steps_json", ""))
        except (TypeError, json.JSONDecodeError):
            errors.append(f"{cid}: steps_json is not valid JSON"); continue
        if not isinstance(steps, list):
            errors.append(f"{cid}: steps_json must be an array"); continue
        if status == "NOT_APPLICABLE" and steps:
            errors.append(f"{cid}: NOT_APPLICABLE must have empty steps")
        if status == "COMPLETE" and (not steps or any(s.get("phase") != "VERIFICATION" for s in steps if isinstance(s, dict))):
            errors.append(f"{cid}: COMPLETE must contain verification-only proof steps")
        previous_phase = -1
        canonical_keys = []
        prior_remediations = set()
        prior_findings = set()
        remediations = []
        verifications = set()
        for index, step in enumerate(steps, 1):
            if not isinstance(step, dict) or set(step) != FIELDS:
                errors.append(f"{cid}: step {index} has invalid fields"); continue
            if step["step_no"] != index:
                errors.append(f"{cid}: step numbers are not consecutive")
            phase = step["phase"]
            if phase not in PHASE or PHASE[phase] < previous_phase:
                errors.append(f"{cid}: invalid phase ordering")
            else:
                previous_phase = PHASE[phase]
            if (step["operation"], step["state"]) not in ALLOWED:
                errors.append(f"{cid}: invalid operation/state pair at step {index}")
            op = step["operation"]
            expected_phase = ("FINDING" if op.startswith("REPORT_") else
                              "REMEDIATION" if op in {"DISABLE_DATA_FLOW", "BLOCK_RESTORE", "DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"} else
                              "VERIFICATION" if op.startswith("VERIFY_") else "")
            if expected_phase and phase != expected_phase:
                errors.append(f"{cid}: operation {op} is invalid in phase {phase}")
            if phase in PHASE and op in OP_ORDER:
                canonical_keys.append((PHASE[phase], OP_ORDER[op], step["system_id"], step["resource_id"]))
            if status == "COMPLETE" and not step["evidence_id"]:
                errors.append(f"{cid}: complete verification {index} lacks evidence")
            evidence_id = step["evidence_id"]
            if status == "INCOMPLETE" and phase != "FINDING" and evidence_id:
                errors.append(f"{cid}: planned step {index} must have empty evidence_id")
            if phase == "FINDING":
                prior_findings.add((step["system_id"], step["resource_id"]))
                if not evidence_id:
                    errors.append(f"{cid}: finding {index} lacks evidence")
            if phase == "REMEDIATION":
                prior_remediations.add((step["system_id"], step["resource_id"], step["operation"]))
                remediations.append(step)
            if phase == "VERIFICATION" and status == "INCOMPLETE":
                expected_op = {
                    "DELETE_RECORD": "VERIFY_RECORD_ABSENT", "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
                    "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED", "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED",
                    "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
                }
                # Each planned remediation must have its matching post-action check.
                verifications.add((step["system_id"], step["resource_id"], step["operation"]))
            elif phase == "VERIFICATION":
                verifications.add((step["system_id"], step["resource_id"], step["operation"]))
            if evidence_id:
                if evidence_id not in known_evidence:
                    errors.append(f"{cid}: unknown evidence_id {evidence_id}")
                else:
                    times = []
                    if evidence_id in manifest: times.append(manifest[evidence_id].get("captured_at", ""))
                    if evidence_id in activity: times.append(activity[evidence_id].get("event_time", ""))
                    if evidence_id in audits: times.append(audits[evidence_id].get("event_time", ""))
                    cutoff = requests[cid].get("audit_at", "")
                    if times and not any(t and t <= cutoff for t in times):
                        errors.append(f"{cid}: evidence {evidence_id} is after audit_at")
        if status == "INCOMPLETE" and steps and not prior_findings:
            # If discovery produced compliant-looking states but a proof
            # obligation could not be established, retain the future checks
            # rather than blanking the sequence or fabricating a finding.
            unresolved_checks_only = all(
                isinstance(s, dict) and s.get("phase") == "VERIFICATION" and not s.get("evidence_id")
                for s in steps
            )
            if not unresolved_checks_only:
                errors.append(f"{cid}: INCOMPLETE plan has no findings or unresolved future checks")
        if canonical_keys != sorted(canonical_keys):
            errors.append(f"{cid}: steps do not follow canonical phase/operation/system/resource order")
        if status == "INCOMPLETE":
            expected_remedy = {
                "REPORT_REMAINING_RECORD": {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD"},
                "REPORT_EXPOSED_PII": {"REDACT_RECORD", "ANONYMIZE_RECORD"},
                "REPORT_ACTIVE_DATA_FLOW": {"DISABLE_DATA_FLOW"},
                "REPORT_RESTORE_RISK": {"BLOCK_RESTORE"},
            }
            for step in steps:
                if not isinstance(step, dict): continue
                if step.get("phase") == "FINDING":
                    sys, res = step["system_id"], step["resource_id"]
                    candidates = expected_remedy.get(step["operation"], set())
                    if candidates and not any((sys, res, op) in prior_remediations for op in candidates):
                        errors.append(f"{cid}: finding lacks matching remediation for {sys}/{res}")
            verification_for = {
                "DELETE_RECORD": "VERIFY_RECORD_ABSENT", "REDACT_RECORD": "VERIFY_RECORD_REDACTED",
                "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED", "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED",
                "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED",
            }
            for sys, res, op in prior_remediations:
                if (sys, res, verification_for[op]) not in verifications:
                    errors.append(f"{cid}: remediation lacks matching verification for {sys}/{res}")
    return errors


def main() -> int:
    errors = validate()
    if errors:
        print(f"Validation failed: {len(errors)} issue(s)")
        for error in errors[:100]: print(error)
        return 1
    print("Output contract validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
