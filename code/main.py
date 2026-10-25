"""Deterministic deletion audit pipeline for the participant dataset."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

try:  # Support both ``python -m code.main`` and ``python code/main.py``.
    from .identity import IdentityResolver
    from .evidence import EvidenceIndex, ResourceState
    from .ingestion import EvidenceIngestor
    from .policy import PolicyEngine
except ImportError:  # pragma: no cover - exercised by the documented script form
    from identity import IdentityResolver
    from evidence import EvidenceIndex, ResourceState
    from ingestion import EvidenceIngestor
    from policy import PolicyEngine


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "dataset"
OUTPUT_PATH = ROOT / "output.csv"

SYSTEM_CATEGORIES = {
    "account_service": "USER_PROFILE",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "support_platform": "SUPPORT_MESSAGE",
    "analytics_platform": "ANALYTICS_PROFILE",
    "export_service": "USER_EXPORT",
    "marketing_platform": "MARKETING_PROFILE",
    "integration_service": "ACTIVE_DATA_FLOW",
    "backup_service": "BACKUP_ARCHIVE",
    "security_service": "SECURITY_AUDIT_LOG",
    "email_service": "EMAIL_DELIVERY_LOG",
    "legal_service": "LEGAL_HOLD_RECORD",
}


def load_requests(path: Path) -> List[dict]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        return list(csv.DictReader(stream))


def write_output(rows: List[dict], path: Path = OUTPUT_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(rows)


def _record_action(resource: ResourceState, action: str) -> Optional[Tuple[str, str]]:
    state = resource.state.upper()
    # Do not emit a concrete action when a conditional rule is unresolved.
    # In particular, an unproven ability to block backup restoration must not
    # be turned into a claimed actionable BLOCK_RESTORE plan.
    if action == "UNRESOLVED":
        return None
    if resource.is_flow or resource.data_category == "ACTIVE_DATA_FLOW":
        return ("REPORT_ACTIVE_DATA_FLOW", "ACTIVE") if state == "ACTIVE" else None
    if resource.is_restore or resource.data_category in ("RESTORE_RISK", "BACKUP_ARCHIVE"):
        return ("REPORT_RESTORE_RISK", "ACTIVE") if state == "ACTIVE" else None
    if action == "RETAIN":
        return None
    if action == "REDACT":
        if state == "PRESENT" and resource.has_pii:
            return "REPORT_EXPOSED_PII", "PRESENT"
        return None
    if action == "ANONYMIZE":
        if state == "PRESENT":
            return "REPORT_EXPOSED_PII", "PRESENT"
        return None
    if action == "DELETE" and state in {"PRESENT", "REDACTED", "ANONYMIZED"}:
        return "REPORT_REMAINING_RECORD", "PRESENT"
    return None


def _desired_action(resource: ResourceState, policy: PolicyEngine, audit_at: str = "",
                    related_resources: Optional[Dict[Tuple[str, str], ResourceState]] = None) -> str:
    category = resource.data_category or SYSTEM_CATEGORIES.get(resource.system_id, "")
    rule = policy.rules.get(category)
    if rule:
        condition = policy.condition_result(rule, resource, audit_at, related_resources)
        if condition == "TRUE":
            return rule.required_action.upper()
        if condition == "FALSE":
            return policy.condition_fallback_action(rule)
        return "UNRESOLVED"
    if resource.is_flow or resource.system_id == "integration_service":
        return "FLOW"
    if resource.is_restore or resource.system_id == "backup_service":
        return "RESTORE"
    return "DELETE"


def _step(phase: str, system: str, resource: str, operation: str,
          state: str, evidence: str = "") -> dict:
    return {
        "step_no": 0,
        "phase": phase,
        "system_id": system,
        "resource_id": resource,
        "operation": operation,
        "state": state,
        "evidence_id": evidence or "",
    }


def build_case_steps(resources: Dict[Tuple[str, str], ResourceState], policy: PolicyEngine,
                     audit_at: str = "") -> Tuple[str, list]:
    findings: List[dict] = []
    remediations: List[dict] = []
    verifications: List[dict] = []

    # Absence of discovered evidence is not proof that deletion completed.
    # Do not invent a resource identifier or an evidence-free absence check.
    if not resources:
        return "INCOMPLETE", []

    for (system, resource_id), item in resources.items():
        action = _desired_action(item, policy, audit_at, resources)
        violation = _record_action(item, action)
        if violation:
            op, state = violation
            findings.append(_step("FINDING", system, resource_id, op, state, item.evidence_id))

            if op == "REPORT_ACTIVE_DATA_FLOW":
                remediations.append(_step("REMEDIATION", system, resource_id, "DISABLE_DATA_FLOW", "DISABLED"))
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED"))
            elif op == "REPORT_RESTORE_RISK":
                remediations.append(_step("REMEDIATION", system, resource_id, "BLOCK_RESTORE", "BLOCKED"))
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED"))
            elif action == "REDACT":
                remediations.append(_step("REMEDIATION", system, resource_id, "REDACT_RECORD", "REDACTED"))
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_RECORD_REDACTED", "REDACTED"))
            elif action == "ANONYMIZE":
                remediations.append(_step("REMEDIATION", system, resource_id, "ANONYMIZE_RECORD", "ANONYMIZED"))
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"))
            else:
                remediations.append(_step("REMEDIATION", system, resource_id, "DELETE_RECORD", "ABSENT"))
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_RECORD_ABSENT", "ABSENT"))

    if findings:
        # A remediation plan must finish by checking already compliant
        # retained/removed records alongside the records that need changes.
        for (system, resource_id), item in resources.items():
            if _record_action(item, _desired_action(item, policy, audit_at, resources)) is not None:
                continue
            action = _desired_action(item, policy, audit_at, resources)
            state = item.state.upper()
            if system == "integration_service" and state == "DISABLED":
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED"))
            elif system == "backup_service" and state == "BLOCKED":
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED"))
            elif action == "RETAIN" and state == "PRESENT":
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_RECORD_PRESENT", "PRESENT"))
            elif action == "DELETE" and state == "ABSENT":
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_RECORD_ABSENT", "ABSENT"))
            elif action == "REDACT" and state == "REDACTED":
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_RECORD_REDACTED", "REDACTED"))
            elif action == "ANONYMIZE" and state == "ANONYMIZED":
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"))
        # Stop replication and restore risks before deleting dependent records.
        steps = PolicyEngine.sort_steps(findings + remediations + verifications)
        return "INCOMPLETE", steps

    # An authorized deletion is complete only when the evidence establishes
    # the required treatment of every discovered item and at least the account
    # state. Every verification below cites the evidence supporting that state.
    proof_complete = True
    for (system, resource_id), item in resources.items():
        action = _desired_action(item, policy, audit_at, resources)
        state = item.state.upper()
        if not item.evidence_id or state not in {
            "PRESENT", "ABSENT", "REDACTED", "ANONYMIZED", "ACTIVE", "DISABLED", "BLOCKED"
        }:
            proof_complete = False
            continue
        if action == "UNRESOLVED":
            proof_complete = False
            continue
        # BACKUP_ARCHIVE policy retains the archive only when restore access is
        # blocked. This is a restore-control obligation, not a requirement that
        # the control's BLOCKED state equal the record's PRESENT state.
        if system == "integration_service" or action == "FLOW":
            if state == "DISABLED":
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_DATA_FLOW_DISABLED", "DISABLED", item.evidence_id))
            else:
                proof_complete = False
            continue
        if system == "backup_service" or action == "RESTORE":
            if state == "BLOCKED":
                verifications.append(_step("VERIFICATION", system, resource_id, "VERIFY_RESTORE_BLOCKED", "BLOCKED", item.evidence_id))
            else:
                proof_complete = False
            continue
        if action == "RETAIN" and state != "PRESENT":
            proof_complete = False
            continue
        op_state = {
            "REDACT": ("VERIFY_RECORD_REDACTED", "REDACTED"),
            "ANONYMIZE": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
            "RETAIN": ("VERIFY_RECORD_PRESENT", "PRESENT"),
            "DELETE": ("VERIFY_RECORD_ABSENT", "ABSENT"),
        }.get(action)
        if action == "NO_ACTION" and state in {"ABSENT", "REDACTED", "ANONYMIZED"}:
            op_state = {
                "ABSENT": ("VERIFY_RECORD_ABSENT", "ABSENT"),
                "REDACTED": ("VERIFY_RECORD_REDACTED", "REDACTED"),
                "ANONYMIZED": ("VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"),
            }[state]
        if op_state and state == op_state[1]:
            verifications.append(_step("VERIFICATION", system, resource_id, op_state[0], op_state[1], item.evidence_id))
        else:
            proof_complete = False
    if not verifications:
        return "INCOMPLETE", []
    if proof_complete:
        return "COMPLETE", PolicyEngine.sort_steps(verifications)
    # Preserve checks for every obligation we could determine even when one
    # other obligation fails closed. They describe the required future audit
    # state, not proof of a completed case.
    for step in verifications:
        step["evidence_id"] = ""
    return "INCOMPLETE", PolicyEngine.sort_steps(verifications)


def run(requests_path: Path, output_path: Path) -> List[dict]:
    resolver = IdentityResolver(str(DATASET_DIR / "user_identities.csv"), str(DATASET_DIR / "user_audit_log.csv"))
    ingestor = EvidenceIngestor(str(DATASET_DIR))
    evidence = EvidenceIndex(ingestor)
    policy = PolicyEngine(str(DATASET_DIR / "deletion_rules.csv"))
    output = []

    for req in load_requests(requests_path):
        user = resolver.resolve_by_email(req.get("email", ""), req.get("requested_at", ""))
        if not IdentityResolver.is_deletion_authorized(req.get("request_text", "")):
            status, steps = "NOT_APPLICABLE", []
        elif not user:
            status, steps = "INCOMPLETE", []
        else:
            resources = evidence.get_user_resources(
                user, req.get("requested_at", ""), req.get("reported_at", ""), req.get("audit_at", "")
            )
            status, steps = build_case_steps(resources, policy, req.get("audit_at", ""))
        output.append({"case_id": req["case_id"], "deletion_status": status,
                       "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":"))})

    output.sort(key=lambda row: row["case_id"])
    write_output(output, output_path)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit deletion requests using participant-provided evidence.")
    parser.add_argument("--requests", type=Path, default=DATASET_DIR / "deletion_requests.csv",
                        help="request CSV (defaults to all evaluation requests)")
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH,
                        help="output CSV (defaults to repository-root output.csv)")
    args = parser.parse_args()
    rows = run(args.requests, args.output)
    print(f"Generated {len(rows)} rows to {args.output}")


if __name__ == "__main__":
    main()
