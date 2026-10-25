"""Run lightweight regression scenarios and score public sample answers."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from code.evidence import ResourceState
from code.identity import IdentityResolver
from code.main import DATASET_DIR, build_case_steps, run
from code.policy import PolicyEngine


def run_custom_cases() -> None:
    assert not IdentityResolver.is_deletion_authorized(
        "Could you send a copy of my information? Please do not delete anything."
    )
    policy = PolicyEngine(str(DATASET_DIR / "deletion_rules.csv"))

    flow = ResourceState("integration_service", "data_flow_test", "ACTIVE", "evidence_test",
                         "2026-01-01T00:00:00Z", is_flow=True, data_category="ACTIVE_DATA_FLOW")
    status, steps = build_case_steps({("integration_service", "data_flow_test"): flow}, policy)
    assert status == "INCOMPLETE"
    assert [s["operation"] for s in steps] == [
        "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"
    ]

    tombstone = ResourceState("identity_service", "tombstone_test", "PRESENT", "evidence_test",
                              "2026-01-01T00:00:00Z", has_pii=True,
                              data_category="ACCOUNT_TOMBSTONE",
                              condition_facts={"account_deleted": True,
                                               "stable_reference_required": True})
    status, steps = build_case_steps({("identity_service", "tombstone_test"): tombstone}, policy)
    assert status == "INCOMPLETE"
    assert [s["operation"] for s in steps] == [
        "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"
    ]

    clean = ResourceState("analytics_platform", "analytics_test", "ANONYMIZED", "evidence_test",
                          "2026-01-01T00:00:00Z", data_category="ANALYTICS_PROFILE")
    status, steps = build_case_steps({("analytics_platform", "analytics_test"): clean}, policy)
    assert status == "COMPLETE" and steps[0]["operation"] == "VERIFY_RECORD_ANONYMIZED"

    status, steps = build_case_steps({}, policy)
    assert status == "INCOMPLETE" and steps == []

    legal_hold = ResourceState("legal_service", "legal_hold_test", "PRESENT", "evidence_test",
                               "2026-01-01T00:00:00Z", is_retained=True,
                               data_category="LEGAL_HOLD_RECORD",
                               condition_facts={"hold_active": True})
    status, steps = build_case_steps({("legal_service", "legal_hold_test"): legal_hold}, policy)
    assert status == "COMPLETE" and steps[0]["operation"] == "VERIFY_RECORD_PRESENT"

    expired_audit = ResourceState("security_service", "audit_expired", "PRESENT", "evidence_test",
                                  "2026-01-01T00:00:00Z", is_retained=True,
                                  data_category="SECURITY_AUDIT_LOG",
                                  retention_until="2025-12-31T23:59:59Z")
    status, steps = build_case_steps(
        {("security_service", "audit_expired"): expired_audit}, policy,
        audit_at="2026-01-02T00:00:00Z",
    )
    assert status == "INCOMPLETE"
    assert [s["operation"] for s in steps] == [
        "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"
    ]
    print("7 custom evaluation cases passed")


def score_public_sample() -> None:
    expected_path = DATASET_DIR / "sample_output.csv"
    requests_path = DATASET_DIR / "sample_deletion_requests.csv"
    if not expected_path.exists() or not requests_path.exists():
        print("Public sample scoring skipped (participant sample files unavailable).")
        return
    with expected_path.open(newline="", encoding="utf-8") as f:
        expected = {r["case_id"]: r for r in csv.DictReader(f)}
    with TemporaryDirectory() as temp_dir:
        actual_rows = run(requests_path, Path(temp_dir) / "sample_output.csv")
    actual = {r["case_id"]: r for r in actual_rows}
    statuses = sum(expected[k]["deletion_status"] == actual[k]["deletion_status"] for k in expected)
    sequences = sum(json.loads(expected[k]["steps_json"]) == json.loads(actual[k]["steps_json"])
                    for k in expected)
    print(f"Public sample: status accuracy {statuses}/{len(expected)}; exact sequences {sequences}/{len(expected)}")


if __name__ == "__main__":
    run_custom_cases()
    score_public_sample()
