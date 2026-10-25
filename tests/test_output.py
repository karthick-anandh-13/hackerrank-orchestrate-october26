# tests/test_output.py
"""Validator tests for the Ghost Data Still Exists challenge output.
Ensures the generated output.csv meets all contract requirements.
"""
import csv
import json
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = REPO_ROOT / "dataset"
OUTPUT_PATH = REPO_ROOT / "output.csv"

ALLOWED_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
ALLOWED_PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}
ALLOWED_OPERATIONS = {
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
}

class TestOutputValidator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not OUTPUT_PATH.exists():
            raise FileNotFoundError(f"Output file not found: {OUTPUT_PATH}")
        with open(OUTPUT_PATH, newline="", encoding="utf-8") as f:
            cls.rows = list(csv.DictReader(f))
        requests_path = DATASET_DIR / "deletion_requests.csv"
        with open(requests_path, newline="", encoding="utf-8") as f:
            cls.request_ids = {row["case_id"] for row in csv.DictReader(f)}

    def test_case_coverage(self):
        case_ids = [row["case_id"] for row in self.rows]
        self.assertEqual(len(case_ids), 518, "Expected 518 rows")
        self.assertEqual(set(case_ids), self.request_ids, "Case IDs mismatch")
        self.assertListEqual(sorted(case_ids), case_ids, "Rows not sorted by case_id")

    def test_status_values(self):
        for row in self.rows:
            self.assertIn(row["deletion_status"], ALLOWED_STATUSES)

    def test_steps_json_structure(self):
        for row in self.rows:
            steps = json.loads(row["steps_json"])
            self.assertIsInstance(steps, list)
            last_step_no = 0
            phase_order = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
            last_phase = None
            for step in steps:
                for key in ["step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"]:
                    self.assertIn(key, step)
                self.assertEqual(step["step_no"], last_step_no + 1)
                last_step_no = step["step_no"]
                self.assertIn(step["phase"], ALLOWED_PHASES)
                if last_phase is None:
                    last_phase = step["phase"]
                else:
                    self.assertLessEqual(phase_order[step["phase"]], phase_order[last_phase] + 1)
                    last_phase = step["phase"]
                self.assertIn(step["operation"], ALLOWED_OPERATIONS)
                self.assertIsInstance(step["state"], str)
                self.assertNotEqual(step["state"], "")
                self.assertIsInstance(step["evidence_id"], str)

# Edge‑case synthetic tests
from code.identity import IdentityResolver
from code.evidence import EvidenceIndex
from code.ingestion import EvidenceItem

class MockIngestor:
    def __init__(self, items=None, activities=None):
        self.evidence_items = items or []
        self.activities = activities or []

class EdgeCaseTests(unittest.TestCase):
    def test_historical_email_resolution(self):
        resolver = IdentityResolver(identities_path=str(DATASET_DIR / "user_identities.csv"),
                                    audit_log_path=str(DATASET_DIR / "user_audit_log.csv"))
        hist_email = "nadia.ionescu@yahoo.com"
        user = resolver.resolve_by_any_identifier(hist_email)
        self.assertIsNotNone(user)
        item = EvidenceItem(
            file_id="evidence_test",
            captured_at="2025-01-01T00:00:00Z",
            origin="synthetic_test",
            file_path="synthetic://support_9999",
            system_id="support_platform",
            resource_id="support_9999",
            state="PRESENT",
            user_id=user.user_id,
            email=hist_email,
            phone=None,
            email_hash=None,
            data_category="support",
            text_content="",
        )
        idx = EvidenceIndex(MockIngestor(items=[item]))
        resources = idx.get_user_resources(user, "2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z", "2025-01-03T00:00:00Z")
        self.assertTrue(any(res.state == "PRESENT" for res in resources.values()))

    def test_data_flow_disabling(self):
        resolver = IdentityResolver(identities_path=str(DATASET_DIR / "user_identities.csv"),
                                    audit_log_path=str(DATASET_DIR / "user_audit_log.csv"))
        user = resolver.resolve_by_any_identifier("amina.elmasri@gmail.com")
        self.assertIsNotNone(user)
        item = EvidenceItem(
            file_id="evidence_flow",
            captured_at="2025-01-01T00:00:00Z",
            origin="synthetic_test",
            file_path="synthetic://data_flow_123",
            system_id="integration_service",
            resource_id="flow_123",
            state="PRESENT",
            user_id=user.user_id,
            email=user.email,
            phone=None,
            email_hash=None,
            data_category="flow",
            text_content="",
        )
        idx = EvidenceIndex(MockIngestor(items=[item]))
        resources = idx.get_user_resources(user, "2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z", "2025-01-03T00:00:00Z")
        key = ("integration_service", "flow_123")
        self.assertIn(key, resources)
        self.assertTrue(resources[key].is_flow)

    def test_account_tombstone_retention(self):
        resolver = IdentityResolver(identities_path=str(DATASET_DIR / "user_identities.csv"),
                                    audit_log_path=str(DATASET_DIR / "user_audit_log.csv"))
        user = resolver.resolve_by_any_identifier("kwame-mensah@proton.me")
        self.assertIsNotNone(user)
        item = EvidenceItem(
            file_id="evidence_tomb",
            captured_at="2025-01-01T00:00:00Z",
            origin="synthetic_test",
            file_path="synthetic://tombstone_99",
            system_id="security_service",
            resource_id="tombstone_99",
            state="PRESENT",
            user_id=user.user_id,
            email=user.email,
            phone=user.phone,
            email_hash=None,
            data_category="tombstone",
            text_content="",
        )
        idx = EvidenceIndex(MockIngestor(items=[item]))
        resources = idx.get_user_resources(user, "2025-01-01T00:00:00Z", "2025-01-02T00:00:00Z", "2025-01-03T00:00:00Z")
        key = ("security_service", "tombstone_99")
        self.assertIn(key, resources)
        self.assertTrue(resources[key].is_retained)
        self.assertEqual(resources[key].state, "PRESENT")

if __name__ == "__main__":
    unittest.main()
