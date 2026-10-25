"""Regression coverage for identity-grounded, time-bounded evidence joins."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from code.evidence import EvidenceIndex
from code.identity import IdentityResolver
from code.ingestion import EvidenceIngestor, EvidenceItem, SystemActivity
from code.main import build_case_steps
from code.policy import PolicyEngine


ROOT = Path(__file__).resolve().parents[1]


class MockIngestor:
    def __init__(self, items=None, activities=None):
        self.evidence_items = items or []
        self.activities = activities or []


class EvidenceLinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.resolver = IdentityResolver(
            str(ROOT / "dataset/user_identities.csv"),
            str(ROOT / "dataset/user_audit_log.csv"),
        )
        cls.user = cls.resolver.resolve_by_user_id("user_01")

    def test_control_export_uses_target_system_and_lookup_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence.json"
            evidence.write_text(json.dumps({
                "source": "privacy_treatment_service",
                "records": [{
                    "system": "account_service",
                    "resource_id": "account_fixture",
                    "record_type": "USER_PROFILE",
                    "result": "NOT_FOUND",
                    "lookup_value": self.user.email,
                }],
            }), encoding="utf-8")
            with (root / "evidence_files.csv").open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["file_id", "file_path", "origin", "captured_at"])
                writer.writeheader()
                writer.writerow({
                    "file_id": "evidence_fixture",
                    "file_path": "evidence.json",
                    "origin": "privacy_treatment_service",
                    "captured_at": "2026-09-01T00:00:00Z",
                })
            (root / "system_activity.csv").write_text(
                "activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details\n",
                encoding="utf-8",
            )
            ingestor = EvidenceIngestor(str(root))
            resources = EvidenceIndex(ingestor).get_user_resources(
                self.user,
                "2026-08-31T00:00:00Z",
                "2026-09-01T00:00:00Z",
                "2026-09-02T00:00:00Z",
            )
            found = resources[("account_service", "account_fixture")]
            self.assertEqual(found.state, "ABSENT")
            self.assertEqual(found.evidence_id, "evidence_fixture")

    def test_unlinked_global_delete_activity_does_not_identify_a_user(self):
        activity = SystemActivity(
            "activity_fixture", "2026-09-01T00:00:00Z", "DELETE_RECORD",
            "deletion_worker", "account_service", "account_unrelated", "SUCCESS",
            "Deletion worker submitted primary profile account_unrelated.",
        )
        resources = EvidenceIndex(MockIngestor(activities=[activity])).get_user_resources(
            self.user,
            "2026-08-31T00:00:00Z",
            "2026-09-01T00:00:00Z",
            "2026-09-02T00:00:00Z",
        )
        self.assertEqual(resources, {})

    def test_identity_link_carries_forward_latest_resource_snapshot(self):
        old = EvidenceItem(
            file_id="evidence_old", captured_at="2026-09-01T00:00:00Z",
            origin="fixture", file_path="old.json", system_id="support_platform",
            resource_id="support_fixture", user_id=self.user.user_id,
            email=self.user.email, state="PRESENT", data_category="SUPPORT_MESSAGE",
        )
        new = EvidenceItem(
            file_id="evidence_new", captured_at="2026-09-02T00:00:00Z",
            origin="fixture", file_path="new.json", system_id="support_platform",
            resource_id="support_fixture", state="REDACTED", data_category="SUPPORT_MESSAGE",
        )
        resources = EvidenceIndex(MockIngestor(items=[old, new])).get_user_resources(
            self.user,
            "2026-08-31T00:00:00Z",
            "2026-09-01T00:00:00Z",
            "2026-09-03T00:00:00Z",
        )
        found = resources[("support_platform", "support_fixture")]
        self.assertEqual((found.state, found.evidence_id), ("REDACTED", "evidence_new"))
        self.assertFalse(found.has_pii)

    def test_support_contact_index_uses_secondary_identifier_delete_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence_dir = root / "evidence"
            evidence_dir.mkdir()
            (evidence_dir / "support.log").write_text(
                "2026-09-02T10:00:00Z level=DEBUG service=support_replica "
                "trace_id=contact-1 event=contact_query_started "
                f"lookup_key={self.user.email} source=legacy_contact_index\n"
                "2026-09-02T10:00:01Z level=INFO service=support_replica "
                "trace_id=contact-1 event=contact_query_completed "
                "resource_id=contact_fixture rows=1\n"
                "2026-09-02T10:00:02Z level=WARN service=support_replica "
                "trace_id=contact-1 event=deletion_marker_check "
                "resource_id=contact_fixture marker_found=false\n",
                encoding="utf-8",
            )
            with (root / "evidence_files.csv").open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["file_id", "file_path", "origin", "captured_at"])
                writer.writeheader()
                writer.writerow({
                    "file_id": "evidence_contact",
                    "file_path": "evidence/support.log",
                    "origin": "support_replica",
                    "captured_at": "2026-09-02T10:00:02Z",
                })
            (root / "system_activity.csv").write_text(
                "activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details\n",
                encoding="utf-8",
            )
            ingestor = EvidenceIngestor(str(root))
            evidence = EvidenceIndex(ingestor)
            resources = evidence.get_user_resources(
                self.user,
                "2026-09-01T00:00:00Z",
                "2026-09-02T00:00:00Z",
                "2026-09-03T00:00:00Z",
            )
            resource = resources[("support_platform", "contact_fixture")]
            self.assertEqual(resource.data_category, "SECONDARY_IDENTIFIER")
            status, steps = build_case_steps(
                resources, PolicyEngine(str(ROOT / "dataset/deletion_rules.csv")),
                "2026-09-03T00:00:00Z",
            )
            self.assertEqual(status, "INCOMPLETE")
            self.assertEqual(
                [step["operation"] for step in steps],
                ["REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"],
            )

    def test_key_value_log_retains_policy_facts_and_observation_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence_dir = root / "evidence"
            evidence_dir.mkdir()
            (evidence_dir / "security.log").write_text(
                "2026-09-02T10:00:00Z level=INFO service=security_service "
                "trace_id=audit-1 event=audit_record_read_completed "
                "resource_id=audit_fixture subject_reference=user_01 "
                "retention_until=2034-09-30T23:59:59Z rows=1\n",
                encoding="utf-8",
            )
            with (root / "evidence_files.csv").open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["file_id", "file_path", "origin", "captured_at"])
                writer.writeheader()
                writer.writerow({
                    "file_id": "evidence_security_log",
                    "file_path": "evidence/security.log",
                    "origin": "security_service",
                    "captured_at": "2026-09-02T10:01:00Z",
                })
            (root / "system_activity.csv").write_text(
                "activity_id,event_time,event_type,source_system,target_system,resource_id,reported_result,details\n",
                encoding="utf-8",
            )
            item = EvidenceIngestor(str(root)).evidence_items[0]
            self.assertEqual(item.observed_at, "2026-09-02T10:00:00Z")
            self.assertEqual(item.raw_payload["retention_until"], "2034-09-30T23:59:59Z")
            resources = EvidenceIndex(MockIngestor(items=[item])).get_user_resources(
                self.user,
                "2026-09-01T00:00:00Z",
                "2026-09-02T10:01:00Z",
                "2026-09-03T00:00:00Z",
            )
            status, steps = build_case_steps(
                resources, PolicyEngine(str(ROOT / "dataset/deletion_rules.csv")),
                "2026-09-03T00:00:00Z",
            )
            self.assertEqual(status, "COMPLETE")
            self.assertEqual([step["operation"] for step in steps], ["VERIFY_RECORD_PRESENT"])

    def test_tombstone_with_only_stable_user_reference_is_compliant(self):
        item = EvidenceItem(
            file_id="evidence_tombstone",
            captured_at="2026-09-02T00:00:00Z",
            origin="identity_snapshot",
            file_path="snapshot.json",
            system_id="identity_service",
            resource_id="tombstone_fixture",
            user_id=self.user.user_id,
            state="PRESENT",
            data_category="ACCOUNT_TOMBSTONE",
            raw_payload={"account_deleted": True, "stable_reference_required": True},
        )
        resources = EvidenceIndex(MockIngestor(items=[item])).get_user_resources(
            self.user,
            "2026-09-01T00:00:00Z",
            "2026-09-02T00:00:00Z",
            "2026-09-03T00:00:00Z",
        )
        tombstone = resources[("identity_service", "tombstone_fixture")]
        self.assertEqual(tombstone.state, "REDACTED")
        self.assertFalse(tombstone.has_pii)
        status, steps = build_case_steps(
            resources, PolicyEngine(str(ROOT / "dataset/deletion_rules.csv")),
            "2026-09-03T00:00:00Z",
        )
        self.assertEqual(status, "COMPLETE")
        self.assertEqual([step["operation"] for step in steps], ["VERIFY_RECORD_REDACTED"])

        exposed = EvidenceItem(
            file_id="evidence_tombstone_exposed",
            captured_at="2026-09-02T00:00:00Z",
            origin="identity_snapshot",
            file_path="snapshot_with_direct_identifier.json",
            system_id="identity_service",
            resource_id="tombstone_exposed_fixture",
            user_id=self.user.user_id,
            email=self.user.email,
            state="REDACTED",
            data_category="ACCOUNT_TOMBSTONE",
            raw_payload={"account_deleted": True, "stable_reference_required": True},
        )
        exposed_resources = EvidenceIndex(MockIngestor(items=[exposed])).get_user_resources(
            self.user,
            "2026-09-01T00:00:00Z",
            "2026-09-02T00:00:00Z",
            "2026-09-03T00:00:00Z",
        )
        exposed_tombstone = exposed_resources[("identity_service", "tombstone_exposed_fixture")]
        self.assertEqual(exposed_tombstone.state, "PRESENT")
        self.assertTrue(exposed_tombstone.has_pii)
        exposed_status, exposed_steps = build_case_steps(
            exposed_resources, PolicyEngine(str(ROOT / "dataset/deletion_rules.csv")),
            "2026-09-03T00:00:00Z",
        )
        self.assertEqual(exposed_status, "INCOMPLETE")
        self.assertEqual(
            [step["operation"] for step in exposed_steps],
            ["REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"],
        )


if __name__ == "__main__":
    unittest.main()
