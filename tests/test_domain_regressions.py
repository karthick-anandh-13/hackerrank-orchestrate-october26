import csv
import tempfile
import unittest
from pathlib import Path

from code.evidence import ResourceState
from code.identity import IdentityResolver
from code.main import build_case_steps
from code.policy import PolicyEngine


class DomainRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = PolicyEngine("dataset/deletion_rules.csv")

    def resource(self, system, rid, state="PRESENT", category=None, **kwargs):
        return ResourceState(system, rid, state, "evidence_fixture", "2026-09-01T00:00:00Z",
                             data_category=category, **kwargs)

    def test_historical_identifier_resolves_and_conflicting_owner_is_time_bounded(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            with (root / "identities.csv").open("w", newline="") as f:
                w = csv.writer(f); w.writerow(["user_id", "name", "email", "phone", "email_hash", "updated_at"])
                w.writerow(["user_a", "A", "new@example.com", "", "", "2026-01-02T00:00:00Z"])
                w.writerow(["user_b", "B", "shared@example.com", "", "", "2026-01-03T00:00:00Z"])
            with (root / "audit.csv").open("w", newline="") as f:
                w = csv.writer(f); w.writerow(["audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"])
                w.writerow(["a1", "user_a", "2026-01-02T00:00:00Z", "email", "shared@example.com", "new@example.com"])
                w.writerow(["b1", "user_b", "2026-01-01T00:00:00Z", "email", "", "shared@example.com"])
            resolver = IdentityResolver(str(root / "identities.csv"), str(root / "audit.csv"))
            self.assertEqual(resolver.resolve_by_email("shared@example.com", "2025-12-01T00:00:00Z").user_id, "user_a")
            self.assertEqual(resolver.resolve_by_email("shared@example.com", "2026-01-04T00:00:00Z").user_id, "user_b")
            self.assertIsNone(resolver.resolve_by_email("shared@example.com"))
            self.assertIn(("email", "shared@example.com"), resolver.identity_conflicts)
            self.assertTrue(resolver.users_by_id["user_a"].identifier_valid_at(
                "email", "shared@example.com", "2025-12-01T00:00:00Z"))
            self.assertFalse(resolver.users_by_id["user_a"].identifier_valid_at(
                "email", "shared@example.com", "2026-01-01T12:00:00Z"))

    def test_missing_evidence_does_not_prove_completion(self):
        status, steps = build_case_steps({}, self.policy)
        self.assertEqual((status, steps), ("INCOMPLETE", []))

    def test_policy_retention_expiry_redaction_anonymization_and_tombstone(self):
        expired = self.resource("security_service", "audit_1", category="SECURITY_AUDIT_LOG",
                                retention_until="2025-12-31T00:00:00Z")
        status, steps = build_case_steps({("security_service", "audit_1"): expired}, self.policy,
                                         "2026-01-01T00:00:00Z")
        self.assertEqual(status, "INCOMPLETE")
        self.assertIn("DELETE_RECORD", [s["operation"] for s in steps])
        boundary = self.resource("security_service", "audit_boundary", category="SECURITY_AUDIT_LOG",
                                 retention_until="2026-01-01T00:00:00Z")
        # The supplied deadline is exclusive: at the boundary retention ends.
        boundary_status, boundary_steps = build_case_steps(
            {("security_service", "audit_boundary"): boundary}, self.policy,
            "2026-01-01T00:00:00Z")
        self.assertEqual(boundary_status, "INCOMPLETE")
        self.assertIn("DELETE_RECORD", [s["operation"] for s in boundary_steps])
        support = self.resource("support_platform", "message_1", category="SUPPORT_MESSAGE", has_pii=True,
                                condition_facts={"shared_context": True})
        status, steps = build_case_steps({("support_platform", "message_1"): support}, self.policy)
        self.assertEqual([s["operation"] for s in steps], ["REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"])
        analytics = self.resource("analytics_platform", "analytics_1", "ANONYMIZED", "ANALYTICS_PROFILE")
        self.assertEqual(build_case_steps({("analytics_platform", "analytics_1"): analytics}, self.policy)[0], "COMPLETE")
        tombstone = self.resource("identity_service", "tomb_1", category="ACCOUNT_TOMBSTONE", has_pii=True,
                                  condition_facts={"account_deleted": True,
                                                   "stable_reference_required": True})
        status, steps = build_case_steps({("identity_service", "tomb_1"): tombstone}, self.policy)
        self.assertEqual(status, "INCOMPLETE")
        self.assertIn("REDACT_RECORD", [s["operation"] for s in steps])

    def test_delete_policy_still_removes_redacted_records(self):
        support = self.resource(
            "support_platform", "support_redacted", "REDACTED", "SUPPORT_MESSAGE",
            condition_facts={"shared_context": False},
        )
        status, steps = build_case_steps({("support_platform", "support_redacted"): support}, self.policy)
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(
            [step["operation"] for step in steps],
            ["REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"],
        )

    def test_support_excerpt_establishes_shared_context_unless_explicitly_conflicted(self):
        rule = self.policy.rules["SUPPORT_MESSAGE"]
        support = self.resource(
            "support_platform", "support_context", "REDACTED", "SUPPORT_MESSAGE",
            condition_facts={"message_excerpt": "Customer supplied contact details for a delivery query."},
        )
        self.assertEqual(
            self.policy.condition_result(rule, support, "2026-09-01T00:00:00Z"),
            "TRUE",
        )
        support.condition_facts["shared_context"] = False
        self.assertEqual(
            self.policy.condition_result(rule, support, "2026-09-01T00:00:00Z"),
            "UNKNOWN",
        )

    def test_missing_retention_does_not_mean_stable_reference_is_unneeded(self):
        tombstone = self.resource(
            "identity_service", "tombstone_unknown", "REDACTED", "ACCOUNT_TOMBSTONE",
            condition_facts={"account_deleted": True, "user_id": "user_01"},
        )
        audit_record = self.resource(
            "security_service", "audit_unknown", "PRESENT", "SECURITY_AUDIT_LOG",
            condition_facts={"user_id": "user_01"},
        )
        status, steps = build_case_steps({
            ("identity_service", "tombstone_unknown"): tombstone,
            ("security_service", "audit_unknown"): audit_record,
        }, self.policy, "2026-09-01T00:00:00Z")
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(steps, [])

    def test_active_flow_and_restore_risk_have_controls_and_checks(self):
        flow = self.resource("integration_service", "flow_1", "ACTIVE", "ACTIVE_DATA_FLOW", is_flow=True)
        status, steps = build_case_steps({("integration_service", "flow_1"): flow}, self.policy)
        self.assertEqual([s["operation"] for s in steps], ["REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"])
        backup = self.resource("backup_service", "backup_1", "ACTIVE", "RESTORE_RISK", is_restore=True)
        status, steps = build_case_steps({("backup_service", "backup_1"): backup}, self.policy)
        self.assertEqual([s["operation"] for s in steps], ["REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"])

    def test_unknown_obligation_does_not_blank_other_verification_steps(self):
        clean = self.resource("support_platform", "support_clean", "REDACTED", "SUPPORT_MESSAGE",
                              condition_facts={"shared_context": True})
        unknown = self.resource("search_service", "search_unknown", "UNKNOWN", "SEARCH_INDEX_ENTRY")
        status, steps = build_case_steps({
            ("support_platform", "support_clean"): clean,
            ("search_service", "search_unknown"): unknown,
        }, self.policy)
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual([s["operation"] for s in steps], ["VERIFY_RECORD_REDACTED"])
        self.assertEqual(steps[0]["evidence_id"], "")

    def test_blocked_backup_does_not_suppress_other_obligations(self):
        resources = {
            ("security_service", "audit_clean"): self.resource(
                "security_service", "audit_clean", "PRESENT", "SECURITY_AUDIT_LOG",
                retention_until="2027-01-01T00:00:00Z"),
            ("support_platform", "support_clean"): self.resource(
                "support_platform", "support_clean", "REDACTED", "SUPPORT_MESSAGE",
                condition_facts={"shared_context": True}),
            ("integration_service", "flow_clean"): self.resource(
                "integration_service", "flow_clean", "DISABLED", "ACTIVE_DATA_FLOW", is_flow=True),
            ("backup_service", "backup_blocked"): self.resource(
                "backup_service", "backup_blocked", "BLOCKED", "BACKUP_ARCHIVE", is_restore=True,
                condition_facts={"restore_blockable": True}),
        }
        status, steps = build_case_steps(resources, self.policy, "2026-09-01T00:00:00Z")
        self.assertEqual(status, "COMPLETE")
        self.assertEqual({s["resource_id"] for s in steps}, {"audit_clean", "support_clean", "flow_clean", "backup_blocked"})
        self.assertIn(("backup_blocked", "VERIFY_RESTORE_BLOCKED", "BLOCKED"), {
            (s["resource_id"], s["operation"], s["state"]) for s in steps
        })

    def test_active_inactive_and_unknown_legal_hold_condition(self):
        active = self.resource("legal_service", "hold_active", category="LEGAL_HOLD_RECORD",
                               condition_facts={"hold_active": True})
        status, steps = build_case_steps({("legal_service", "hold_active"): active}, self.policy)
        self.assertEqual(status, "COMPLETE")
        self.assertEqual([s["operation"] for s in steps], ["VERIFY_RECORD_PRESENT"])

        inactive = self.resource("legal_service", "hold_inactive", category="LEGAL_HOLD_RECORD",
                                 condition_facts={"hold_active": False})
        status, steps = build_case_steps({("legal_service", "hold_inactive"): inactive}, self.policy)
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual([s["operation"] for s in steps], [
            "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"])

        missing = self.resource("legal_service", "hold_unknown", category="LEGAL_HOLD_RECORD")
        status, steps = build_case_steps({("legal_service", "hold_unknown"): missing}, self.policy)
        self.assertEqual((status, steps), ("INCOMPLETE", []))

    def test_support_shared_context_condition_and_ambiguity(self):
        shared = self.resource("support_platform", "shared_message", category="SUPPORT_MESSAGE",
                               has_pii=True, condition_facts={"shared_context": True})
        status, steps = build_case_steps({("support_platform", "shared_message"): shared}, self.policy)
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual([s["operation"] for s in steps], [
            "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"])

        order_context = self.resource("support_platform", "order_context", category="SUPPORT_MESSAGE",
                                      has_pii=True,
                                      condition_facts={"message_excerpt": "Customer asked about order ORD-42."})
        status, steps = build_case_steps({("support_platform", "order_context"): order_context}, self.policy)
        self.assertEqual([s["operation"] for s in steps], [
            "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"])

        private = self.resource("support_platform", "private_message", category="SUPPORT_MESSAGE",
                                has_pii=True, condition_facts={"shared_context": False})
        status, steps = build_case_steps({("support_platform", "private_message"): private}, self.policy)
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual([s["operation"] for s in steps], [
            "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"])

        missing = self.resource("support_platform", "context_unknown", category="SUPPORT_MESSAGE",
                                has_pii=True)
        ambiguous = self.resource("support_platform", "context_conflict", category="SUPPORT_MESSAGE",
                                  has_pii=True,
                                  condition_facts={"shared_context": True, "shared_context_retained": False,
                                                   "message_excerpt": "Order ORD-42"})
        status, steps = build_case_steps({
            ("support_platform", "context_unknown"): missing,
            ("support_platform", "context_conflict"): ambiguous,
        }, self.policy)
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(steps, [])

    def test_unknown_backup_blockability_does_not_claim_a_block_action(self):
        backup = self.resource("backup_service", "backup_unknown", "ACTIVE", "BACKUP_ARCHIVE",
                               is_restore=True)
        status, steps = build_case_steps({("backup_service", "backup_unknown"): backup}, self.policy)
        self.assertEqual((status, steps), ("INCOMPLETE", []))

    def test_tombstone_stable_reference_requires_a_proven_retained_record(self):
        tombstone = self.resource("identity_service", "tombstone_linked", "REDACTED",
                                  "ACCOUNT_TOMBSTONE",
                                  condition_facts={"account_status": "DELETED", "user_id": "user_77"})
        retained = self.resource("security_service", "audit_retained", "PRESENT",
                                 "SECURITY_AUDIT_LOG", retention_until="2027-01-01T00:00:00Z",
                                 condition_facts={"user_id": "user_77", "retention_until": "2027-01-01T00:00:00Z"})
        status, steps = build_case_steps({
            ("identity_service", "tombstone_linked"): tombstone,
            ("security_service", "audit_retained"): retained,
        }, self.policy, "2026-09-01T00:00:00Z")
        self.assertEqual(status, "COMPLETE")
        self.assertEqual({s["operation"] for s in steps}, {
            "VERIFY_RECORD_REDACTED", "VERIFY_RECORD_PRESENT"})

        no_retention_proof = self.resource("security_service", "audit_unknown", "PRESENT",
                                           "SECURITY_AUDIT_LOG", condition_facts={"user_id": "user_77"})
        status, steps = build_case_steps({
            ("identity_service", "tombstone_linked"): tombstone,
            ("security_service", "audit_unknown"): no_retention_proof,
        }, self.policy, "2026-09-01T00:00:00Z")
        self.assertEqual(status, "INCOMPLETE")

    def test_all_supplied_policy_conditions_are_recognized(self):
        known = {
            "Always", "Conversation contains shared customer, agent, or order context that must be retained",
            "Attachment belongs only to the deletion subject", "Record is still attributable to a user",
            "Log contains a user email address", "Record is within the supplied retention period",
            "A supplied legal hold is active", "Restore access can be blocked",
            "Account is deleted and only a stable internal user_id is needed to preserve references to retained records",
        }
        self.assertEqual({rule.condition for rule in self.policy.rules.values()}, known)


if __name__ == "__main__":
    unittest.main()
