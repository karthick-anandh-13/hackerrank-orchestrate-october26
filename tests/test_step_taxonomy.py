import unittest

from code.policy import PolicyEngine


class CanonicalStepTaxonomyTests(unittest.TestCase):
    def test_sort_is_invariant_to_evidence_discovery_order(self):
        steps = [
            {"step_no": 0, "phase": "VERIFICATION", "system_id": "integration_service", "resource_id": "flow_1", "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": "e1"},
            {"step_no": 0, "phase": "FINDING", "system_id": "support_platform", "resource_id": "support_1", "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": "e2"},
            {"step_no": 0, "phase": "REMEDIATION", "system_id": "support_platform", "resource_id": "support_1", "operation": "REDACT_RECORD", "state": "REDACTED", "evidence_id": ""},
            {"step_no": 0, "phase": "FINDING", "system_id": "search_service", "resource_id": "search_1", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "e3"},
        ]
        left = PolicyEngine.sort_steps([dict(s) for s in steps])
        right = PolicyEngine.sort_steps([dict(s) for s in reversed(steps)])
        self.assertEqual(left, right)
        self.assertEqual([s["phase"] for s in left], ["FINDING", "FINDING", "REMEDIATION", "VERIFICATION"])
        self.assertEqual([s["step_no"] for s in left], [1, 2, 3, 4])

    def test_unknown_or_misphased_operation_is_rejected(self):
        with self.assertRaises(ValueError):
            PolicyEngine.sort_steps([{"phase": "FINDING", "operation": "NO_ACTION", "system_id": "", "resource_id": ""}])
        with self.assertRaises(ValueError):
            PolicyEngine.sort_steps([{"phase": "FINDING", "operation": "DELETE_RECORD", "system_id": "", "resource_id": ""}])


if __name__ == "__main__":
    unittest.main()
