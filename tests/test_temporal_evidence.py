import unittest
from types import SimpleNamespace

from code.evidence import EvidenceIndex
from code.identity import IdentityResolver
from code.ingestion import EvidenceIngestor, EvidenceItem


class TemporalEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ingestor = EvidenceIngestor("dataset")
        cls.index = EvidenceIndex(cls.ingestor)

    def test_observation_time_orders_multiple_log_rows_in_one_capture(self):
        self.assertTrue(all(item.observed_at and item.resource_location for item in self.ingestor.evidence_items))
        latest = self.index._find_latest_evidence_for_resource("account_8473", "2026-09-07T00:00:00Z",
                                                               "account_service")
        self.assertIsNotNone(latest)
        self.assertEqual(latest.state, "ABSENT")
        self.assertEqual(latest.observed_at, "2026-09-06T07:00:00Z")

    def test_manifest_capture_time_bounds_evidence_availability(self):
        latest = self.index._find_latest_evidence_for_resource("account_8473", "2026-09-05T00:00:00Z",
                                                               "account_service")
        self.assertIsNone(latest)

    def test_observation_after_audit_cutoff_is_excluded(self):
        ingestor = SimpleNamespace(evidence_items=[
            EvidenceItem("before_cutoff", "2026-09-05T00:00:00Z", "primary", "snapshot.sql",
                         "account_service", "account_x", observed_at="2026-09-05T12:00:00Z",
                         resource_location="primary:profiles", state="PRESENT"),
            EvidenceItem("after_cutoff", "2026-09-05T00:00:00Z", "replica", "snapshot.sql",
                         "account_service", "account_x", observed_at="2026-09-07T12:00:00Z",
                         resource_location="replica:profiles", state="ABSENT"),
        ], activities=[])
        latest = EvidenceIndex(ingestor)._find_latest_evidence_for_resource(
            "account_x", "2026-09-06T00:00:00Z", "account_service")
        self.assertEqual(latest.file_id, "before_cutoff")
        self.assertEqual(latest.state, "PRESENT")

    def test_stale_and_current_observations_use_temporal_provenance(self):
        ingestor = SimpleNamespace(evidence_items=[
            EvidenceItem("stale", "2026-09-05T00:00:00Z", "replica_eu", "snapshot.sql",
                         "account_service", "account_x", observed_at="2026-09-04T23:00:00Z",
                         resource_location="replica_eu:profiles", state="PRESENT"),
            EvidenceItem("current", "2026-09-06T00:00:00Z", "primary", "snapshot.sql",
                         "account_service", "account_x", observed_at="2026-09-05T23:00:00Z",
                         resource_location="primary:profiles", state="ABSENT"),
        ], activities=[])
        latest = EvidenceIndex(ingestor)._find_latest_evidence_for_resource(
            "account_x", "2026-09-07T00:00:00Z", "account_service")
        self.assertEqual(latest.state, "ABSENT")
        self.assertEqual(latest.resource_location, "primary:profiles")

    def test_equal_time_replica_conflict_is_unknown(self):
        ingestor = SimpleNamespace(evidence_items=[
            EvidenceItem("replica_present", "2026-09-06T00:00:00Z", "replica_eu", "a.sql",
                         "account_service", "account_x", observed_at="2026-09-05T23:00:00Z",
                         resource_location="replica_eu:profiles", state="PRESENT"),
            EvidenceItem("primary_absent", "2026-09-06T00:00:00Z", "primary", "b.sql",
                         "account_service", "account_x", observed_at="2026-09-05T23:00:00Z",
                         resource_location="primary:profiles", state="ABSENT"),
        ], activities=[])
        latest = EvidenceIndex(ingestor)._find_latest_evidence_for_resource(
            "account_x", "2026-09-07T00:00:00Z", "account_service")
        self.assertEqual(latest.state, "UNKNOWN")
        self.assertEqual(set(latest.raw_payload["conflict_evidence_ids"]), {"replica_present", "primary_absent"})

    def test_incomplete_source_lineage_does_not_attach_unrelated_copy(self):
        user = IdentityResolver("dataset/user_identities.csv", "dataset/user_audit_log.csv").resolve_by_user_id("user_01")
        ingestor = SimpleNamespace(evidence_items=[
            EvidenceItem("subject_record", "2026-09-01T00:00:00Z", "primary", "a.json",
                         "account_service", "account_subject", user_id="user_01", state="ABSENT"),
            EvidenceItem("orphan_copy", "2026-09-01T00:00:00Z", "search", "b.json",
                         "search_service", "search_orphan", state="PRESENT",
                         raw_payload={"source_resource_id": "unknown_source"}),
        ], activities=[])
        found = EvidenceIndex(ingestor).get_user_resources(
            user, "2026-08-01T00:00:00Z", "2026-08-02T00:00:00Z", "2026-09-02T00:00:00Z")
        self.assertIn(("account_service", "account_subject"), found)
        self.assertNotIn(("search_service", "search_orphan"), found)


if __name__ == "__main__":
    unittest.main()
