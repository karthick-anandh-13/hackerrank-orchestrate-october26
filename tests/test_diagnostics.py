import unittest
from pathlib import Path

from code.diagnostics import build_diagnostics


class DiagnosticsArtifactTests(unittest.TestCase):
    def test_sample_diagnostics_are_reason_coded_and_temporal(self):
        unresolved, graphs = build_diagnostics(Path("dataset/sample_deletion_requests.csv"))
        self.assertTrue(unresolved)
        self.assertTrue(all(item.get("reason_code") and item.get("as_of") is not None for item in unresolved))
        self.assertTrue(all("nodes" in graph and "edges" in graph and "resurrection_risks" in graph for graph in graphs))
        self.assertTrue(any(item["reason_code"] == "POLICY_ACTION_REQUIRED" for item in unresolved))


if __name__ == "__main__":
    unittest.main()
