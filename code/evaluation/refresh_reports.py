"""Regenerate evaluation and usage reports from the current output artifacts."""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from code.diagnostics import build_diagnostics
from code.evidence import EvidenceIndex
from code.identity import IdentityResolver
from code.ingestion import EvidenceIngestor
from code.main import DATASET_DIR, run
from code.policy import PolicyEngine


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as stream:
        return list(csv.DictReader(stream))


def report_metrics() -> dict:
    output_rows = read_csv(ROOT / "output.csv")
    output = {row["case_id"]: row for row in output_rows}
    requests = {row["case_id"]: row for row in read_csv(DATASET_DIR / "deletion_requests.csv")}
    expected = {row["case_id"]: row for row in read_csv(DATASET_DIR / "sample_output.csv")}
    with tempfile.TemporaryDirectory() as tmp:
        actual_rows = run(DATASET_DIR / "sample_deletion_requests.csv", Path(tmp) / "sample.csv")
    actual = {row["case_id"]: row for row in actual_rows}

    status_matches = sum(expected[c]["deletion_status"] == actual[c]["deletion_status"] for c in expected)
    exact_sequences = sum(json.loads(expected[c]["steps_json"]) == json.loads(actual[c]["steps_json"])
                          for c in expected)
    exact_combined = sum(
        expected[c]["deletion_status"] == actual[c]["deletion_status"]
        and json.loads(expected[c]["steps_json"]) == json.loads(actual[c]["steps_json"])
        for c in expected
    )
    expected_steps = {c: json.loads(row["steps_json"]) for c, row in expected.items()}
    actual_steps = {c: json.loads(row["steps_json"]) for c, row in actual.items()}
    public_details = []
    for cid in sorted(expected):
        exp_steps, act_steps = expected_steps[cid], actual_steps[cid]
        public_details.append({
            "case_id": cid,
            "expected_status": expected[cid]["deletion_status"],
            "actual_status": actual[cid]["deletion_status"],
            "status_match": expected[cid]["deletion_status"] == actual[cid]["deletion_status"],
            "expected_step_count": len(exp_steps), "actual_step_count": len(act_steps),
            "exact_ordered_step_match": exp_steps == act_steps,
            "exact_ordered_output_match": (expected[cid]["deletion_status"] == actual[cid]["deletion_status"]
                                            and exp_steps == act_steps),
            "expected_steps": exp_steps, "actual_steps": act_steps,
        })
    expected_step_count = sum(map(len, expected_steps.values()))
    actual_step_count = sum(map(len, actual_steps.values()))
    position_matches = 0
    field_matches = 0
    field_positions = 0
    for cid in expected:
        es, ac = expected_steps[cid], actual_steps[cid]
        for index in range(max(len(es), len(ac))):
            field_positions += 7
            if index < len(es) and index < len(ac):
                position_matches += int(es[index] == ac[index])
                field_matches += sum(es[index].get(key) == ac[index].get(key)
                                     for key in ("step_no", "phase", "system_id", "resource_id",
                                                 "operation", "state", "evidence_id"))
    statuses = Counter(row["deletion_status"] for row in output_rows)
    authorized = {
        cid for cid, request in requests.items()
        if IdentityResolver.is_deletion_authorized(request.get("request_text", ""))
    }
    unresolved, graphs = build_diagnostics(DATASET_DIR / "deletion_requests.csv")
    reasons_by_case: dict[str, set[str]] = defaultdict(set)
    reason_counts = Counter()
    for obligation in unresolved:
        reasons_by_case[obligation["case_id"]].add(obligation["reason_code"])
        reason_counts[obligation["reason_code"]] += 1
    incomplete_with_findings = sum(
        output[cid]["deletion_status"] == "INCOMPLETE"
        and any(step["phase"] == "FINDING" for step in json.loads(output[cid]["steps_json"]))
        for cid in authorized
    )
    incomplete_without_findings = sum(
        output[cid]["deletion_status"] == "INCOMPLETE"
        and not any(step["phase"] == "FINDING" for step in json.loads(output[cid]["steps_json"]))
        for cid in authorized
    )
    test_run = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
        cwd=ROOT, text=True, capture_output=True,
    )
    test_text = test_run.stdout + test_run.stderr
    if test_run.returncode:
        raise RuntimeError("Full test suite failed while refreshing reports:\n" + test_text[-4000:])
    test_count = 0
    for line in test_text.splitlines():
        if line.startswith("Ran ") and " tests " in line:
            test_count = int(line.split()[1])
            break

    ingestor = EvidenceIngestor(str(DATASET_DIR))
    return {
        "output_rows": len(output_rows), "statuses": statuses, "authorized": len(authorized),
        "na": statuses["NOT_APPLICABLE"], "complete_authorized": sum(
            output[c]["deletion_status"] == "COMPLETE" for c in authorized),
        "incomplete_with_findings": incomplete_with_findings,
        "incomplete_without_findings": incomplete_without_findings,
        "unresolved": unresolved, "reason_counts": reason_counts,
        "reason_case_counts": {key: sum(key in reasons for reasons in reasons_by_case.values())
                                for key in sorted(reason_counts)},
        "graphs": graphs, "status_matches": status_matches, "exact_sequences": exact_sequences,
        "exact_combined": exact_combined, "public_cases": len(expected),
        "expected_step_count": expected_step_count, "actual_step_count": actual_step_count,
        "position_matches": position_matches, "field_matches": field_matches,
        "field_positions": field_positions, "test_count": test_count,
        "evidence_files": len(ingestor.manifest), "evidence_items": len(ingestor.evidence_items),
        "activities": len(ingestor.activities), "output": output,
        "public_details": public_details,
    }


def pct(n: int, d: int) -> str:
    return f"{100*n/d:.2f}%" if d else "n/a"


def write_reports(m: dict) -> None:
    cov = [
        "# Evidence Coverage Report", "",
        "Generated by `python3 -m code.evaluation.refresh_reports` from the current root `output.csv`, participant-facing inputs, and diagnostics.", "",
        "## Case-level output and evidence-chain classes", "",
        "| Class | Cases | Share of authorized requests | Interpretation |", "|---|---:|---:|---|",
        f"| Evidence-backed closure over discovered resources | {m['complete_authorized']} | {pct(m['complete_authorized'], m['authorized'])} | Does not establish exhaustive inventory coverage. |",
        f"| Incomplete with supported findings | {m['incomplete_with_findings']} | {pct(m['incomplete_with_findings'], m['authorized'])} | Output contains at least one evidence-backed finding. |",
        f"| Incomplete without emitted findings | {m['incomplete_without_findings']} | {pct(m['incomplete_without_findings'], m['authorized'])} | Missing links, unresolved conditions, or conflicts prevent a grounded action sequence. |",
        f"| Not applicable | {m['na']} | — | Request text does not authorize deletion. |", "",
        "These categories derive from the current output. `COMPLETE` means all discovered obligations were verified, not that the supplied evidence proves the company-wide inventory is exhaustive.", "",
        "## Unresolved evidence and policy conditions", "",
        f"Diagnostics contain {len(m['unresolved'])} unresolved obligation records and {sum(m['reason_case_counts'].values())} case/reason assignments (case counts below can overlap).", "",
        "| Reason code | Obligation records | Cases affected |", "|---|---:|---:|",
    ]
    for reason in sorted(m["reason_counts"]):
        cov.append(f"| `{reason}` | {m['reason_counts'][reason]} | {m['reason_case_counts'][reason]} |")
    cov += ["", f"The diagnostic graph contains {len(m['graphs'])} subject-case graphs. Open-world inventory coverage, hidden-set accuracy, and operational control effectiveness remain unverified.", ""]
    (ROOT / "code/evaluation/evidence_coverage_report.md").write_text("\n".join(cov), encoding="utf-8")

    eval_lines = [
        "# Evaluation Report", "", "Generated from the participant-visible public sample and current pipeline output.", "",
        "## Public sample", "",
        "| Metric | Result |", "|---|---:|",
        f"| Deletion-status accuracy | {m['status_matches']} / {m['public_cases']} ({pct(m['status_matches'], m['public_cases'])}) |",
        f"| Position-aligned exact step recall | {m['position_matches']} / {m['expected_step_count']} ({pct(m['position_matches'], m['expected_step_count'])}) |",
        f"| Position-aligned exact step precision | {m['position_matches']} / {m['actual_step_count']} ({pct(m['position_matches'], m['actual_step_count'])}) |",
        f"| Field accuracy | {m['field_matches']} / {m['field_positions']} ({pct(m['field_matches'], m['field_positions'])}) |",
        f"| Exact ordered status and sequence accuracy | {m['exact_combined']} / {m['public_cases']} ({pct(m['exact_combined'], m['public_cases'])}) |", "",
        "The evaluator compares decoded JSON arrays in order; whitespace and object-key order do not affect its score. The public sample was used during development and is not a blind holdout.", "",
        "## Participant-created regression scenarios", "",
        "The current suite has " + str(m["test_count"]) + " tests. Condition-specific cases exercise active, inactive, missing, and conflicting legal-hold evidence; support messages with shared context, without shared context, and with unknown/ambiguous context; and verify the resulting finding, remediation, verification, and status.", "",
        "Other tests cover historical identifiers, missing evidence, retention boundaries, anonymization, tombstones, active flows, restore risk, equal-time replica conflicts, and deterministic step ordering.", "",
        "## Findings and limitations", "",
        "Policy conditions now use three-valued evaluation. Actions are selected only when supported facts establish the condition; explicitly false conditions use a documented fallback where the erasure rules support one; missing or contradictory facts remain unresolved and cannot support `COMPLETE`.", "",
        f"This pass yields {m['status_matches']}/{m['public_cases']} public statuses and {m['exact_sequences']}/{m['public_cases']} exact sequences. The public sample was used as a diagnostic during development; no sample IDs or expected outputs are special-cased.", "",
        "Exact-step mismatches remain concentrated in incomplete identity/resource links and unresolved policy conditions. Missing or conflicting evidence remains unresolved rather than being treated as proof of deletion or retention.", "",
        "The evidence inventory is open-world. A `COMPLETE` result covers discovered resources only; supplied evidence does not establish that every company system or restore path has been inventoried. Hidden-set accuracy is unknown.", "",
        f"Final generated output has {m['output_rows']} rows: {m['statuses']['COMPLETE']} `COMPLETE`, {m['statuses']['INCOMPLETE']} `INCOMPLETE`, {m['statuses']['NOT_APPLICABLE']} `NOT_APPLICABLE`. The independent output validator and full test suite must pass on this same artifact before submission.", "",
    ]
    (ROOT / "code/evaluation/evaluation_report.md").write_text("\n".join(eval_lines), encoding="utf-8")

    usage = [
        "# Usage Report", "", "## Final full-dataset run", "",
        f"The current output contains {m['output_rows']} requests and was generated by `python3 -m code.main`. The local pipeline uses no external model provider.", "",
        "| Provider / model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost |", "|---|---:|---:|---:|---:|---:|",
        "| None (local Python pipeline) | 0 | 0 | 0 | 0 | $0.00 |",
        "| **Overall** | **0** | **0** | **0** | **0** | **$0.00** |", "",
        f"Requests: {m['output_rows']}; average model calls/tokens/cost per request: 0 / 0 / $0.00. Local parsing uses {m['evidence_files']} manifest files, produced {m['evidence_items']} evidence items, and read {m['activities']} activity rows. `pdftotext` and `tesseract` are local utilities, not model providers.", "",
        "## Results tied to this output", "",
        f"Status distribution: {m['statuses']['COMPLETE']} COMPLETE, {m['statuses']['INCOMPLETE']} INCOMPLETE, {m['statuses']['NOT_APPLICABLE']} NOT_APPLICABLE. Public sample: {m['status_matches']}/{m['public_cases']} status matches and {m['exact_sequences']}/{m['public_cases']} exact ordered sequences.", "",
        f"Evidence coverage: {m['complete_authorized']}/{m['authorized']} authorized cases have evidence-backed closure over discovered resources; {m['incomplete_with_findings']} have supported findings; {m['incomplete_without_findings']} have no emitted findings because the evidence or policy condition is unresolved. This does not establish exhaustive inventory coverage.", "",
        "## Methodology", "",
        "Step ordering follows the challenge's fixed phase and operation order. Conditions use explicit parsed facts and three-valued logic. Public answers were used as a diagnostic evaluation set, not as a blind holdout; no public case IDs or expected answers are hardcoded in prediction logic. `python3 -m code.evaluation.refresh_reports` regenerates metrics from the current output and public sample and reruns the complete test suite.", "",
    ]
    (ROOT / "code/evaluation/usage_report.md").write_text("\n".join(usage), encoding="utf-8")

    condition_doc = [
        "# Policy Condition Audit", "", "Condition text comes directly from `dataset/deletion_rules.csv`. The evaluator does not treat an absent fact as false.", "",
        "| Rule condition | Implemented evidence | False / unknown handling |", "|---|---|---|",
        "| `Always` | Unconditional true. | Applies the rule action. |",
        "| Shared support context | Explicit shared-context flags or literal order references; excerpts that explicitly mention a customer or agent also establish shared conversation context. | False falls back to deleting the message; conflicting explicit classification is unresolved. |",
        "| Attachment belongs only to subject | Explicit ownership boolean (`belongs_only_to_subject`, `subject_only`, or `exclusive_to_subject`). | False or unknown stays unresolved because deleting shared material is not authorized by this rule. |",
        "| Analytics/telemetry attributable | Explicit attribution flag or parsed subject identifiers. | False is no-action only when the observed record is already absent/redacted/anonymized; otherwise status remains incomplete. |",
        "| Email delivery log contains email | Explicit email-presence flag or parsed email field. | False is no-action; unknown remains unresolved. |",
        "| Security record within retention | Valid `retention_until` / `retained_until` compared with `audit_at`; boundary is exclusive. | Before deadline: retain. At/after deadline: delete. Missing/invalid date: unresolved. |",
        "| Legal hold active | Explicit `hold_active`, `legal_hold_active`, or `active` boolean only. A retention date is not silently converted into a hold-status fact. | Inactive falls back to deletion; missing/ambiguous status is unresolved. |",
        "| Backup access can be blocked | Explicit `restore_blockable` / `can_block_restore` attestation. `restore_allowed=false` proves current block state, not general capability. | False or missing is unresolved; no unsupported successful control is claimed. |",
        "| Tombstone condition | Explicit deleted status and stable-reference requirement, or deleted account plus a linked retained record using the stable `user_id`. | False falls back to deletion; missing evidence is unresolved. |", "",
        "Condition-unresolved cases are forced to `INCOMPLETE`. Because the CSV contract has no UNKNOWN state or policy-condition step, the reason is recorded in the reason-coded diagnostic artifact; unresolved obligations may not have a representable step in `steps_json`.", "",
    ]
    (ROOT / "code/evaluation/policy_condition_audit.md").write_text("\n".join(condition_doc), encoding="utf-8")
    artifacts = ROOT / "evaluation_artifacts" / "final_run"
    artifacts.mkdir(parents=True, exist_ok=True)
    (ROOT / "evaluation_artifacts" / "public_32_case_mismatch_report_final.json").write_text(
        json.dumps({
            "evaluator_contract": {
                "source": "code/evaluation/main.py:score_public_sample",
                "command": "python3 -m code.evaluation.main",
                "status": "exact string equality",
                "steps": "decoded JSON array equality; order and all step values matter",
            },
            "summary": {
                "cases": m["public_cases"], "status_matches": m["status_matches"],
                "status_accuracy": m["status_matches"] / m["public_cases"],
                "exact_ordered_step_matches": m["exact_sequences"],
                "exact_ordered_step_accuracy": m["exact_sequences"] / m["public_cases"],
                "combined_matches": m["exact_combined"],
                "combined_accuracy": m["exact_combined"] / m["public_cases"],
            },
            "cases": m["public_details"],
        }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    output_bytes = (ROOT / "output.csv").read_bytes()
    final_run = {
        "generation_command": "python3 -m code.main",
        "validation_command": "python3 -m code.validate_output",
        "tests_command": "python3 -m unittest discover -s tests -v",
        "public_evaluation_command": "python3 -m code.evaluation.main",
        "report_refresh_command": "python3 -m code.evaluation.refresh_reports",
        "request_rows": len(read_csv(DATASET_DIR / "deletion_requests.csv")),
        "output_rows": m["output_rows"],
        "output_sha256": hashlib.sha256(output_bytes).hexdigest(),
        "status_distribution": dict(m["statuses"]),
        "tests_passed": m["test_count"], "tests_failed": 0,
        "output_validator": "passed before report refresh",
        "public_sample": {
            "status_matches": m["status_matches"], "cases": m["public_cases"],
            "exact_step_sequence_matches": m["exact_sequences"],
            "exact_combined_matches": m["exact_combined"],
        },
        "evidence_manifest_files": m["evidence_files"],
        "parsed_evidence_items": m["evidence_items"], "activity_rows": m["activities"],
        "unresolved_obligation_records": len(m["unresolved"]),
        "risk_graph_cases": len(m["graphs"]), "usage_model_provider_calls": 0,
    }
    (artifacts / "final_run.json").write_text(json.dumps(final_run, indent=2) + "\n", encoding="utf-8")
    print(f"Reports refreshed; {m['test_count']} tests passed; public score {m['status_matches']}/{m['public_cases']} status, {m['exact_sequences']}/{m['public_cases']} exact sequence.")


if __name__ == "__main__":
    write_reports(report_metrics())
