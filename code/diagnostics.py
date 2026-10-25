"""Generate reason-coded unresolved obligations and per-subject risk graphs."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

try:
    from .evidence import EvidenceIndex
    from .identity import IdentityResolver
    from .ingestion import EvidenceIngestor
    from .main import DATASET_DIR, SYSTEM_CATEGORIES, _desired_action, _record_action, load_requests
    from .policy import PolicyEngine
except ImportError:  # pragma: no cover
    from evidence import EvidenceIndex
    from identity import IdentityResolver
    from ingestion import EvidenceIngestor
    from main import DATASET_DIR, SYSTEM_CATEGORIES, _desired_action, _record_action, load_requests
    from policy import PolicyEngine

RESOURCE_RE = re.compile(r"\b(?:account|analytics|backup|data_flow|export|search|support|audit_record|tombstone)_[A-Za-z0-9_-]+\b")


def build_diagnostics(request_path: Path = DATASET_DIR / "deletion_requests.csv") -> tuple[list[dict], list[dict]]:
    resolver = IdentityResolver(str(DATASET_DIR / "user_identities.csv"), str(DATASET_DIR / "user_audit_log.csv"))
    index = EvidenceIndex(EvidenceIngestor(str(DATASET_DIR)))
    policy = PolicyEngine(str(DATASET_DIR / "deletion_rules.csv"))
    unresolved: list[dict] = []
    graphs: list[dict] = []

    for request in load_requests(request_path):
        case_id, cutoff = request["case_id"], request["audit_at"]
        if not IdentityResolver.is_deletion_authorized(request.get("request_text", "")):
            continue
        user = resolver.resolve_by_email(request.get("email", ""), request.get("requested_at", ""))
        if user is None:
            unresolved.append({
                "case_id": case_id, "as_of": cutoff, "reason_code": "IDENTITY_UNRESOLVED_OR_AMBIGUOUS",
                "obligation": "Resolve the Data Subject to one identity using temporally valid current or historical identifiers.",
                "system_id": "identity_service", "resource_id": "", "observed_state": "UNKNOWN",
                "required_action": "ENTITY_RESOLUTION", "evidence_ids": [],
                "missing_evidence": ["unique identity ownership evidence at requested_at"],
            })
            graphs.append({"case_id": case_id, "as_of": cutoff, "nodes": [], "edges": [], "resurrection_risks": []})
            continue

        resources = index.get_user_resources(user, request.get("requested_at", ""),
                                             request.get("reported_at", ""), cutoff)
        if not resources:
            unresolved.append({
                "case_id": case_id, "as_of": cutoff, "reason_code": "SUBJECT_LINEAGE_GAP",
                "obligation": "Discover and reconcile all applicable stores for this Data Subject.",
                "system_id": "data_inventory", "resource_id": "", "observed_state": "UNKNOWN",
                "required_action": "EVIDENCE_DISCOVERY", "evidence_ids": [],
                "missing_evidence": [f"subject-linked inventory evidence from {system}" for system in sorted(SYSTEM_CATEGORIES)],
            })

        nodes: dict[str, dict] = {}
        edges: list[dict] = []
        subject_node = f"subject:{case_id}"
        nodes[subject_node] = {"node_id": subject_node, "node_type": "DATA_SUBJECT_CASE"}
        resource_ids = {item.resource_id for item in resources.values()}
        for item in resources.values():
            node_id = f"{item.system_id}:{item.resource_id}:{item.resource_location}"
            nodes[node_id] = {
                "node_id": node_id, "node_type": "RESOURCE", "system_id": item.system_id,
                "resource_id": item.resource_id, "resource_location": item.resource_location,
                "state": item.state, "data_category": item.data_category,
                "observed_at": item.observed_at, "captured_at": item.captured_at,
                "evidence_ids": sorted({item.evidence_id, *item.conflict_evidence_ids} - {""}),
            }
            edges.append({"from": subject_node, "to": node_id, "relation": "SUBJECT_LINEAGE",
                          "evidence_ids": nodes[node_id]["evidence_ids"]})
            action = _desired_action(item, policy, cutoff, resources)
            violation = _record_action(item, action)
            if action == "UNRESOLVED" and item.state != "UNKNOWN":
                rule = policy.rules.get(item.data_category or SYSTEM_CATEGORIES.get(item.system_id, ""))
                unresolved.append({
                    "case_id": case_id, "as_of": cutoff,
                    "reason_code": "POLICY_CONDITION_UNPROVEN",
                    "obligation": "Resolve the conditional policy rule before declaring this resource compliant.",
                    "system_id": item.system_id, "resource_id": item.resource_id,
                    "resource_location": item.resource_location, "observed_state": item.state,
                    "required_action": rule.required_action if rule else "UNKNOWN",
                    "condition": rule.condition if rule else "unknown policy condition",
                    "evidence_ids": [item.evidence_id] if item.evidence_id else [],
                    "missing_evidence": policy.condition_evidence_needed(rule) if rule else ["applicable policy rule"],
                })
            if item.state == "UNKNOWN":
                unresolved.append({
                    "case_id": case_id, "as_of": cutoff, "reason_code": "CONFLICTING_LATEST_OBSERVATIONS",
                    "obligation": "Resolve conflicting equally recent observations before deciding deletion state.",
                    "system_id": item.system_id, "resource_id": item.resource_id,
                    "resource_location": item.resource_location, "observed_state": "UNKNOWN",
                    "required_action": action, "evidence_ids": sorted({item.evidence_id, *item.conflict_evidence_ids} - {""}),
                    "missing_evidence": ["authoritative attestation or a later reconciled observation"],
                })
            elif violation:
                op, _ = violation
                unresolved.append({
                    "case_id": case_id, "as_of": cutoff, "reason_code": "POLICY_ACTION_REQUIRED",
                    "obligation": f"Complete {action.lower()} for the remaining policy violation ({op}).",
                    "system_id": item.system_id, "resource_id": item.resource_id,
                    "resource_location": item.resource_location, "observed_state": item.state,
                    "required_action": action, "evidence_ids": [item.evidence_id] if item.evidence_id else [],
                    "missing_evidence": ["post-remediation verification"],
                })
            elif (action == "RETAIN" and item.state != "PRESENT" and
                  not (item.system_id == "backup_service" and item.state == "BLOCKED")):
                unresolved.append({
                    "case_id": case_id, "as_of": cutoff, "reason_code": "RETAINED_RECORD_NOT_PROVEN",
                    "obligation": "Prove the policy-required retained record is available.",
                    "system_id": item.system_id, "resource_id": item.resource_id,
                    "resource_location": item.resource_location, "observed_state": item.state,
                    "required_action": "RETAIN", "evidence_ids": [item.evidence_id] if item.evidence_id else [],
                    "missing_evidence": ["current presence attestation"],
                })

        # Subject-associated synchronization/restore events define directed
        # reachability edges. Activity rows are treated as evidence of a path,
        # not as proof that a resulting data mutation succeeded.
        for activity in index.ingestor.activities:
            if activity.event_time > cutoff:
                continue
            mentioned = set(RESOURCE_RE.findall(activity.details or ""))
            activity_res = activity.resource_id
            if activity_res not in resource_ids and not (mentioned & resource_ids):
                continue
            if activity.event_type not in {"SYNC_RECORD", "RESTORE_RECORD", "RESTORE_BACKUP", "REPLAY_BACKUP", "REPOPULATE_RECORD"} and "repopulated downstream resource" not in (activity.details or "").lower():
                continue
            target_ids = sorted(mentioned & resource_ids)
            source_matches = [n for n, v in nodes.items() if v.get("resource_id") == activity_res]
            for target_id in target_ids:
                target_matches = [n for n, v in nodes.items() if v.get("resource_id") == target_id]
                for source in source_matches:
                    for target in target_matches:
                        edges.append({"from": source, "to": target,
                                      "relation": "CAN_REPOPULATE" if activity.source_system in {"integration_service", "backup_service"} else "DATA_PROPAGATION",
                                      "activity_id": activity.activity_id, "observed_at": activity.event_time,
                                      "reported_result": activity.reported_result})

        # A subject-linked active flow/restore source can resurrect any
        # currently absent prohibited copy in the same evidence chain.
        risks = []
        for source_id, source in sorted(nodes.items()):
            if source.get("node_type") != "RESOURCE" or source.get("state") != "ACTIVE":
                continue
            if source.get("system_id") not in {"integration_service", "backup_service"}:
                continue
            source_edges = [e for e in edges if e.get("from") == source_id and e.get("relation") in {"CAN_REPOPULATE", "DATA_PROPAGATION"}]
            targets = {e["to"] for e in source_edges}
            if source.get("system_id") == "backup_service":
                targets.update(n for n, v in nodes.items() if v.get("node_type") == "RESOURCE" and v.get("state") == "ABSENT")
            for target in sorted(targets):
                target_node = nodes[target]
                if target_node.get("state") in {"ABSENT", "REDACTED", "ANONYMIZED"}:
                    risks.append({"source": source_id, "target": target,
                                  "path": [source_id, target],
                                  "risk": "RESURRECTION_RISK",
                                  "evidence_ids": sorted({source.get("evidence_ids", [""])[0], *[e.get("activity_id", "") for e in source_edges]} - {""})})
                    edges.append({"from": source_id, "to": target, "relation": "RESURRECTION_RISK"})
        graphs.append({"case_id": case_id, "as_of": cutoff,
                       "nodes": [nodes[n] for n in sorted(nodes)],
                       "edges": sorted(edges, key=lambda e: (e["from"], e["relation"], e["to"])),
                       "resurrection_risks": risks})

    return unresolved, graphs


def main() -> None:
    parser = argparse.ArgumentParser(description="Create reason-coded obligation and resurrection risk artifacts")
    parser.add_argument("--unresolved", type=Path, default=Path("evaluation_artifacts/unresolved_obligations.json"))
    parser.add_argument("--graph", type=Path, default=Path("evaluation_artifacts/resurrection_risk_graph.json"))
    args = parser.parse_args()
    unresolved, graphs = build_diagnostics()
    for path, payload in ((args.unresolved, unresolved), (args.graph, graphs)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(unresolved)} unresolved obligations and {len(graphs)} subject risk graphs")


if __name__ == "__main__":
    main()
