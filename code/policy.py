"""Policy engine and step ordering definitions."""

import csv
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple


@dataclass
class DeletionRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: str


class PolicyEngine:
    # The participant output contract exposes only these three phases. Within
    # each phase, operation order is policy/state driven and independent of
    # evidence ingestion or resource discovery order.
    CANONICAL_STEP_TAXONOMY = (
        ("FINDING", "REPORT_REMAINING_RECORD"),
        ("FINDING", "REPORT_EXPOSED_PII"),
        ("FINDING", "REPORT_ACTIVE_DATA_FLOW"),
        ("FINDING", "REPORT_RESTORE_RISK"),
        ("REMEDIATION", "DISABLE_DATA_FLOW"),
        ("REMEDIATION", "BLOCK_RESTORE"),
        ("REMEDIATION", "DELETE_RECORD"),
        ("REMEDIATION", "REDACT_RECORD"),
        ("REMEDIATION", "ANONYMIZE_RECORD"),
        ("VERIFICATION", "VERIFY_RECORD_ABSENT"),
        ("VERIFICATION", "VERIFY_RECORD_PRESENT"),
        ("VERIFICATION", "VERIFY_RECORD_REDACTED"),
        ("VERIFICATION", "VERIFY_RECORD_ANONYMIZED"),
        ("VERIFICATION", "VERIFY_DATA_FLOW_DISABLED"),
        ("VERIFICATION", "VERIFY_RESTORE_BLOCKED"),
    )

    PHASE_ORDER = {
        'FINDING': 1,
        'REMEDIATION': 2,
        'VERIFICATION': 3,
    }

    OPERATION_ORDER = {
        # FINDINGS
        'REPORT_REMAINING_RECORD': 1,
        'REPORT_EXPOSED_PII': 2,
        'REPORT_ACTIVE_DATA_FLOW': 3,
        'REPORT_RESTORE_RISK': 4,
        # REMEDIATION
        'DISABLE_DATA_FLOW': 10,
        'BLOCK_RESTORE': 11,
        'DELETE_RECORD': 12,
        'REDACT_RECORD': 13,
        'ANONYMIZE_RECORD': 14,
        # VERIFICATION
        'VERIFY_RECORD_ABSENT': 20,
        'VERIFY_RECORD_PRESENT': 21,
        'VERIFY_RECORD_REDACTED': 22,
        'VERIFY_RECORD_ANONYMIZED': 23,
        'VERIFY_DATA_FLOW_DISABLED': 24,
        'VERIFY_RESTORE_BLOCKED': 25,
    }

    @classmethod
    def _explicit_boolean(cls, facts: dict, keys: tuple[str, ...]) -> Optional[bool]:
        """Read only explicit condition evidence; absent/unparseable is unknown."""
        seen = False
        values = []
        for key in keys:
            if key not in facts:
                continue
            seen = True
            value = facts[key]
            normalized = str(value).strip().casefold() if value is not None else ""
            if value is True or normalized in {"1", "true", "yes", "active", "enabled"}:
                values.append(True)
            elif value is False or normalized in {"0", "false", "no", "inactive", "disabled", ""}:
                values.append(False)
            else:
                return None
        if not seen or len(set(values)) != 1:
            return None
        return values[0]

    @staticmethod
    def _time(value: object):
        if not isinstance(value, str) or not value.strip():
            return None
        try:
            result = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            if result.tzinfo is None:
                result = result.replace(tzinfo=timezone.utc)
            return result.astimezone(timezone.utc)
        except ValueError:
            return None

    @classmethod
    def condition_result(cls, rule: DeletionRule, resource, audit_at: str,
                         related_resources: Optional[dict] = None) -> str:
        """Return TRUE/FALSE/UNKNOWN for the supplied natural-language clauses.

        Inferred facts are deliberately excluded. Conditions without an explicit
        evidence mapping remain UNKNOWN and cannot support COMPLETE.
        """
        condition = rule.condition.strip()
        facts = resource.condition_facts or {}
        if condition.casefold() == "always":
            return "TRUE"

        if condition == "Conversation contains shared customer, agent, or order context that must be retained":
            context_keys = ("shared_customer_context", "agent_context_retained", "order_context_retained")
            all_flag_keys = ("shared_context", "shared_context_retained", *context_keys)
            explicit_values = []
            for key in all_flag_keys:
                if key not in facts:
                    continue
                value = cls._explicit_boolean({key: facts[key]}, (key,))
                if value is None:
                    return "UNKNOWN"
                explicit_values.append((key, value))
            if {value for _, value in explicit_values} == {True, False}:
                return "UNKNOWN"
            order_reference = facts.get("order_reference")
            message = str(facts.get("message_text") or facts.get("message_excerpt") or "")
            order_context = ((isinstance(order_reference, str) and bool(order_reference.strip()))
                             or bool(re.search(r"\bORD-[A-Za-z0-9-]+\b", message, re.IGNORECASE)))
            text_context = order_context or bool(re.search(r"\b(customer|agent)\b", message, re.IGNORECASE))
            if text_context and explicit_values and not any(value for _, value in explicit_values):
                return "UNKNOWN"
            if any(value for _, value in explicit_values):
                return "TRUE"
            explicit_general = any(key in {"shared_context", "shared_context_retained"}
                                   for key, _ in explicit_values)
            explicit_components_complete = all(key in facts for key in context_keys)
            if explicit_general or explicit_components_complete:
                return "FALSE"
            # An explicit order reference in the captured conversation is
            # direct evidence of shared order context. Do not classify free
            # text as private merely because a marker was not found.
            if text_context:
                return "TRUE"
            return "UNKNOWN"

        if condition == "Attachment belongs only to the deletion subject":
            explicit = cls._explicit_boolean(
                facts, ("belongs_only_to_subject", "subject_only", "exclusive_to_subject"))
            return "UNKNOWN" if explicit is None else ("TRUE" if explicit else "FALSE")

        if condition == "Record is still attributable to a user":
            explicit = cls._explicit_boolean(facts, ("attributable", "is_attributable"))
            if explicit is not None:
                if not explicit and any(facts.get(key) not in (None, "", "null")
                                        for key in ("user_id", "email", "phone", "email_hash")):
                    return "UNKNOWN"
                return "TRUE" if explicit else "FALSE"
            identifiers = ("user_id", "email", "phone", "email_hash")
            if any(facts.get(key) not in (None, "", "null") for key in identifiers):
                return "TRUE"
            if resource.state.upper() in {"ANONYMIZED", "REDACTED", "ABSENT"}:
                return "FALSE"
            return "UNKNOWN"

        if condition == "Log contains a user email address":
            explicit = cls._explicit_boolean(facts, ("contains_user_email", "email_present"))
            if explicit is not None:
                if not explicit and any(isinstance(facts.get(key), str) and "@" in facts[key]
                                        for key in ("email", "customer_email", "owner_email", "requester_email")):
                    return "UNKNOWN"
                return "TRUE" if explicit else "FALSE"
            email_keys = ("email", "customer_email", "owner_email", "requester_email")
            if any(isinstance(facts.get(key), str) and "@" in facts[key] for key in email_keys):
                return "TRUE"
            if any(key in facts for key in email_keys):
                return "FALSE"
            return "UNKNOWN"

        if condition == "Record is within the supplied retention period":
            until = facts.get("retention_until") or facts.get("retained_until") or resource.retention_until
            deadline, cutoff = cls._time(until), cls._time(audit_at)
            if deadline is None or cutoff is None:
                return "UNKNOWN"
            return "TRUE" if cutoff < deadline else "FALSE"

        if condition == "A supplied legal hold is active":
            explicit = cls._explicit_boolean(facts, ("hold_active", "legal_hold_active", "active"))
            return "UNKNOWN" if explicit is None else ("TRUE" if explicit else "FALSE")

        if condition == "Restore access can be blocked":
            explicit = cls._explicit_boolean(facts, ("restore_blockable", "can_block_restore"))
            if explicit is not None:
                if not explicit and resource.state.upper() == "BLOCKED":
                    return "UNKNOWN"
                return "TRUE" if explicit else "FALSE"
            # A current BLOCKED observation is direct evidence that access is
            # already blocked; a prior `restore_allowed=false` is not a general
            # capability assertion for an ACTIVE resource.
            if resource.state.upper() == "BLOCKED":
                return "TRUE"
            return "UNKNOWN"

        if condition == "Account is deleted and only a stable internal user_id is needed to preserve references to retained records":
            deleted = cls._explicit_boolean(facts, ("account_deleted",))
            if deleted is None and "account_status" in facts:
                deleted = str(facts["account_status"]).strip().casefold() == "deleted"
            stable_needed = cls._explicit_boolean(facts, ("stable_reference_required",))
            if stable_needed is None and resource.condition_facts.get("user_id") and related_resources:
                stable_uid = resource.condition_facts.get("user_id")
                cutoff = cls._time(audit_at)
                for item in related_resources.values():
                    item_facts = item.condition_facts or {}
                    if (item is resource or item.state.upper() != "PRESENT"
                            or item_facts.get("user_id") != stable_uid):
                        continue
                    if item.data_category == "SECURITY_AUDIT_LOG":
                        until = item_facts.get("retention_until") or item_facts.get("retained_until") or item.retention_until
                        deadline = cls._time(until)
                        if deadline is not None and cutoff is not None:
                            stable_needed = cutoff < deadline
                    elif item.data_category == "LEGAL_HOLD_RECORD":
                        stable_needed = cls._explicit_boolean(
                            item_facts, ("hold_active", "legal_hold_active", "active"))
                    else:
                        continue
                    if stable_needed is True:
                        break
            if deleted is None or stable_needed is None:
                return "UNKNOWN"
            return "TRUE" if deleted and stable_needed else "FALSE"

        return "UNKNOWN"

    @staticmethod
    def condition_evidence_needed(rule: DeletionRule) -> list[str]:
        return {
            "Conversation contains shared customer, agent, or order context that must be retained":
                ["explicit shared-context classification"],
            "Attachment belongs only to the deletion subject":
                ["explicit attachment ownership classification"],
            "Record is still attributable to a user":
                ["subject identifier fields or an explicit attribution result"],
            "Log contains a user email address":
                ["email field or explicit email-presence result"],
            "Record is within the supplied retention period":
                ["valid retention deadline and audit cutoff"],
            "A supplied legal hold is active":
                ["explicit legal-hold active/inactive status"],
            "Restore access can be blocked":
                ["explicit restore-blockability attestation"],
            "Account is deleted and only a stable internal user_id is needed to preserve references to retained records":
                ["account-deleted status", "explicit stable-reference requirement"],
        }.get(rule.condition.strip(), ["evidence for policy condition"])

    @classmethod
    def condition_fallback_action(cls, rule: DeletionRule) -> str:
        """Action when a supported condition is explicitly false.

        Security retention and legal-hold exemptions no longer apply after
        expiry/inactivation, so deletion is the general erasure action.
        A support message without shared context also falls back to deletion.
        Other conditions have no safe fallback specified by the policy.
        """
        if rule.data_category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD", "SUPPORT_MESSAGE", "ACCOUNT_TOMBSTONE"}:
            return "DELETE"
        if rule.data_category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY", "EMAIL_DELIVERY_LOG"}:
            return "NO_ACTION"
        return "UNRESOLVED"

    def __init__(self, rules_path: str):
        self.rules: Dict[str, DeletionRule] = {}
        self._load_rules(rules_path)

    def _load_rules(self, path: str):
        with open(path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                r = DeletionRule(
                    rule_id=row['rule_id'],
                    data_category=row['data_category'],
                    condition=row['condition'],
                    required_action=row['required_action'],
                )
                self.rules[r.data_category] = r

    @classmethod
    def step_sort_key(cls, step: dict) -> Tuple[int, int, str, str]:
        taxonomy = {operation: (phase, rank) for rank, (phase, operation)
                    in enumerate(cls.CANONICAL_STEP_TAXONOMY)}
        phase = step.get('phase', '')
        operation = step.get('operation', '')
        if operation not in taxonomy or taxonomy[operation][0] != phase:
            raise ValueError(f"Operation {operation!r} is not valid in phase {phase!r}")
        phase_rank = cls.PHASE_ORDER[phase]
        op_rank = taxonomy[operation][1]
        sys_id = step.get('system_id', '')
        res_id = step.get('resource_id', '')
        return (phase_rank, op_rank, sys_id, res_id)

    @classmethod
    def sort_steps(cls, steps: List[dict]) -> List[dict]:
        sorted_steps = sorted(steps, key=cls.step_sort_key)
        for i, s in enumerate(sorted_steps, start=1):
            s['step_no'] = i
        return sorted_steps
