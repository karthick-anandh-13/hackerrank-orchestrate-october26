"""Evidence indexing and temporal resolution module."""

from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Set, Tuple
try:
    from .identity import UserIdentity
    from .ingestion import EvidenceIngestor, EvidenceItem, SystemActivity
except ImportError:  # support ``python code/main.py`` from the repository root
    from identity import UserIdentity
    from ingestion import EvidenceIngestor, EvidenceItem, SystemActivity
import re

@dataclass
class ResourceState:
    system_id: str
    resource_id: str
    state: str  # PRESENT, ABSENT, REDACTED, ANONYMIZED, ACTIVE, DISABLED, BLOCKED
    evidence_id: str
    captured_at: str
    has_pii: bool = False
    is_flow: bool = False
    is_restore: bool = False
    is_retained: bool = False
    details: str = ""
    data_category: str = ""
    retention_until: str = ""
    observed_at: str = ""
    resource_location: str = ""
    conflict_evidence_ids: Tuple[str, ...] = ()
    # Raw, participant-visible facts needed to evaluate conditional policy
    # clauses. Missing keys remain missing so policy code can return UNKNOWN.
    condition_facts: Dict[str, object] = field(default_factory=dict)


class EvidenceIndex:
    def __init__(self, ingestor: EvidenceIngestor):
        self.ingestor = ingestor
        self.items_by_res: Dict[str, List[EvidenceItem]] = {}
        self.activities_by_res: Dict[str, List[SystemActivity]] = {}
        self._build_indices()

    def _build_indices(self):
        for item in self.ingestor.evidence_items:
            self.items_by_res.setdefault(item.resource_id, []).append(item)

        for act in self.ingestor.activities:
            self.activities_by_res.setdefault(act.resource_id, []).append(act)

    @staticmethod
    def _interpreted_state(item: EvidenceItem, system_id: str, data_category: str) -> Tuple[str, bool]:
        """Interpret tombstone compliance from permitted vs direct identifiers."""
        state = item.state or 'PRESENT'
        has_direct_identifiers = any((item.email, item.phone, item.name, item.email_hash))
        is_tombstone = data_category == 'ACCOUNT_TOMBSTONE' or system_id == 'identity_service'
        if is_tombstone:
            # A stable internal user reference is permitted by the supplied
            # tombstone rule. Only direct identifiers make the tombstone
            # exposed; an explicit PRESENT/REDACTED parser label is reconciled
            # against the extracted fields rather than trusted on its own.
            if state in {'PRESENT', 'REDACTED'}:
                state = 'PRESENT' if has_direct_identifiers else 'REDACTED'
            return state, state == 'PRESENT' and has_direct_identifiers
        has_linkable_identifier = has_direct_identifiers or bool(item.user_id)
        return state, state == 'PRESENT' and has_linkable_identifier

    def get_user_resources(
        self,
        user: UserIdentity,
        requested_at: str,
        reported_at: str,
        audit_at: str
    ) -> Dict[Tuple[str, str], ResourceState]:
        """Finds all resources associated with the user and their state at audit_at."""
        resources: Dict[Tuple[str, str], ResourceState] = {}

        # 1. Match evidence through an identity present in the record. Once a
        # resource is linked, later snapshots of that same resource remain
        # attributable even when deletion removed the identifiers.
        for item in self.ingestor.evidence_items:
            if item.captured_at > audit_at or self._item_time(item) > audit_at:
                continue

            if self._item_matches_user(item, user):
                system_id = 'support_platform' if item.system_id == 'support_replica' else item.system_id
                latest = self._find_latest_evidence_for_resource(
                    item.resource_id, audit_at, system_id=system_id
                ) or item
                key = (system_id, latest.resource_id)
                # Keep latest evidence item before or at audit_at
                if key not in resources or self._item_time(latest) >= (resources[key].observed_at or resources[key].captured_at):
                    is_flow = (system_id == 'integration_service')
                    is_restore = (system_id == 'backup_service')
                    is_retained = (system_id == 'security_service')
                    data_category = (latest.data_category or item.data_category or
                                     ('SUPPORT_ATTACHMENT' if item.system_id == 'support_replica' else ''))
                    state, has_pii = self._interpreted_state(latest, system_id, data_category)

                    resources[key] = ResourceState(
                        system_id=system_id,
                        resource_id=latest.resource_id,
                        state=state,
                        evidence_id=latest.file_id,
                        captured_at=latest.captured_at,
                        has_pii=has_pii,
                        is_flow=is_flow,
                        is_restore=is_restore,
                        is_retained=is_retained,
                        details=latest.text_content or item.text_content,
                        data_category=data_category,
                        retention_until=(latest.raw_payload.get('retention_until') or
                                         latest.raw_payload.get('retained_until') or ''),
                        observed_at=self._item_time(latest)
                        ,resource_location=latest.resource_location or latest.origin,
                        conflict_evidence_ids=tuple(latest.raw_payload.get("conflict_evidence_ids", ()))
                        ,condition_facts=self._condition_facts(latest)
                    )

        # 1b. Follow explicit source-resource references from a subject-linked
        # record to its dependent copy (for example, a search document copied
        # from an account profile). The relationship comes from the evidence
        # row itself; resource ID similarity is never used as a join key.
        directly_linked_ids = {resource_id for _, resource_id in resources}
        for item in self.ingestor.evidence_items:
            if item.captured_at > audit_at or self._item_time(item) > audit_at:
                continue
            source_id = item.raw_payload.get('source_resource_id')
            if not source_id or str(source_id) not in directly_linked_ids:
                continue
            system_id = 'support_platform' if item.system_id == 'support_replica' else item.system_id
            latest = self._find_latest_evidence_for_resource(
                item.resource_id, audit_at, system_id=system_id
            ) or item
            key = (system_id, latest.resource_id)
            if key in resources and (resources[key].observed_at or resources[key].captured_at) >= self._item_time(latest):
                continue
            category = latest.data_category or item.data_category or ''
            state, has_pii = self._interpreted_state(latest, system_id, category)
            resources[key] = ResourceState(
                system_id=system_id,
                resource_id=latest.resource_id,
                state=state,
                evidence_id=latest.file_id,
                captured_at=latest.captured_at,
                has_pii=has_pii,
                is_flow=(system_id == 'integration_service'),
                is_restore=(system_id == 'backup_service'),
                is_retained=(system_id == 'security_service'),
                details=latest.text_content or item.text_content,
                data_category=category,
                retention_until=(latest.raw_payload.get('retention_until') or
                                 latest.raw_payload.get('retained_until') or ''),
                observed_at=self._item_time(latest),
                resource_location=latest.resource_location or latest.origin,
                conflict_evidence_ids=tuple(latest.raw_payload.get("conflict_evidence_ids", ())),
                condition_facts=self._condition_facts(latest),
            )

        # 2. Check system activities linked to user
        for act in self.ingestor.activities:
            # Data-catalog links are lineage evidence and may predate the
            # deletion request. Other operational activity is request-scoped.
            if (act.event_type != 'LINK_RESOURCE_IDENTITY' and act.event_time < requested_at) or act.event_time > audit_at:
                continue
            det = act.details
            matches_user = self._text_matches_user(det, user, act.event_time)
            if matches_user and act.resource_id:
                sys_id = act.target_system
                res_id = act.resource_id
                key = (sys_id, res_id)
                if key not in resources:
                    # Look up latest evidence item for this resource if any
                    ev_item = self._find_latest_evidence_for_resource(res_id, audit_at, system_id=sys_id)
                    ev_id = ev_item.file_id if ev_item else ""
                    cap = ev_item.captured_at if ev_item else act.event_time
                    # Activity results are claims. Without item level evidence,
                    # retain only actual state-changing resource classes when
                    # separately corroborated by their capture.
                    if not ev_item:
                        continue
                    state = ev_item.state

                    is_flow = (sys_id == 'integration_service')
                    is_restore = (sys_id == 'backup_service')
                    is_retained = (sys_id == 'security_service')

                    resources[key] = ResourceState(
                        system_id=sys_id,
                        resource_id=res_id,
                        state=state,
                        evidence_id=ev_id,
                        captured_at=cap,
                        is_flow=is_flow,
                        is_restore=is_restore,
                        is_retained=is_retained,
                        details=act.details,
                        data_category=ev_item.data_category or '',
                        retention_until=(ev_item.raw_payload.get('retention_until') or
                                         ev_item.raw_payload.get('retained_until') or ''),
                        observed_at=self._item_time(ev_item)
                        ,resource_location=ev_item.resource_location or ev_item.origin,
                        conflict_evidence_ids=tuple(ev_item.raw_payload.get("conflict_evidence_ids", ()))
                        ,condition_facts=self._condition_facts(ev_item)
                    )

        return resources

    @staticmethod
    def _condition_facts(item: EvidenceItem) -> Dict[str, object]:
        facts = dict(item.raw_payload or {})
        # Keep parsed direct identifiers available to policy conditions while
        # retaining whether the source explicitly provided a value.
        for key in ("user_id", "email", "phone", "name", "email_hash"):
            value = getattr(item, key, None)
            if value not in (None, ""):
                facts.setdefault(key, value)
        return facts

    @staticmethod
    def _item_matches_user(item: EvidenceItem, user: UserIdentity) -> bool:
        observed = item.observed_at or item.captured_at
        if item.user_id and item.user_id == user.user_id:
            return True
        if item.email and user.identifier_valid_at("email", item.email, observed):
            return True
        if item.phone and user.identifier_valid_at("phone", item.phone, observed):
            return True
        if item.email_hash and user.identifier_valid_at("email_hash", item.email_hash, observed):
            return True
        return False

    @staticmethod
    def _text_matches_user(text: str, user: UserIdentity, at: str = "") -> bool:
        if not text:
            return False
        lowered = text.lower()
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(user.user_id)}(?![A-Za-z0-9_])", text):
            return True
        if any(email and user.identifier_valid_at("email", email, at) and
               re.search(rf"(?<![A-Za-z0-9._%+-]){re.escape(email)}(?![A-Za-z0-9._%+-])", text, re.I)
               for email in user.all_emails):
            return True
        if any(value and user.identifier_valid_at("email_hash", value, at) and value in lowered
               for value in user.all_hashes):
            return True
        digits = re.sub(r"\D", "", text)
        for phone in user.all_phones:
            phone_digits = re.sub(r"\D", "", phone or "")
            if len(phone_digits) >= 7 and user.identifier_valid_at("phone", phone, at) and phone_digits in digits:
                return True
        return False

    def _find_latest_evidence_for_resource(
        self, res_id: str, audit_at: str, system_id: Optional[str] = None
    ) -> Optional[EvidenceItem]:
        items = self.items_by_res.get(res_id, [])
        valid_items = [
            it for it in items
            if it.captured_at <= audit_at and
            self._item_time(it) <= audit_at and
            (system_id is None or it.system_id == system_id or
             (system_id == 'support_platform' and it.system_id == 'support_replica'))
        ]
        if valid_items:
            # Manifest capture time bounds availability; observed_at orders
            # states. Conflicting equally recent copies become UNKNOWN.
            latest_time = max((x.observed_at or x.captured_at) for x in valid_items)
            latest = [x for x in valid_items if (x.observed_at or x.captured_at) == latest_time]
            states = {x.state for x in latest}
            winner = sorted(latest, key=lambda x: (x.resource_location or "", x.file_id))[0]
            if len(states) > 1:
                conflict_ids = tuple(sorted({x.file_id for x in latest}))
                payload = dict(winner.raw_payload)
                payload["conflict_evidence_ids"] = conflict_ids
                payload["conflicting_locations"] = tuple(sorted({x.resource_location or x.origin for x in latest}))
                return replace(winner, state="UNKNOWN", raw_payload=payload)
            return winner
        return None

    @staticmethod
    def _item_time(item: EvidenceItem) -> str:
        return item.observed_at or item.captured_at

    @staticmethod
    def _time_delta(left: str, right: str) -> float:
        from datetime import datetime
        try:
            return abs((datetime.fromisoformat(left.replace('Z', '+00:00')) -
                        datetime.fromisoformat(right.replace('Z', '+00:00'))).total_seconds())
        except ValueError:
            return float('inf')
