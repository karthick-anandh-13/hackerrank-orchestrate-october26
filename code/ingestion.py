"""Evidence and activity ingestion module."""

import csv
import json
import os
import re
import sqlite3
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


@dataclass
class EvidenceItem:
    file_id: str
    captured_at: str
    origin: str
    file_path: str
    system_id: str
    resource_id: str
    observed_at: Optional[str] = None
    resource_location: Optional[str] = None
    user_id: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    name: Optional[str] = None
    email_hash: Optional[str] = None
    state: Optional[str] = None
    data_category: Optional[str] = None
    raw_payload: Dict[str, Any] = field(default_factory=dict)
    text_content: str = ""

    def __post_init__(self):
        # Keep manifest provenance separate from the logical store location.
        # Table suffixes are added by structured SQL ingestion below.
        if not self.observed_at:
            self.observed_at = self.captured_at
        if not self.resource_location:
            self.resource_location = self.origin or self.file_path


@dataclass
class SystemActivity:
    activity_id: str
    event_time: str
    event_type: str
    source_system: str
    target_system: str
    resource_id: str
    reported_result: str
    details: str


class EvidenceIngestor:
    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self.manifest: Dict[str, dict] = {}
        self.evidence_items: List[EvidenceItem] = []
        self.activities: List[SystemActivity] = []
        self._load_manifest()
        self._load_activities()
        self._load_all_evidence()

    def _load_manifest(self):
        path = os.path.join(self.dataset_dir, 'evidence_files.csv')
        with open(path, mode='r', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                self.manifest[r['file_id']] = r

    def _load_activities(self):
        path = os.path.join(self.dataset_dir, 'system_activity.csv')
        if not os.path.exists(path):
            return
        with open(path, mode='r', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                self.activities.append(SystemActivity(
                    activity_id=r['activity_id'],
                    event_time=r['event_time'],
                    event_type=r['event_type'],
                    source_system=r['source_system'],
                    target_system=r['target_system'],
                    resource_id=r['resource_id'],
                    reported_result=r['reported_result'],
                    details=r['details']
                ))

    def _load_all_evidence(self):
        for fid, finfo in self.manifest.items():
            rel_path = finfo['file_path']
            full_path = os.path.join(self.dataset_dir, rel_path)
            if not os.path.exists(full_path):
                continue
            cap = finfo['captured_at']
            orig = finfo['origin']

            if rel_path.endswith('.sql'):
                self._load_sql_file(fid, cap, orig, rel_path, full_path)
            elif rel_path.endswith('.json'):
                self._load_json_file(fid, cap, orig, rel_path, full_path)
            elif rel_path.endswith('.log'):
                self._load_log_file(fid, cap, orig, rel_path, full_path)
            elif rel_path.endswith('.txt'):
                self._load_txt_file(fid, cap, orig, rel_path, full_path)
            elif rel_path.endswith('.pdf'):
                self._load_pdf_file(fid, cap, orig, rel_path, full_path)
            elif rel_path.endswith('.png'):
                self._load_png_file(fid, cap, orig, rel_path, full_path)

    def _load_sql_file(self, fid: str, cap: str, orig: str, rel_path: str, full_path: str):
        conn = sqlite3.connect(':memory:')
        try:
            with open(full_path, mode='r', encoding='utf-8', errors='ignore') as f:
                conn.executescript(f.read())
            tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]

            if 'customer_profiles' in tables:
                for row in conn.execute("SELECT resource_id, customer_reference, full_name, email, phone, email_hash, account_status FROM customer_profiles"):
                    self.evidence_items.append(EvidenceItem(
                        file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                        system_id='account_service', resource_id=row[0],
                        resource_location=f"{orig}:customer_profiles",
                        user_id=row[1], name=row[2], email=row[3], phone=row[4], email_hash=row[5],
                        # A catalog row proves logical presence regardless of
                        # account status; status is an attribute, not absence.
                        state='PRESENT',
                        data_category='USER_PROFILE'
                    ))

            if 'customer_search_documents' in tables:
                for row in conn.execute("SELECT resource_id, customer_reference, display_name, email, phone, email_hash FROM customer_search_documents"):
                    self.evidence_items.append(EvidenceItem(
                        file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                        system_id='search_service', resource_id=row[0],
                        resource_location=f"{orig}:customer_search_documents",
                        user_id=row[1], name=row[2], email=row[3], phone=row[4], email_hash=row[5],
                        state='PRESENT', data_category='SEARCH_INDEX_ENTRY'
                    ))

            if 'search_documents_primary' in tables:
                for row in conn.execute("SELECT resource_id, display_name, email, source_resource_id, indexed_at FROM search_documents_primary"):
                    self.evidence_items.append(EvidenceItem(
                        file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                        system_id='search_service', resource_id=row[0], name=row[1], email=row[2],
                        resource_location=f"{orig}:search_documents_primary",
                        state='PRESENT', data_category='SEARCH_INDEX_ENTRY',
                        raw_payload={'source_resource_id': row[3], 'indexed_at': row[4]}
                    ))

            if 'customer_analytics_profiles' in tables:
                for row in conn.execute("SELECT resource_id, customer_reference, email, phone, email_hash, audience_cohort FROM customer_analytics_profiles"):
                    has_pii = bool(row[1] or row[2] or row[3] or row[4])
                    self.evidence_items.append(EvidenceItem(
                        file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                        system_id='analytics_platform', resource_id=row[0],
                        resource_location=f"{orig}:customer_analytics_profiles",
                        user_id=row[1], email=row[2], phone=row[3], email_hash=row[4],
                        state='PRESENT' if has_pii else 'ANONYMIZED',
                        data_category='ANALYTICS_PROFILE'
                    ))

            if 'support_records' in tables:
                for row in conn.execute("SELECT resource_id, customer_reference, requester_name, requester_email, requester_phone, message_excerpt FROM support_records"):
                    has_pii = bool(row[2] or row[3] or row[4])
                    self.evidence_items.append(EvidenceItem(
                        file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                        system_id='support_platform', resource_id=row[0],
                        resource_location=f"{orig}:support_records",
                        user_id=row[1], name=row[2], email=row[3], phone=row[4],
                        state='PRESENT' if has_pii else 'REDACTED',
                        data_category='SUPPORT_MESSAGE',
                        raw_payload={'message_excerpt': row[5]}
                    ))

            if 'customer_exports' in tables:
                for row in conn.execute("SELECT resource_id, customer_reference, owner_email, owner_phone, object_key FROM customer_exports"):
                    self.evidence_items.append(EvidenceItem(
                        file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                        system_id='export_service', resource_id=row[0],
                        resource_location=f"{orig}:customer_exports",
                        user_id=row[1], email=row[2], phone=row[3],
                        state='PRESENT', data_category='USER_EXPORT'
                    ))

            if 'connector_subscriptions' in tables:
                for row in conn.execute("SELECT resource_id, customer_reference, customer_email, connector_name, enabled, last_delivery_status FROM connector_subscriptions"):
                    self.evidence_items.append(EvidenceItem(
                        file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                        system_id='integration_service', resource_id=row[0],
                        resource_location=f"{orig}:connector_subscriptions",
                        user_id=row[1], email=row[2],
                        state='ACTIVE' if row[4] == 1 else 'DISABLED',
                        data_category='ACTIVE_DATA_FLOW'
                    ))

            if 'backup_restore_entries' in tables:
                for row in conn.execute("SELECT resource_id, customer_reference, customer_email, archive_key, restore_allowed FROM backup_restore_entries"):
                    self.evidence_items.append(EvidenceItem(
                        file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                        system_id='backup_service', resource_id=row[0],
                        resource_location=f"{orig}:backup_restore_entries",
                        user_id=row[1], email=row[2],
                        state='ACTIVE' if row[4] == 1 else 'BLOCKED',
                        data_category='RESTORE_RISK'
                    ))

            if 'security_audit_records' in tables:
                for row in conn.execute("SELECT resource_id, subject_reference, event_code, retention_until FROM security_audit_records"):
                    self.evidence_items.append(EvidenceItem(
                        file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                        system_id='security_service', resource_id=row[0],
                        resource_location=f"{orig}:security_audit_records",
                        user_id=row[1], state='PRESENT', data_category='SECURITY_AUDIT_LOG',
                        raw_payload={'event_code': row[2], 'retention_until': row[3]}
                    ))

            if 'customer_profiles_failover_replica' in tables:
                for row in conn.execute("SELECT resource_id, user_id, full_name, email, phone, account_status FROM customer_profiles_failover_replica"):
                    self.evidence_items.append(EvidenceItem(
                        file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                        system_id='account_service', resource_id=row[0],
                        resource_location=f"{orig}:customer_profiles_failover_replica",
                        user_id=row[1], name=row[2], email=row[3], phone=row[4],
                        state='PRESENT',
                        data_category='USER_PROFILE'
                    ))

            for tbl in tables:
                if tbl in ('customer_data_primary', 'customer_data_read_replica',
                           'customer_data_replica_eu_west', 'customer_data_replica_ap_south',
                           'customer_data_reporting_replica', 'customer_data_failover_replica'):
                    for row in conn.execute(f"SELECT resource_id, origin_system, record_json FROM {tbl}"):
                        res_id = row[0]
                        orig_sys = self._normalize_system_id(row[1])
                        doc = json.loads(row[2])
                        nested = doc.get('document') if isinstance(doc.get('document'), dict) else {}
                        payload = dict(doc)
                        payload.update(nested)
                        uid = payload.get('user_id') or payload.get('customer_reference') or payload.get('subject_reference')
                        em = payload.get('email') or payload.get('customer_email') or payload.get('requester_email') or payload.get('owner_email')
                        ph = payload.get('phone') or payload.get('requester_phone') or payload.get('owner_phone')
                        nm = payload.get('full_name') or payload.get('display_name') or payload.get('requester_name')
                        hsh = payload.get('email_hash')

                        state = 'PRESENT'
                        if orig_sys == 'analytics_platform':
                            has_pii = bool(em or ph or hsh or (uid and uid != 'null'))
                            state = 'PRESENT' if has_pii else 'ANONYMIZED'
                        elif orig_sys == 'support_platform':
                            has_pii = bool(em or ph or nm)
                            state = 'PRESENT' if has_pii else 'REDACTED'
                        elif orig_sys == 'integration_service':
                            state = 'ACTIVE' if doc.get('enabled') in (1, True, 'true') else 'DISABLED'
                        elif orig_sys == 'backup_service':
                            state = 'ACTIVE' if doc.get('restore_allowed') in (1, True, 'true') else 'BLOCKED'

                        self.evidence_items.append(EvidenceItem(
                            file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                            system_id=orig_sys, resource_id=res_id,
                            resource_location=f"{orig}:{tbl}",
                            user_id=uid, email=em, phone=ph, name=nm, email_hash=hsh,
                            state=state,
                            data_category={
                                'account_service': 'USER_PROFILE',
                                'identity_service': 'ACCOUNT_TOMBSTONE',
                                'search_service': 'SEARCH_INDEX_ENTRY',
                                'support_platform': 'SUPPORT_MESSAGE',
                                'analytics_platform': 'ANALYTICS_PROFILE',
                                'export_service': 'USER_EXPORT',
                                'marketing_platform': 'MARKETING_PROFILE',
                                'integration_service': 'ACTIVE_DATA_FLOW',
                                'backup_service': 'RESTORE_RISK',
                                'security_service': 'SECURITY_AUDIT_LOG',
                                'legal_service': 'LEGAL_HOLD_RECORD',
                            }.get(orig_sys),
                            raw_payload=payload
                        ))
        finally:
            conn.close()

    def _load_json_file(self, fid: str, cap: str, orig: str, rel_path: str, full_path: str):
        with open(full_path, mode='r', encoding='utf-8') as f:
            data = json.load(f)

        if 'service_exports' in data:
            for sys_id, export_dict in data['service_exports'].items():
                for list_name, items in export_dict.items():
                    for it in items:
                        res_id = it.get('resource_id')
                        target_sys = self._normalize_system_id(str(
                            it.get('system') or it.get('target_system') or sys_id
                        ))
                        category = str(it.get('record_type') or it.get('data_category') or '')
                        if category == 'DATA_FLOW':
                            category = 'ACTIVE_DATA_FLOW'
                        elif not category and target_sys == 'legal_service':
                            category = 'LEGAL_HOLD_RECORD'
                        uid = it.get('customer_reference') or it.get('user_id') or it.get('subject_reference')
                        profile = it.get('profile') if isinstance(it.get('profile'), dict) else {}
                        em = (it.get('email') or it.get('customer_email') or it.get('owner_email') or
                              it.get('requester_email') or it.get('query') or profile.get('email'))
                        ph = it.get('phone') or it.get('owner_phone') or it.get('requester_phone') or profile.get('phone')
                        nm = (it.get('display_name') or it.get('requester_name') or it.get('full_name') or
                              profile.get('full_name') or profile.get('name'))
                        hsh = it.get('email_hash') or profile.get('email_hash')
                        uid = uid or profile.get('customer_reference') or profile.get('user_id')
                        identifier = it.get('lookup_value') or it.get('subject_key') or it.get('subject_selector')
                        if identifier:
                            value = str(identifier).strip()
                            if re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
                                em = em or value.lower()
                                if uid == value:
                                    uid = None
                            elif re.fullmatch(r'user_[0-9]+', value):
                                uid = uid or value
                            elif re.fullmatch(r'[a-fA-F0-9]{32,64}', value):
                                hsh = hsh or value.lower()
                            elif re.search(r'\d', value) and len(re.sub(r'\D', '', value)) >= 7:
                                ph = ph or value

                        result = str(it.get('result') or it.get('status') or '').upper()
                        state = 'PRESENT'
                        if result in ('NOT_FOUND', 'MISS', 'ABSENT', 'DELETED'):
                            state = 'ABSENT'
                        elif result == 'ANONYMIZED':
                            state = 'ANONYMIZED'
                        elif result == 'REDACTED':
                            state = 'REDACTED'
                        elif result in ('ACTIVE', 'DISABLED', 'BLOCKED'):
                            state = result
                        elif target_sys == 'account_service':
                            state = 'ABSENT' if it.get('status_code') == 404 else 'PRESENT'
                        elif target_sys == 'search_service':
                            hits = it.get('hits', {})
                            state = 'PRESENT' if (isinstance(hits, dict) and hits.get('total', 0) > 0) else 'ABSENT'
                            if isinstance(hits, dict) and hits.get('documents'):
                                doc = hits['documents'][0]
                                em = em or doc.get('email')
                                uid = uid or doc.get('customer_reference')
                                res_id = doc.get('resource_id') or res_id
                        elif target_sys == 'analytics_platform':
                            has_pii = bool(em or ph or hsh or (uid and uid != 'null'))
                            state = 'PRESENT' if has_pii else 'ANONYMIZED'
                        elif target_sys == 'support_platform':
                            has_pii = bool(em or ph or nm)
                            state = 'PRESENT' if has_pii else 'REDACTED'
                        elif target_sys == 'integration_service':
                            state = 'ACTIVE' if it.get('enabled') in (True, 'true', 1) else 'DISABLED'
                        elif target_sys == 'backup_service':
                            state = 'ACTIVE' if it.get('restore_allowed') in (True, 'true', 1) else 'BLOCKED'

                        self.evidence_items.append(EvidenceItem(
                            file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                            system_id=target_sys, resource_id=res_id,
                            user_id=uid, email=em, phone=ph, name=nm, email_hash=hsh,
                            state=state, raw_payload=it,
                            data_category=(category or ("SUPPORT_ATTACHMENT" if "attachment" in rel_path.lower() and target_sys == "support_platform" else None))
                        ))

        elif 'snapshots' in data:
            for s in data['snapshots']:
                store = s.get('data_store')
                for r in s.get('records', []):
                    res_id = r.get('resource_id')
                    ds = self._normalize_system_id(str(
                        r.get('system') or r.get('target_system') or store or 'unknown_service'
                    ))
                    category = str(r.get('record_type') or r.get('data_category') or '')
                    if category == 'DATA_FLOW':
                        category = 'ACTIVE_DATA_FLOW'
                    if not category:
                        category = {
                            'account_service': 'USER_PROFILE',
                            'identity_service': 'ACCOUNT_TOMBSTONE',
                            'search_service': 'SEARCH_INDEX_ENTRY',
                            'support_platform': 'SUPPORT_MESSAGE',
                            'analytics_platform': 'ANALYTICS_PROFILE',
                            'export_service': 'USER_EXPORT',
                            'integration_service': 'ACTIVE_DATA_FLOW',
                            'backup_service': 'RESTORE_RISK',
                            'security_service': 'SECURITY_AUDIT_LOG',
                            'legal_service': 'LEGAL_HOLD_RECORD',
                        }.get(ds, '')
                    uid = r.get('customer_reference') or r.get('user_id') or r.get('subject_reference')
                    em = r.get('email')
                    ph = r.get('phone')
                    nm = r.get('name') or r.get('full_name') or r.get('display_name')
                    hsh = r.get('email_hash')
                    identifier = r.get('lookup_value') or r.get('subject_key') or r.get('subject_selector')
                    if identifier:
                        value = str(identifier).strip()
                        if re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
                            em = em or value.lower()
                            if uid == value:
                                uid = None
                        elif re.fullmatch(r'user_[0-9]+', value):
                            uid = uid or value
                        elif re.fullmatch(r'[a-fA-F0-9]{32,64}', value):
                            hsh = hsh or value.lower()
                        elif re.search(r'\d', value) and len(re.sub(r'\D', '', value)) >= 7:
                            ph = ph or value

                    result = str(r.get('result') or r.get('status') or '').upper()
                    state = 'PRESENT'
                    if result in ('NOT_FOUND', 'MISS', 'ABSENT', 'DELETED'):
                        state = 'ABSENT'
                    elif result == 'ANONYMIZED':
                        state = 'ANONYMIZED'
                    elif result == 'REDACTED':
                        state = 'REDACTED'
                    elif result in ('ACTIVE', 'DISABLED', 'BLOCKED'):
                        state = result
                    elif ds == 'identity_service':
                        has_pii = bool(em or ph or nm or hsh)
                        state = 'PRESENT' if has_pii else 'REDACTED'
                    elif ds == 'analytics_platform':
                        has_pii = bool(em or ph or hsh or (uid and uid != 'null'))
                        state = 'PRESENT' if has_pii else 'ANONYMIZED'
                    elif ds == 'integration_service':
                        state = 'ACTIVE' if r.get('enabled') in (True, 'true', 1) else 'DISABLED'
                    elif ds == 'backup_service':
                        state = 'ACTIVE' if r.get('restore_allowed') in (True, 'true', 1) else 'BLOCKED'

                    self.evidence_items.append(EvidenceItem(
                        file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                        system_id=ds, resource_id=res_id,
                        user_id=uid, email=em, phone=ph, name=nm, email_hash=hsh,
                        state=state, data_category=category or None, raw_payload=r
                    ))

        elif 'records' in data:
            orig_src = data.get('origin') or data.get('source')
            sys_id = 'security_service' if 'security' in orig_src else (
                'export_service' if 'export' in orig_src else (
                    'integration_service' if 'connector' in orig_src else (
                        'analytics_platform' if 'analytics' in orig_src else orig_src
                    )
                )
            )
            for r in data['records']:
                res_id = r.get('resource_id')
                # Resource lookup exports are captured by several control
                # services, but each row names the actual data system and the
                # identity used for that lookup. Treat the row's target system
                # as authoritative instead of the export producer.
                target_system = (r.get('system') or r.get('target_system') or
                                 r.get('data_store') or sys_id)
                target_system = self._normalize_system_id(str(target_system))
                category = str(r.get('record_type') or r.get('data_category') or '')
                if category == 'DATA_FLOW':
                    category = 'ACTIVE_DATA_FLOW'
                elif not category and target_system == 'legal_service':
                    category = 'LEGAL_HOLD_RECORD'

                identifier = (r.get('lookup_value') or r.get('subject_reference') or
                              r.get('subject_key') or r.get('subject_selector'))
                uid = (r.get('customer_reference') or r.get('user_id') or
                       r.get('subject_reference') or r.get('subject_key'))
                em = (r.get('email') or r.get('customer_email') or r.get('owner_email') or
                      r.get('requester_email'))
                ph = r.get('phone') or r.get('owner_phone') or r.get('requester_phone')
                nm = r.get('requester_name')
                hsh = r.get('email_hash')

                if identifier:
                    value = str(identifier).strip()
                    if re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
                        em = em or value.lower()
                        if uid == value:
                            uid = None
                    elif re.fullmatch(r'user_[0-9]+', value):
                        uid = uid or value
                    elif re.fullmatch(r'[a-fA-F0-9]{32,64}', value):
                        hsh = hsh or value.lower()
                    elif re.search(r'\d', value) and len(re.sub(r'\D', '', value)) >= 7:
                        ph = ph or value

                state = 'PRESENT'
                result = str(r.get('result') or r.get('status') or '').upper()
                if result in ('NOT_FOUND', 'MISS', 'ABSENT', 'DELETED'):
                    state = 'ABSENT'
                elif result == 'ANONYMIZED':
                    state = 'ANONYMIZED'
                elif result == 'REDACTED':
                    state = 'REDACTED'
                elif result in ('ACTIVE', 'DISABLED', 'BLOCKED'):
                    state = result
                elif target_system == 'integration_service':
                    state = 'ACTIVE' if r.get('enabled') in (True, 'true', 1) else 'DISABLED'
                elif target_system == 'backup_service':
                    state = 'ACTIVE' if r.get('restore_allowed') in (True, 'true', 1) else 'BLOCKED'
                elif target_system == 'analytics_platform':
                    has_pii = bool(em or ph or hsh or uid)
                    state = 'PRESENT' if has_pii else 'ANONYMIZED'
                elif target_system == 'support_platform':
                    has_pii = bool(em or ph or nm or uid)
                    state = 'PRESENT' if has_pii else 'REDACTED'

                self.evidence_items.append(EvidenceItem(
                    file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                    system_id=target_system, resource_id=res_id,
                    user_id=uid, email=em, phone=ph, name=nm, email_hash=hsh,
                    state=state, data_category=category or None, raw_payload=r
                ))

    @staticmethod
    def _normalize_system_id(system_id: str) -> str:
        aliases = {
            'search_index_service': 'search_service',
            'support_storage_service': 'support_platform',
            'support_replica': 'support_platform',
            'attachment_preview': 'support_platform',
            'backup_restore_service': 'backup_service',
        }
        return aliases.get(system_id, system_id)

    def _load_log_file(self, fid: str, cap: str, orig: str, rel_path: str, full_path: str):
        traces: Dict[str, List[str]] = {}
        json_traces: Dict[str, List[dict]] = {}
        json_records: List[dict] = []
        standalone_lines: List[str] = []

        with open(full_path, mode='r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                json_start = line.find('{')
                if json_start >= 0:
                    try:
                        obj = json.loads(line[json_start:])
                    except json.JSONDecodeError:
                        obj = None
                    if isinstance(obj, dict):
                        trace_id = obj.get('trace_id')
                        if trace_id:
                            json_traces.setdefault(str(trace_id), []).append(obj)
                        else:
                            json_records.append(obj)
                        continue
                m_tr = re.search(r'trace_id=([a-zA-Z0-9_-]+)', line)
                if m_tr:
                    traces.setdefault(m_tr.group(1), []).append(line.strip())
                else:
                    standalone_lines.append(line.strip())

        # Some observability exports are JSON-lines rather than key=value
        # records. Join start/completion events by trace_id so lookup keys from
        # the start event link the resource and measured result in completion.
        for group in list(json_traces.values()) + [[r] for r in json_records]:
            merged: Dict[str, Any] = {}
            for record in group:
                merged.update({k: v for k, v in record.items() if v not in (None, '', 'null')})
            resource_id = merged.get('resource_id')
            if not resource_id:
                continue
            system_id = str(merged.get('service') or merged.get('logger') or 'unknown_service')
            system_id = self._normalize_system_id(system_id)
            uid_value = (merged.get('user_id') or merged.get('customer_reference') or
                         merged.get('subject_reference') or merged.get('subject_key'))
            uid_match = re.search(r'\buser_[0-9]+\b', str(uid_value or ''))
            uid = uid_match.group(0) if uid_match else None
            email_value = (merged.get('email') or merged.get('customer_email') or
                           merged.get('requester_email') or merged.get('owner_email') or
                           merged.get('lookup_key') or merged.get('subject_key'))
            email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', str(email_value or ''))
            email = email_match.group(0).lower() if email_match else None
            phone = merged.get('phone') or merged.get('customer_phone') or merged.get('requester_phone')
            email_hash = (merged.get('email_hash') or merged.get('correlation_key') or
                          merged.get('lookup_hash'))
            if email_hash:
                hash_match = re.search(r'\b[a-fA-F0-9]{32,64}\b', str(email_hash))
                email_hash = hash_match.group(0).lower() if hash_match else None

            lower_system = system_id.lower()
            event = str(merged.get('event') or '').lower()
            status = str(merged.get('http_status') or merged.get('status_code') or '').lower()
            rows = str(merged.get('rows') or '').lower()
            result = str(merged.get('result') or merged.get('state') or '').lower()
            if 'account' in lower_system:
                state = 'ABSENT' if status == '404' or rows == '0' or 'not_found' in event else 'PRESENT'
                category = 'USER_PROFILE'
                system_id = 'account_service'
            elif 'search' in lower_system:
                state = 'ABSENT' if result in ('miss', 'not_found') or str(merged.get('total_hits')) == '0' else 'PRESENT'
                category = 'SEARCH_INDEX_ENTRY'
                system_id = 'search_service'
            elif 'analytics' in lower_system:
                state = 'PRESENT' if (email or phone or email_hash or uid) else 'ANONYMIZED'
                category = 'ANALYTICS_PROFILE'
                system_id = 'analytics_platform'
            elif 'support' in lower_system:
                state = 'PRESENT' if (email or phone or uid) else 'REDACTED'
                category = 'SUPPORT_MESSAGE'
                system_id = 'support_platform'
            elif 'integration' in lower_system or 'connector' in lower_system:
                enabled = str(merged.get('enabled') or '').lower()
                state = 'ACTIVE' if enabled in ('true', '1', 'yes') else 'DISABLED'
                category = 'ACTIVE_DATA_FLOW'
                system_id = 'integration_service'
            elif 'backup' in lower_system:
                allowed = str(merged.get('restore_allowed') or '').lower()
                eligible = str(merged.get('eligible') or '').lower()
                blocked = str(merged.get('deletion_block') or '').lower()
                state = 'ACTIVE' if allowed in ('true', '1') or (eligible == 'true' and blocked == 'false') else 'BLOCKED'
                category = 'RESTORE_RISK'
                system_id = 'backup_service'
            elif 'security' in lower_system:
                state = 'PRESENT'
                category = 'SECURITY_AUDIT_LOG'
                system_id = 'security_service'
            else:
                state = 'PRESENT'
                category = None

            self.evidence_items.append(EvidenceItem(
                file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                system_id=system_id, resource_id=str(resource_id), user_id=uid,
                email=email, phone=str(phone) if phone else None, email_hash=email_hash,
                state=state, data_category=category,
                observed_at=str(merged.get('timestamp') or merged.get('event_time') or merged.get('observed_at') or cap),
                raw_payload=merged, text_content=' '.join(json.dumps(row, ensure_ascii=False) for row in group)
            ))

        for tr, lines in traces.items():
            combined = ' '.join(lines)
            raw_payload = {}
            for match in re.finditer(
                r'''(?:^|\s)([A-Za-z_]\w*)=(?:"([^"]*)"|'([^']*)'|(\S+))''',
                combined,
            ):
                raw_payload[match.group(1)] = next(
                    value for value in match.groups()[1:] if value is not None
                )
            m_res = re.search(r'resource_id=([a-zA-Z0-9_-]+)', combined)
            m_sys = re.search(r'service=([a-zA-Z0-9_-]+)', combined)
            if not m_sys:
                m_sys = re.search(r'\bnode-\d+\s+([a-zA-Z0-9_-]+_(?:service|platform|replica))\s+tr-', combined)
            if not m_sys:
                m_sys = re.search(r'\[([a-zA-Z0-9_-]+_(?:service|platform|replica))\]', combined)
            if not m_sys:
                m_sys = re.search(r'\|\s*([a-zA-Z0-9_-]+_(?:service|platform|replica))\s*\|', combined)
            m_em = re.findall(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', combined)
            m_uid = re.search(r'\b(user_[0-9]+)\b', combined)
            m_ph = re.search(r'(?:\+|%2B)[0-9\s-]{7,}', combined)
            m_hash = re.search(r'(?:correlation_key|email_hash)=\"?([a-fA-F0-9]{32,64})', combined)

            m_source = re.search(r'\bsource=([a-zA-Z0-9_-]+)', combined)
            res_id = m_res.group(1) if m_res else None
            sys_id = m_sys.group(1) if m_sys else None
            sys_id = self._normalize_system_id(sys_id) if sys_id else None
            uid = m_uid.group(1) if m_uid else None
            em = m_em[0] if m_em else None
            ph = m_ph.group(0) if m_ph else None

            if not res_id:
                continue

            state = 'PRESENT'
            if sys_id == 'account_service':
                state = 'ABSENT' if 'http_status=404' in combined or 'rows=0' in combined else 'PRESENT'
            elif sys_id == 'search_service':
                state = 'PRESENT' if 'result=hit' in combined or 'total_hits=1' in combined else 'ABSENT'
            elif sys_id == 'analytics_platform':
                has_pii = bool(em or ph or uid or m_hash)
                state = 'PRESENT' if has_pii else 'ANONYMIZED'
            elif sys_id == 'support_platform':
                has_pii = bool(em or ph or 'message_pii_scan' in combined or 'attachment_pii_scan' in combined)
                state = 'PRESENT' if has_pii else 'REDACTED'
            elif sys_id == 'integration_service':
                state = 'ACTIVE' if 'enabled=true' in combined else 'DISABLED'
            elif sys_id == 'backup_service':
                state = 'ACTIVE' if ('restore_allowed=true' in combined.lower() or 'restore_allowed: true' in combined.lower()
                                     or ('eligible=true' in combined.lower() and 'deletion_block=false' in combined.lower())) else 'BLOCKED'

            observed_times = [
                match.group(1)
                for line in lines
                for match in [re.match(
                    r'\s*(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)', line
                )]
                if match
            ]
            self.evidence_items.append(EvidenceItem(
                file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                system_id=sys_id or 'unknown_service', resource_id=res_id,
                user_id=uid, email=em, phone=ph,
                email_hash=m_hash.group(1).lower() if m_hash else None,
                observed_at=max(observed_times, default=cap),
                state=state, text_content=combined,
                raw_payload=raw_payload,
                # A contact-index lookup is an identifier record, not a shared
                # support conversation subject to the default redaction rule.
                data_category=(
                    'SECONDARY_IDENTIFIER'
                    if sys_id == 'support_platform' and m_source and
                    m_source.group(1).lower().endswith('contact_index')
                    else 'SECONDARY_IDENTIFIER'
                    if m_hash and sys_id == 'analytics_platform'
                    else None
                )
            ))

        for line in standalone_lines:
            if 'resource_id=' in line or 'resource_id="' in line:
                m_res = re.search(r'resource_id=[\"\']?([a-zA-Z0-9_-]+)', line)
                m_sys = re.search(r'service=[\"\']?([a-zA-Z0-9_-]+)', line)
                if not m_sys:
                    m_sys = re.search(r'\bnode-\d+\s+([a-zA-Z0-9_-]+_(?:service|platform|replica))\s+tr-', line)
                if not m_sys:
                    m_sys = re.search(r'\[([a-zA-Z0-9_-]+_(?:service|platform|replica))\]', line)
                if not m_sys:
                    m_sys = re.search(r'\|\s*([a-zA-Z0-9_-]+_(?:service|platform|replica))\s*\|', line)
                m_target = re.search(r'\b(?:system|target_system)=[\"\']?([a-zA-Z0-9_-]+)', line)
                m_em = re.findall(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line)
                m_uid = re.search(r'\b(user_[0-9]+)\b', line)
                m_ph = re.search(r'(?:\+|%2B)[0-9\s()-]{7,}', line)
                m_hash = re.search(r'(?:correlation_key|email_hash|lookup_hash)=[\"\']?([a-fA-F0-9]{32,64})', line)
                m_result = re.search(r'\bresult=[\"\']?([a-zA-Z_-]+)', line)
                m_category = re.search(r'\brecord_type=[\"\']?([a-zA-Z_-]+)', line)

                res_id = m_res.group(1) if m_res else None
                sys_id = m_sys.group(1) if m_sys else None
                sys_id = self._normalize_system_id(sys_id) if sys_id else None
                if m_target:
                    sys_id = self._normalize_system_id(m_target.group(1))
                uid = m_uid.group(1) if m_uid else None
                em = m_em[0] if m_em else None
                ph = m_ph.group(0) if m_ph else None
                email_hash = m_hash.group(1).lower() if m_hash else None

                if not res_id:
                    continue

                state = 'PRESENT'
                result_value = m_result.group(1).upper() if m_result else ''
                if result_value in ('NOT_FOUND', 'MISS', 'ABSENT', 'DELETED'):
                    state = 'ABSENT'
                elif result_value in ('ANONYMIZED', 'REDACTED', 'ACTIVE', 'DISABLED', 'BLOCKED'):
                    state = result_value
                elif sys_id == 'account_service':
                    state = 'ABSENT' if 'http_status=404' in line or 'rows=0' in line else 'PRESENT'
                elif sys_id == 'search_service':
                    state = 'PRESENT' if 'result=hit' in line or 'total_hits=1' in line else 'ABSENT'
                elif sys_id == 'analytics_platform':
                    has_pii = bool(em or uid)
                    state = 'PRESENT' if has_pii else 'ANONYMIZED'
                elif sys_id == 'support_platform':
                    has_pii = bool(em)
                    state = 'PRESENT' if has_pii else 'REDACTED'
                elif sys_id == 'integration_service':
                    state = 'ACTIVE' if 'enabled=true' in line else 'DISABLED'
                elif sys_id == 'backup_service':
                    state = 'ACTIVE' if 'restore_allowed=true' in line.lower() or ('eligible=true' in line.lower() and 'deletion_block=false' in line.lower()) else 'BLOCKED'

                self.evidence_items.append(EvidenceItem(
                    file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                    system_id=sys_id or 'unknown_service', resource_id=res_id,
                    user_id=uid, email=em, phone=ph, email_hash=email_hash,
                    observed_at=(re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?', line).group(0)
                                 if re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?', line) else cap),
                    state=state, text_content=line,
                    data_category=(m_category.group(1) if m_category else {
                        'account_service': 'USER_PROFILE',
                        'identity_service': 'ACCOUNT_TOMBSTONE',
                        'search_service': 'SEARCH_INDEX_ENTRY',
                        'support_platform': 'SUPPORT_MESSAGE',
                        'analytics_platform': 'ANALYTICS_PROFILE',
                        'export_service': 'USER_EXPORT',
                        'integration_service': 'ACTIVE_DATA_FLOW',
                        'backup_service': 'RESTORE_RISK',
                        'security_service': 'SECURITY_AUDIT_LOG',
                        'legal_service': 'LEGAL_HOLD_RECORD',
                    }.get(sys_id))
                ))

    def _load_txt_file(self, fid: str, cap: str, orig: str, rel_path: str, full_path: str):
        with open(full_path, mode='r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if '|' in line:
                    parts = [x.strip() for x in line.split('|')]
                    if len(parts) >= 3:
                        sys_id = parts[1]
                        sys_id = self._normalize_system_id(sys_id)
                        res_id = parts[2]
                        if sys_id and res_id and ('_' in res_id):
                            line_text = line.strip()
                            m_em = re.findall(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line_text)
                            m_uid = re.search(r'\b(user_[0-9]+)\b', line_text)
                            em = m_em[0] if m_em else None
                            uid = m_uid.group(1) if m_uid else None

                            state_text = parts[4].upper() if len(parts) > 4 else ''
                            category = parts[3].upper() if len(parts) > 4 else None
                            state = 'PRESENT'
                            if state_text in ('NOT_FOUND', 'ABSENT', 'DELETED') or 'ABSENT' in line_text or 'deleted' in line_text.lower():
                                state = 'ABSENT'
                            elif state_text == 'ACTIVE':
                                state = 'ACTIVE'
                            elif state_text == 'BLOCKED':
                                state = 'BLOCKED'
                            elif state_text == 'DISABLED':
                                state = 'DISABLED'
                            elif state_text == 'ANONYMIZED':
                                state = 'ANONYMIZED'
                            elif state_text == 'REDACTED' or 'REDACTED' in line_text or 'redacted' in line_text.lower():
                                state = 'REDACTED'
                            elif 'ANONYMIZED' in line_text or 'anonymized' in line_text.lower():
                                state = 'ANONYMIZED'
                            elif 'BLOCKED' in line_text or 'blocked' in line_text.lower():
                                state = 'BLOCKED'
                            elif 'DISABLED' in line_text or 'disabled' in line_text.lower():
                                state = 'DISABLED'

                            self.evidence_items.append(EvidenceItem(
                                file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                                system_id=sys_id, resource_id=res_id,
                                user_id=uid, email=em, state=state, text_content=line_text,
                                data_category=category
                            ))

    def _load_pdf_file(self, fid: str, cap: str, orig: str, rel_path: str, full_path: str):
        try:
            txt = subprocess.run(['pdftotext', full_path, '-'], capture_output=True, text=True, check=True).stdout
            m_res = re.findall(r'(account_[0-9]+|search_[0-9]+|support_[0-9]+|audit_record_[0-9]+|data_flow_[0-9]+|backup_[0-9]+|export_[0-9]+|analytics_[0-9]+)', txt)
            m_uid = re.findall(r'\b(user_[0-9]+)\b', txt)
            m_em = re.findall(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', txt)
            for res in m_res:
                sys_id = ('support_platform' if res.startswith('support_') else
                          'export_service' if res.startswith('export_') else
                          'account_service' if res.startswith('account_') else
                          'search_service' if res.startswith('search_') else
                          'analytics_platform' if res.startswith('analytics_') else
                          'integration_service' if res.startswith('data_flow_') else
                          'backup_service' if res.startswith('backup_') else 'security_service')
                self.evidence_items.append(EvidenceItem(
                    file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                    system_id=sys_id, resource_id=res,
                    user_id=m_uid[0] if m_uid else None,
                    email=m_em[0] if m_em else None,
                    state='PRESENT', text_content=txt[:300],
                    data_category=("SUPPORT_ATTACHMENT" if "attachment" in rel_path.lower() and sys_id == "support_platform" else None)
                ))
        except Exception:
            pass

    def _load_png_file(self, fid: str, cap: str, orig: str, rel_path: str, full_path: str):
        """Extract resource identifiers and visible state from screenshots."""
        try:
            txt = subprocess.run(['tesseract', full_path, 'stdout'], capture_output=True,
                                 text=True, check=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            return
        patterns = r'(account_[0-9]+|search_[0-9]+|support_[0-9]+|audit_record_[0-9]+|data_flow_[0-9]+|backup_[0-9]+|export_[0-9]+|analytics_[0-9]+|tombstone_[0-9]+)'
        resources = list(dict.fromkeys(re.findall(patterns, txt, re.IGNORECASE)))
        emails = re.findall(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', txt)
        uids = re.findall(r'\buser_[0-9]+\b', txt)
        phones = re.findall(r'\+[0-9][0-9 ()-]{7,}[0-9]', txt)
        for resource_id in resources:
            prefix = resource_id.split('_', 1)[0].lower()
            system = {'account': 'account_service', 'search': 'search_service', 'support': 'support_platform',
                      'analytics': 'analytics_platform', 'data': 'integration_service', 'backup': 'backup_service',
                      'export': 'export_service', 'audit': 'security_service', 'tombstone': 'identity_service'}.get(prefix, 'unknown_service')
            state = 'PRESENT'
            if system == 'account_service' and re.search(r'404|rows\s*[:=]\s*0|not found|absent', txt, re.IGNORECASE):
                state = 'ABSENT'
            elif system == 'integration_service':
                state = 'ACTIVE' if re.search(r'enabled\s*[:=]\s*true|active', txt, re.IGNORECASE) else 'DISABLED'
            elif system == 'backup_service':
                state = 'ACTIVE' if re.search(r'restore_allowed\s*[:=]\s*true|restore enabled', txt, re.IGNORECASE) else 'BLOCKED'
            elif system == 'analytics_platform' and not (emails or phones or uids):
                state = 'ANONYMIZED'
            elif system == 'support_platform' and not (emails or phones):
                state = 'REDACTED'
            category = None
            if system == 'support_platform' and ('attachment' in rel_path.lower() or 'attachment' in txt.lower()):
                category = 'SUPPORT_ATTACHMENT'
            if system == 'identity_service':
                state = 'PRESENT' if emails or phones else 'REDACTED'
                category = 'ACCOUNT_TOMBSTONE'
            self.evidence_items.append(EvidenceItem(
                file_id=fid, captured_at=cap, origin=orig, file_path=rel_path,
                system_id=system, resource_id=resource_id, user_id=uids[0] if uids else None,
                email=emails[0] if emails else None, phone=phones[0] if phones else None,
                state=state, data_category=category, text_content=txt[:1000]
            ))
