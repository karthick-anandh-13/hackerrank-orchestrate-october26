"""Identity resolution and request classification module."""

import csv
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set


@dataclass
class UserIdentity:
    user_id: str
    name: str
    email: str
    phone: str
    email_hash: str
    all_names: Set[str] = field(default_factory=set)
    all_emails: Set[str] = field(default_factory=set)
    all_phones: Set[str] = field(default_factory=set)
    all_hashes: Set[str] = field(default_factory=set)
    all_identifiers: Dict[str, Set[str]] = field(default_factory=dict)
    identifier_windows: Dict[str, Dict[str, List[tuple]]] = field(default_factory=dict)
    identifier_owner_counts: Dict[str, Dict[str, int]] = field(default_factory=dict)
    identifier_claim_windows: Dict[str, Dict[str, Dict[str, List[tuple]]]] = field(default_factory=dict)

    def identifier_valid_at(self, field_name: str, value: str, at: str = "") -> bool:
        normalized = IdentityResolver._normalize(field_name, value)
        windows = self.identifier_windows.get(field_name, {}).get(normalized, [])
        if not windows:
            return False
        owner_count = self.identifier_owner_counts.get(field_name, {}).get(normalized, 1)
        # A uniquely owned historical identifier remains a valid forensic link
        # after it stops being current. Temporal gating is needed when an
        # identifier is known to have multiple owners.
        if owner_count == 1:
            return True
        moment = IdentityResolver._parse_time(at)
        if moment is None:
            return False
        claims = self.identifier_claim_windows.get(field_name, {}).get(normalized, {})
        active_owners = {
            owner for owner, owner_windows in claims.items()
            if any((start is None or start <= moment) and (end is None or moment < end)
                   for start, end in owner_windows)
        }
        return active_owners == {self.user_id}

    def matches_any_identifier(self, text: str) -> bool:
        if not text:
            return False
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(self.user_id)}(?![A-Za-z0-9_])", text):
            return True
        for em in self.all_emails:
            if em and re.search(rf"(?<![A-Za-z0-9._%+-]){re.escape(em)}(?![A-Za-z0-9._%+-])", text, re.I):
                return True
        for ph in self.all_phones:
            digits = re.sub(r"\D", "", ph or "")
            if len(digits) >= 7 and digits in re.sub(r"\D", "", text):
                return True
        for h in self.all_hashes:
            if h and h in text.lower():
                return True
        return False


class IdentityResolver:
    NON_DELETION_PATTERNS = [
        re.compile(r'download\s+my\s+account\s+information', re.IGNORECASE),
        re.compile(r'copy\s+of\s+last\s+year', re.IGNORECASE),
        re.compile(r'copy\s+of\s+the\s+information', re.IGNORECASE),
        re.compile(r'misspelled\s+on\s+the\s+account', re.IGNORECASE),
        re.compile(r'change\s+the\s+email\s+address', re.IGNORECASE),
        re.compile(r'mobile\s+number.*out\s+of\s+date', re.IGNORECASE),
        re.compile(r'resetting\s+the\s+login', re.IGNORECASE),
        re.compile(r'stop\s+the\s+promotional\s+emails', re.IGNORECASE),
        re.compile(r'remove\s+me\s+from\s+marketing\s+lists\s+only', re.IGNORECASE),
        re.compile(r'what\s+personal\s+information\s+you\s+hold', re.IGNORECASE),
        re.compile(r'do\s+not\s+close', re.IGNORECASE),
        re.compile(r'leave\s+the\s+account', re.IGNORECASE),
        re.compile(r'leave\s+my', re.IGNORECASE),
        re.compile(r'keep\s+the\s+account', re.IGNORECASE),
        re.compile(r'continue\s+using\s+the\s+service', re.IGNORECASE),
        re.compile(r'not\s+asking\s+for\s+deletion', re.IGNORECASE),
        re.compile(r'not\s+a\s+request\s+to\s+erase', re.IGNORECASE),
        re.compile(r'\bdo\s+not\s+(delete|erase|remove)\b', re.IGNORECASE),
        re.compile(r'\bnot\s+asking\s+to\s+(delete|erase|remove)\b', re.IGNORECASE),
        re.compile(r'\bno\s+(deletion|erasure)\b', re.IGNORECASE),
        re.compile(r'without\s+removing', re.IGNORECASE),
        re.compile(r'don\'t\s+delete', re.IGNORECASE),
        re.compile(r'don\'t\s+(erase|remove)', re.IGNORECASE),
    ]

    def __init__(self, identities_path: str, audit_log_path: str):
        self.users_by_id: Dict[str, UserIdentity] = {}
        self.email_to_uid: Dict[str, Set[str]] = {}
        self.identifier_owners: Dict[str, Dict[str, Set[str]]] = {}
        self.audit_events: Dict[str, Dict[str, List[dict]]] = {}
        self.identity_conflicts: Dict[tuple, Set[str]] = {}
        self._load_identities(identities_path)
        self._load_audit_log(audit_log_path)
        self._build_identifier_index()

    def _load_identities(self, path: str):
        with open(path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row['user_id']
                em = row['email'].strip().lower()
                ph = row['phone'].strip()
                nm = row['name'].strip()
                hsh = row['email_hash'].strip().lower()

                user = UserIdentity(
                    user_id=uid,
                    name=nm,
                    email=em,
                    phone=ph,
                    email_hash=hsh,
                    all_names={nm},
                    all_emails={em},
                    all_phones={ph},
                    all_hashes={hsh},
                    all_identifiers={
                        "name": {nm}, "email": {em}, "phone": {self._normalize("phone", ph)},
                        "email_hash": {hsh}, "user_id": {uid},
                    },
                )
                self.users_by_id[uid] = user

    def _load_audit_log(self, path: str):
        with open(path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                uid = row['user_id']
                if uid not in self.users_by_id:
                    continue
                user = self.users_by_id[uid]
                fn = row['field_name']
                old_v = row['old_value'].strip()
                new_v = row['new_value'].strip()
                event = dict(row)
                self.audit_events.setdefault(uid, {}).setdefault(fn, []).append(event)

                if fn == 'email':
                    if old_v:
                        em_old = old_v.lower()
                        user.all_emails.add(em_old)
                    if new_v:
                        em_new = new_v.lower()
                        user.all_emails.add(em_new)
                elif fn == 'phone':
                    if old_v:
                        user.all_phones.add(old_v)
                    if new_v:
                        user.all_phones.add(new_v)
                elif fn == 'name':
                    if old_v:
                        user.all_names.add(old_v)
                    if new_v:
                        user.all_names.add(new_v)
                elif fn == 'email_hash':
                    if old_v:
                        user.all_hashes.add(old_v.lower())
                    if new_v:
                        user.all_hashes.add(new_v.lower())

    @staticmethod
    def _normalize(field_name: str, value: str) -> str:
        value = (value or "").strip()
        if field_name in ("email", "email_hash"):
            return value.casefold()
        if field_name == "phone":
            return re.sub(r"\D", "", value)
        return value

    @staticmethod
    def _parse_time(value: str):
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except (TypeError, ValueError):
            return None

    def _build_identifier_index(self) -> None:
        """Index unique and time-bounded identity claims without last-row-wins."""
        self.identifier_owners = {}
        for uid, user in self.users_by_id.items():
            raw_values = {
                "user_id": {uid}, "name": user.all_names, "email": user.all_emails,
                "phone": user.all_phones, "email_hash": user.all_hashes,
            }
            user.all_identifiers = {}
            user.identifier_windows = {}
            for field_name, values in raw_values.items():
                normalized = {self._normalize(field_name, value) for value in values if value}
                normalized.discard("")
                user.all_identifiers[field_name] = normalized
                for value in normalized:
                    self.identifier_owners.setdefault(field_name, {}).setdefault(value, set()).add(uid)
                if field_name == "user_id":
                    user.identifier_windows[field_name] = {uid: [(None, None)]}
                    continue
                events = sorted(
                    self.audit_events.get(uid, {}).get(field_name, []),
                    key=lambda e: self._parse_time(e.get("event_time", "")) or datetime.min.replace(tzinfo=timezone.utc),
                )
                current_value = self._normalize(field_name, getattr(user, {
                    "name": "name", "email": "email", "phone": "phone", "email_hash": "email_hash"
                }[field_name]))
                ranges: Dict[str, List[tuple]] = {}
                if not events:
                    if current_value:
                        ranges[current_value] = [(None, None)]
                else:
                    first_old = self._normalize(field_name, events[0].get("old_value", ""))
                    active = first_old or current_value
                    start = None if first_old else (self._parse_time(events[0].get("event_time", "")))
                    for event in events:
                        at = self._parse_time(event.get("event_time", ""))
                        old = self._normalize(field_name, event.get("old_value", ""))
                        new = self._normalize(field_name, event.get("new_value", ""))
                        if active and at and at > (start or datetime.min.replace(tzinfo=timezone.utc)):
                            ranges.setdefault(active, []).append((start, at))
                        active, start = new, at
                    if active:
                        if active == current_value:
                            ranges.setdefault(active, []).append((start, None))
                        else:
                            # A snapshot/audit disagreement is represented as two claims;
                            # a caller must not silently choose whichever row was loaded last.
                            ranges.setdefault(active, []).append((start, None))
                            if current_value:
                                ranges.setdefault(current_value, []).append((None, None))
                user.identifier_windows[field_name] = ranges

        # Record genuine overlapping ownership claims; ordinary historical
        # changes are not conflicts when their validity windows do not overlap.
        self.identity_conflicts = {}
        for field_name, value_map in self.identifier_owners.items():
            for value, owners in value_map.items():
                if len(owners) < 2:
                    continue
                overlapping = set()
                owner_list = sorted(owners)
                for i, first_uid in enumerate(owner_list):
                    first_ranges = self.users_by_id[first_uid].identifier_windows.get(field_name, {}).get(value, [])
                    for second_uid in owner_list[i + 1:]:
                        second_ranges = self.users_by_id[second_uid].identifier_windows.get(field_name, {}).get(value, [])
                        if self._windows_overlap(first_ranges, second_ranges):
                            overlapping.update((first_uid, second_uid))
                if overlapping:
                    self.identity_conflicts[(field_name, value)] = overlapping

        self.email_to_uid = {
            value: set(owners)
            for value, owners in self.identifier_owners.get("email", {}).items()
        }
        for user in self.users_by_id.values():
            user.identifier_owner_counts = {
                field_name: {value: len(owners) for value, owners in values.items()}
                for field_name, values in self.identifier_owners.items()
                for value in user.all_identifiers.get(field_name, set())
            }
            user.identifier_claim_windows = {
                field_name: {
                    value: {
                        owner: self.users_by_id[owner].identifier_windows.get(field_name, {}).get(value, [])
                        for owner in owners
                    }
                    for value, owners in values.items()
                    if value in user.all_identifiers.get(field_name, set())
                }
                for field_name, values in self.identifier_owners.items()
            }

    @staticmethod
    def _windows_overlap(left: List[tuple], right: List[tuple]) -> bool:
        min_time = datetime.min.replace(tzinfo=timezone.utc)
        max_time = datetime.max.replace(tzinfo=timezone.utc)
        for left_start, left_end in left:
            a0, a1 = left_start or min_time, left_end or max_time
            for right_start, right_end in right:
                b0, b1 = right_start or min_time, right_end or max_time
                if max(a0, b0) < min(a1, b1):
                    return True
        return False

    def _owners_at(self, field_name: str, value: str, at: str = "") -> Set[str]:
        normalized = self._normalize(field_name, value)
        owners = self.identifier_owners.get(field_name, {}).get(normalized, set())
        if len(owners) <= 1:
            return set(owners)
        moment = self._parse_time(at)
        if moment is None:
            return set(owners)
        active = set()
        for uid in owners:
            windows = self.users_by_id[uid].identifier_windows.get(field_name, {}).get(normalized, [])
            for start, end in windows:
                if (start is None or start <= moment) and (end is None or moment < end):
                    active.add(uid)
                    break
        return active

    def matches_identifier(self, user: UserIdentity, field_name: str, value: str, at: str = "") -> bool:
        if field_name == "user_id":
            return value == user.user_id
        owners = self._owners_at(field_name, value, at)
        return owners == {user.user_id}

    def resolve_by_email(self, email: str, at: str = "") -> Optional[UserIdentity]:
        if not email:
            return None
        owners = self._owners_at("email", email, at)
        return self.users_by_id[next(iter(owners))] if len(owners) == 1 else None

    def resolve_by_user_id(self, user_id: str) -> Optional[UserIdentity]:
        return self.users_by_id.get(user_id)

    def resolve_by_any_identifier(self, text: str, at: str = "") -> Optional[UserIdentity]:
        """Resolve a user by any identifier string (email, phone, hash, name, or user_id).
        Returns the first matching UserIdentity or None if no match.
        """
        if not text:
            return None
        clean = text.strip()
        if clean in self.users_by_id:
            return self.users_by_id[clean]
        if "@" in clean:
            return self.resolve_by_email(clean, at)
        if re.fullmatch(r"[a-fA-F0-9]{32,64}", clean):
            owners = self._owners_at("email_hash", clean, at)
            return self.users_by_id[next(iter(owners))] if len(owners) == 1 else None
        digits = re.sub(r"\D", "", clean)
        if len(digits) >= 7:
            owners = self._owners_at("phone", clean, at)
            return self.users_by_id[next(iter(owners))] if len(owners) == 1 else None
        owners = self._owners_at("name", clean, at)
        return self.users_by_id[next(iter(owners))] if len(owners) == 1 else None

    @classmethod
    def is_deletion_authorized(cls, request_text: str) -> bool:
        if not request_text:
            return False
        clean_text = request_text.strip()
        for pat in cls.NON_DELETION_PATTERNS:
            if pat.search(clean_text):
                return False
        # Require an explicit deletion/erasure intent. Treating every message
        # without a known opt-out phrase as authorization is unsafe.
        deletion_intent = re.compile(
            r"\b(delete|deleted|deleting|deletion|erase|erased|erasing|erasure|remove|removal|close|closure|cancel|destroy|wipe|forget|right to be forgotten)\b"
            r"|\b(eliminar|elimine|borrar|suprimir|supprimer|effacer|löschen|loeschen|entfernen|excluir|exclusão|exclusao|apagar)\b"
            r"|削除|消去|抹消|삭제"
            r"|\b(account|profile|personal data|personal information|my data|my records|search result|cuenta|datos personales|compte|données personnelles|konto|personenbezogene daten|conta)\b|アカウント|個人情報|계정|개인정보",
            re.IGNORECASE,
        )
        if not deletion_intent.search(clean_text):
            return False
        # Non-deletion action requests can mention data or deletion incidentally.
        action_only = re.compile(
            r"\b(access|copy|export|download|correct|correction|update|change|reset|opt.?out|unsubscribe|marketing)\b",
            re.IGNORECASE,
        )
        explicit_delete = re.compile(
            r"\b(delete|deleted|deleting|deletion|erase|erased|erasure|remove|removal|close|closure|cancel|destroy|wipe|forget|eliminar|borrar|suprimir|supprimer|effacer|löschen|loeschen|entfernen|excluir|exclusão|exclusao|apagar)\b.{0,80}\b(account|profile|data|information|records|search result|cuenta|datos|compte|données|konto|conta)\b"
            r"|\b(account|profile|data|information|records|search result|cuenta|datos|compte|données|konto|conta)\b.{0,80}\b(delete|deleted|deleting|deletion|erase|erased|erasure|remove|removal|close|closure|cancel|destroy|wipe|forget|eliminar|borrar|suprimir|supprimer|effacer|löschen|loeschen|entfernen|excluir|exclusão|exclusao|apagar)\b"
            r"|削除.{0,40}(アカウント|個人情報)|アカウント.{0,40}削除|삭제.{0,40}(계정|개인정보)|계정.{0,40}삭제",
            re.IGNORECASE,
        )
        return not action_only.search(clean_text) or bool(explicit_delete.search(clean_text))
