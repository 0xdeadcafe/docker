#!/usr/bin/env python3
"""Bounded shadow reducer for native Vectra commonness Notes."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable

from pycti import OpenCTIApiClient

SOURCE_LABELS = {
    "vectra-metadata:common-domain", "vectra-metadata:common-ip",
    "vectra-metadata:shared-auth-ip", "vectra-metadata:commonness-conflict",
}
HERD_LABEL = "vectra-metadata:herd-common"
HERD_COLOR = "#5e35b1"
SOURCE_PREFIX = "vectra-commonness:"
REVIEW_PREFIX = "vectra-commonness-review:"
QUERY_VERSION = "x39.1-commonness-v1"
NOTE_NAMESPACE = uuid.UUID("902f4dc2-e808-4c8a-bfbb-cb2a40be2053")
SOURCE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
SIGNALS = {"Domain-Name": {"dns", "sni", "http"}, "IPv4-Addr": {"m365", "isession"}}


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes"}


def _page_parts(page: object) -> tuple[list[dict], dict]:
    if isinstance(page, dict):
        return list(page.get("entities") or page.get("data") or []), dict(page.get("pagination") or page.get("pageInfo") or {})
    return list(page or []), {}


def _refs(note: dict) -> list[str]:
    objects = note.get("objects") or {}
    edges = objects.get("edges", []) if isinstance(objects, dict) else objects
    return [str((edge.get("node") or edge).get("id")) for edge in edges
            if isinstance(edge, dict) and (edge.get("node") or edge).get("id")]


def _parse_time(value: object) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def _labels(entity: dict) -> set[str]:
    return {str(label.get("value") or "").lower() for label in entity.get("objectLabel") or []}


def _conflict(entity: dict) -> bool:
    labels = _labels(entity)
    threat = any(any(word in label for word in ("malicious", "malware", "sinkhol", "threat")) for label in labels)
    return int(entity.get("x_opencti_score") or 0) >= 70 or threat or bool((entity.get("indicators") or {}).get("edges"))


@dataclass(frozen=True)
class Vote:
    source_id: str
    signals: frozenset[str]
    updated_at: datetime


@dataclass(frozen=True)
class ReviewPlan:
    observable_id: str
    observable_type: str
    source_count: int
    signals: tuple[str, ...]
    oldest: datetime
    newest: datetime
    conflict: bool

    @property
    def classification(self) -> str:
        return "herd-common" if self.source_count >= 2 else "source-local"

    @property
    def explanation(self) -> str:
        text = (f"Commonness evidence from {self.source_count} distinct Vectra Metadata "
                f"source{'s' if self.source_count != 1 else ''} across {', '.join(self.signals)}; "
                "commonness indicates low hunting discrimination, not benignness.")
        return text + (" Authoritative threat context coexists." if self.conflict else "")


def reduce_evidence(observables: list[dict], notes: list[dict], *, now: datetime,
                    max_age: timedelta) -> tuple[dict[str, ReviewPlan], dict[str, int]]:
    entities = {str(item["id"]): item for item in observables}
    votes: dict[str, dict[str, Vote]] = defaultdict(dict)
    metrics = defaultdict(int)
    for note in notes:
        abstract = str(note.get("attribute_abstract") or note.get("abstract") or "")
        if not abstract.startswith(SOURCE_PREFIX) or abstract.startswith(REVIEW_PREFIX):
            continue
        metrics["source_records"] += 1
        refs = _refs(note)
        try:
            payload = json.loads(note.get("content") or "")
        except (TypeError, ValueError):
            metrics["malformed"] += 1
            continue
        if not isinstance(payload, dict):
            metrics["malformed"] += 1
            continue
        raw_signals = payload.get("qualifying_signals")
        if not isinstance(raw_signals, list) or any(not isinstance(signal, str) for signal in raw_signals):
            metrics["malformed"] += 1
            continue
        source_id = str(payload.get("source_id") or "")
        object_id = refs[0] if len(refs) == 1 else ""
        entity = entities.get(object_id)
        observable_type = str(payload.get("observable_type") or "")
        signals = set(raw_signals)
        updated_at = _parse_time(payload.get("updated_at"))
        valid = (
            payload.get("schema_version") == 1
            and payload.get("query_version") == QUERY_VERSION
            and SOURCE_RE.fullmatch(source_id) is not None
            and abstract.startswith(f"{SOURCE_PREFIX}{source_id}:")
            and entity is not None
            and observable_type == entity.get("entity_type")
            and observable_type in SIGNALS
            and bool(signals)
            and signals <= SIGNALS.get(observable_type, set())
            and updated_at is not None
            and updated_at <= now + timedelta(minutes=5)
        )
        if not valid:
            metrics["malformed"] += 1
            continue
        if now - updated_at > max_age:
            metrics["stale"] += 1
            continue
        vote = Vote(source_id, frozenset(signals), updated_at)
        previous = votes[object_id].get(source_id)
        if previous:
            metrics["duplicates"] += 1
        if previous is None or vote.updated_at > previous.updated_at:
            votes[object_id][source_id] = vote
    plans = {}
    for object_id, source_votes in votes.items():
        entity = entities[object_id]
        timestamps = [vote.updated_at for vote in source_votes.values()]
        plans[object_id] = ReviewPlan(
            object_id, entity["entity_type"], len(source_votes),
            tuple(sorted(set().union(*(vote.signals for vote in source_votes.values())))),
            min(timestamps), max(timestamps), _conflict(entity),
        )
    metrics["valid_evidence"] = sum(len(items) for items in votes.values())
    metrics["source_local"] = sum(plan.source_count == 1 for plan in plans.values())
    metrics["herd"] = sum(plan.source_count >= 2 for plan in plans.values())
    metrics["conflicts"] = sum(plan.conflict for plan in plans.values())
    return plans, dict(metrics)


class CommonnessReviewer:
    def __init__(self, api, *, page_size: int = 100, max_pages: int = 10,
                 max_age_days: int = 2, write: bool = False) -> None:
        if not 1 <= page_size <= 500 or not 1 <= max_pages <= 100 or not 1 <= max_age_days <= 30:
            raise ValueError("invalid review bounds")
        self.api = api
        self.page_size = page_size
        self.max_pages = max_pages
        self.max_age = timedelta(days=max_age_days)
        self.write = write

    def _paged(self, fn: Callable, **kwargs) -> tuple[list[dict], bool, int]:
        items, after = [], None
        for page_number in range(1, self.max_pages + 1):
            raw = fn(first=self.page_size, after=after, withPagination=True, **kwargs)
            entities, pagination = _page_parts(raw)
            items.extend(entities)
            if not pagination.get("hasNextPage"):
                return items, True, page_number
            after = pagination.get("endCursor")
            if not after:
                return items, False, page_number
        return items, False, self.max_pages

    def _inventory(self) -> tuple[list[dict], list[dict], bool, int]:
        label_ids = []
        for value in SOURCE_LABELS | {HERD_LABEL}:
            label_ids.extend(label["id"] for label in self.api.label.list(search=value, first=20)
                             if label.get("value") == value)
        if not label_ids:
            return [], [], True, 0
        observables, complete, pages = self._paged(
            self.api.stix_cyber_observable.list,
            types=["Domain-Name", "IPv4-Addr"],
            filters={"mode": "and", "filters": [{"key": "objectLabel", "values": label_ids}], "filterGroups": []},
            customAttributes="""id entity_type x_opencti_score objectLabel { id value } indicators(first: 1) { edges { node { id } } }""",
        )
        notes, note_pages = [], 0
        for index in range(0, len(observables), 50):
            found, batch_complete, count = self._paged(
                self.api.note.list,
                filters={"mode": "and", "filters": [{"key": "objects", "values": [item["id"] for item in observables[index:index + 50]]}], "filterGroups": []},
                customAttributes="""id attribute_abstract content updated_at objects(all: true) { edges { node { ... on BasicObject { id entity_type } } } }""",
            )
            notes.extend(found)
            note_pages += count
            complete &= batch_complete
        return observables, notes, complete, pages + note_pages

    @staticmethod
    def _review_abstract(object_id: str) -> str:
        return REVIEW_PREFIX + hashlib.sha256(object_id.encode()).hexdigest()[:12]

    @staticmethod
    def _review_note_id(object_id: str) -> str:
        return "note--" + str(uuid.uuid5(NOTE_NAMESPACE, object_id))

    def _apply(self, observables: list[dict], notes: list[dict], plans: dict[str, ReviewPlan]) -> dict[str, int]:
        changed = defaultdict(int)
        herd_label = None
        review_notes: dict[str, list[dict]] = defaultdict(list)
        for note in notes:
            if str(note.get("attribute_abstract") or note.get("abstract") or "").startswith(REVIEW_PREFIX):
                for object_id in _refs(note):
                    review_notes[object_id].append(note)
        for entity in observables:
            object_id = str(entity["id"])
            plan = plans.get(object_id)
            herd_labels = [label for label in entity.get("objectLabel") or [] if label.get("value") == HERD_LABEL]
            if plan and plan.source_count >= 2:
                if not herd_labels:
                    herd_label = herd_label or self.api.label.create(value=HERD_LABEL, color=HERD_COLOR)
                    self.api.stix_cyber_observable.add_label(id=object_id, label_id=herd_label["id"])
                    changed["labels_added"] += 1
                payload = {
                    "schema_version": 1, "classification": plan.classification,
                    "source_count": plan.source_count, "signal_classes": list(plan.signals),
                    "oldest_evidence": plan.oldest.isoformat().replace("+00:00", "Z"),
                    "newest_evidence": plan.newest.isoformat().replace("+00:00", "Z"),
                    "conflict": plan.conflict, "explanation": plan.explanation,
                }
                created = self.api.note.create(
                    stix_id=self._review_note_id(object_id),
                    abstract=self._review_abstract(object_id),
                    content=json.dumps(payload, sort_keys=True, separators=(",", ":")),
                    objects=[object_id], confidence=60, update=True,
                )
                changed["notes_upserted"] += 1
                keep_id = (created or {}).get("id")
                for duplicate in review_notes.get(object_id, []):
                    if keep_id and duplicate.get("id") != keep_id:
                        self.api.stix_domain_object.delete(id=duplicate["id"])
                        changed["notes_removed"] += 1
            else:
                for label in herd_labels:
                    self.api.stix_cyber_observable.remove_label(id=object_id, label_id=label["id"])
                    changed["labels_removed"] += 1
                for note in review_notes.get(object_id, []):
                    self.api.stix_domain_object.delete(id=note["id"])
                    changed["notes_removed"] += 1
        return dict(changed)

    def purge(self) -> dict:
        started = time.monotonic()
        observables, notes, complete, pages = self._inventory()
        summary = {"mode": "purge", "complete": complete, "pages": pages,
                   "candidates": len(observables), "labels_removed": 0,
                   "notes_removed": 0, "writes_blocked": int(not complete)}
        if complete and self.write:
            for entity in observables:
                for label in entity.get("objectLabel") or []:
                    if label.get("value") == HERD_LABEL and label.get("id"):
                        self.api.stix_cyber_observable.remove_label(id=entity["id"], label_id=label["id"])
                        summary["labels_removed"] += 1
            for note in notes:
                if str(note.get("attribute_abstract") or note.get("abstract") or "").startswith(REVIEW_PREFIX):
                    self.api.stix_domain_object.delete(id=note["id"])
                    summary["notes_removed"] += 1
        summary["runtime_seconds"] = round(time.monotonic() - started, 3)
        return summary

    def run(self, *, now: datetime | None = None) -> dict:
        started = time.monotonic()
        now = now or datetime.now(timezone.utc)
        observables, notes, complete, pages = self._inventory()
        plans, metrics = reduce_evidence(observables, notes, now=now, max_age=self.max_age)
        herd_ids = {str(item["id"]) for item in observables if HERD_LABEL in _labels(item)}
        planned_herd_ids = {object_id for object_id, plan in plans.items() if plan.source_count >= 2}
        review_ids = {object_id for note in notes
                      if str(note.get("attribute_abstract") or note.get("abstract") or "").startswith(REVIEW_PREFIX)
                      for object_id in _refs(note)}
        summary = {
            "mode": "apply" if self.write else "shadow", "complete": complete,
            "pages": pages, "candidates": len(observables), "evidence_records": metrics.get("source_records", 0),
            **{name: metrics.get(name, 0) for name in ("valid_evidence", "source_local", "herd", "stale", "malformed", "duplicates", "conflicts")},
            "projected_writes": len(planned_herd_ids)
                                + len(planned_herd_ids - herd_ids)
                                + len(herd_ids - planned_herd_ids)
                                + len(review_ids - planned_herd_ids),
            "writes_blocked": int(self.write and not complete),
        }
        if self.write and complete:
            summary.update(self._apply(observables, notes, plans))
        for name in ("labels_added", "labels_removed", "notes_upserted", "notes_removed"):
            summary.setdefault(name, 0)
        summary["runtime_seconds"] = round(time.monotonic() - started, 3)
        return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("shadow", "apply", "purge"), nargs="?", default="shadow")
    args = parser.parse_args()
    if args.mode in {"apply", "purge"} and not _bool("VECTRA_COMMONNESS_REVIEW_WRITE"):
        parser.error(f"{args.mode} requires VECTRA_COMMONNESS_REVIEW_WRITE=true")
    url = os.environ.get("OPENCTI_URL")
    token = os.environ.get("OPENCTI_TOKEN") or os.environ.get("OPENCTI_ADMIN_TOKEN")
    if not url or not token:
        parser.error("OPENCTI_URL and OPENCTI_TOKEN are required")
    api = OpenCTIApiClient(url, token)
    if getattr(api, "app_logger", None):
        api.app_logger.info = lambda *_args, **_kwargs: None
    reviewer = CommonnessReviewer(
        api,
        page_size=int(os.environ.get("VECTRA_COMMONNESS_REVIEW_PAGE_SIZE", "100")),
        max_pages=int(os.environ.get("VECTRA_COMMONNESS_REVIEW_MAX_PAGES", "10")),
        max_age_days=int(os.environ.get("VECTRA_COMMONNESS_REVIEW_MAX_AGE_DAYS", "2")),
        write=args.mode in {"apply", "purge"},
    )
    print(json.dumps(reviewer.purge() if args.mode == "purge" else reviewer.run(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
