#!/usr/bin/env python3
"""OpenCTI connector for privacy-safe Vectra endpoint commonness evidence."""
from __future__ import annotations

import hashlib
import json
import os
import time
import traceback
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from pycti import OpenCTIConnectorHelper

from metadata_client import QueryResult, VectraMetadataClient, VectraMetadataError
from queries import (
    BATCH_SIZE, DISCOVERY_LIMIT, DISCOVERY_QUERIES, QUERY_BY_NAME,
    TARGETED_QUERIES, Observation, batches, build_windows,
    normalize_domain, normalize_ipv4,
)

LABEL_COMMON_DOMAIN = "vectra-metadata:common-domain"
LABEL_COMMON_IP = "vectra-metadata:common-ip"
LABEL_SHARED_AUTH_IP = "vectra-metadata:shared-auth-ip"
LABEL_CONFLICT = "vectra-metadata:commonness-conflict"
OWNED_LABELS = {LABEL_COMMON_DOMAIN, LABEL_COMMON_IP, LABEL_SHARED_AUTH_IP, LABEL_CONFLICT}
LABEL_COLORS = {
    LABEL_COMMON_DOMAIN: "#1565c0", LABEL_COMMON_IP: "#6d4c41",
    LABEL_SHARED_AUTH_IP: "#00838f", LABEL_CONFLICT: "#b71c1c",
}
NOTE_NAMESPACE = uuid.UUID("4c47e958-57d3-4dc4-af4b-0ac7758b0eac")
QUERY_VERSION = "x39.1-commonness-v1"


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes"}


def _labels(entity: dict) -> set[str]:
    return {str(item.get("value") or "").lower() for item in entity.get("objectLabel") or []}


def _is_conflict(entity: dict) -> bool:
    labels = _labels(entity)
    threat_label = any(any(word in label for word in ("malicious", "malware", "sinkhol", "threat"))
                       for label in labels if label != "trust-cluster:malicious-cascade")
    return (
        int(entity.get("x_opencti_score") or 0) >= 70
        or threat_label
        or "trust-cluster:malicious-cascade" in labels
        or bool((entity.get("indicators") or {}).get("edges"))
    )


@dataclass
class EvidencePlan:
    observable_type: str
    value: str
    observations: list[Observation]
    discovery: bool = False
    entity: dict | None = None

    @property
    def qualifying_signals(self) -> set[str]:
        grouped: dict[str, set[str]] = defaultdict(set)
        for observation in self.observations:
            if observation.breadth >= QUERY_BY_NAME[observation.signal].threshold:
                grouped[observation.signal].add(observation.window_id)
        return {signal for signal, windows in grouped.items() if len(windows) >= 2}

    @property
    def qualifies(self) -> bool:
        return bool(self.qualifying_signals)


class VectraMetadataCommonnessConnector:
    def __init__(self) -> None:
        if _bool("VECTRA_FP_APPLY_FP_CANDIDATE") or _bool("VECTRA_FP_STRONG_RAW_IPS"):
            raise ValueError("legacy benign/fp promotion flags are no longer supported")
        config = {
            "opencti": {"url": os.environ.get("OPENCTI_URL", "http://opencti:8080"),
                        "token": os.environ.get("OPENCTI_TOKEN")},
            "connector": {
                "id": os.environ.get("CONNECTOR_ID"), "type": "EXTERNAL_IMPORT",
                "name": os.environ.get("CONNECTOR_NAME", "Vectra Metadata Commonness"),
                "scope": "IPv4-Addr,Domain-Name", "auto": True,
                "confidence_level": int(os.environ.get("CONNECTOR_CONFIDENCE_LEVEL", "60")),
                "log_level": os.environ.get("CONNECTOR_LOG_LEVEL", "info"),
                "only_contextual": False,
            },
        }
        self.helper = OpenCTIConnectorHelper(config)
        # pycti logs filter values at INFO; targeted observable lookups would leak
        # endpoint values into connector logs. Keep API warnings/errors, but silence
        # only that verbose channel. Connector aggregate logs remain enabled.
        if getattr(getattr(self.helper, "api", None), "app_logger", None):
            self.helper.api.app_logger.info = lambda *_args, **_kwargs: None
        self.source_id = os.environ.get("VECTRA_COMMONNESS_SOURCE_ID", "tenant-01").strip()
        if not self.source_id or len(self.source_id) > 64 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in self.source_id):
            raise ValueError("VECTRA_COMMONNESS_SOURCE_ID must be an opaque 1-64 character ID")
        self.write_enabled = _bool("VECTRA_COMMONNESS_WRITE", False)
        self.lookback_days = int(os.environ.get("VECTRA_COMMONNESS_LOOKBACK_DAYS", "30"))
        self.batch_size = int(os.environ.get("VECTRA_COMMONNESS_BATCH_SIZE", str(BATCH_SIZE)))
        self.page_size = int(os.environ.get("VECTRA_COMMONNESS_PAGE_SIZE", "100"))
        self.discovery_limit = int(os.environ.get("VECTRA_COMMONNESS_DISCOVERY_LIMIT", str(DISCOVERY_LIMIT)))
        self.creation_limit = int(os.environ.get("VECTRA_COMMONNESS_CREATION_LIMIT", "100"))
        self.interval_sec = int(os.environ.get("VECTRA_COMMONNESS_INTERVAL_SEC", "86400"))
        if not 1 <= self.batch_size <= BATCH_SIZE:
            raise ValueError(f"VECTRA_COMMONNESS_BATCH_SIZE must be 1-{BATCH_SIZE}")
        if not 1 <= self.discovery_limit <= DISCOVERY_LIMIT:
            raise ValueError(f"VECTRA_COMMONNESS_DISCOVERY_LIMIT must be 1-{DISCOVERY_LIMIT}")
        if not 1 <= self.creation_limit <= 100:
            raise ValueError("VECTRA_COMMONNESS_CREATION_LIMIT must be 1-100")
        self._client: VectraMetadataClient | None = None
        self._cursors = {"Domain-Name": None, "IPv4-Addr": None}
        self._wrapped = {"Domain-Name": False, "IPv4-Addr": False}
        self._sweep_active: set[tuple[str, str]] = set()
        self._sweep_complete = True

    def _build_client(self) -> VectraMetadataClient | None:
        try:
            return VectraMetadataClient(
                cantina_token=os.environ.get("CANTINA_TOKEN", ""),
                cantina_user=os.environ.get("CANTINA_USER", ""),
                cantina_url=os.environ.get("CANTINA_DARKSTAR_URL", "https://cantina.vectra.ai/api/darkstar/lambda"),
                cantina_customer=os.environ.get("VECTRA_METADATA_CUSTOMER", ""),
                vectra_ndr_url=os.environ.get("VECTRA_NDR_URL", ""),
                vectra_client_id=os.environ.get("VECTRA_NDR_CLIENT_ID", ""),
                vectra_client_secret=os.environ.get("VECTRA_NDR_CLIENT_SECRET", ""),
                vectra_token=os.environ.get("VECTRA_NDR_TOKEN", ""),
                timeout_sec=int(os.environ.get("VECTRA_COMMONNESS_QUERY_TIMEOUT_SEC", "180")),
                poll_interval_sec=float(os.environ.get("VECTRA_METADATA_POLL_INTERVAL", "5")),
                page_size=int(os.environ.get("VECTRA_METADATA_PAGE_SIZE", "1000")),
                max_pages=int(os.environ.get("VECTRA_METADATA_MAX_PAGES", "200")),
                max_retries=int(os.environ.get("VECTRA_METADATA_MAX_RETRIES", "2")),
            )
        except VectraMetadataError as exc:  # type: ignore[name-defined]
            self.helper.log_warning(f"[vectra-commonness] Metadata disabled: {exc}")
            return None

    @staticmethod
    def _page_parts(page: object) -> tuple[list[dict], dict]:
        if isinstance(page, dict):
            entities = page.get("entities") or page.get("data") or []
            pagination = page.get("pagination") or page.get("pageInfo") or {}
            return list(entities), dict(pagination)
        return list(page or []), {}

    def _observable_page(self, observable_type: str) -> tuple[list[dict], bool]:
        cursor = self._cursors[observable_type]
        try:
            raw = self.helper.api.stix_cyber_observable.list(
                types=[observable_type], first=self.page_size, after=cursor,
                orderBy="created_at", orderMode="asc", withPagination=True,
                customAttributes="""
                    id entity_type observable_value x_opencti_score
                    objectLabel { id value }
                    indicators(first: 1) { edges { node { id } } }
                """,
            )
        except Exception as exc:
            if cursor:
                self.helper.log_warning(f"[vectra-commonness] invalid cursor for {observable_type}; restarting: {exc}")
                self._cursors[observable_type] = None
                return [], False
            raise
        entities, pagination = self._page_parts(raw)
        has_next = bool(pagination.get("hasNextPage"))
        self._cursors[observable_type] = pagination.get("endCursor") if has_next else None
        wrapped = not has_next
        self._wrapped[observable_type] |= wrapped
        validator = normalize_domain if observable_type == "Domain-Name" else normalize_ipv4
        valid = []
        for entity in entities:
            value = validator(entity.get("observable_value") or entity.get("value"))
            if value:
                entity = dict(entity)
                entity["observable_value"] = value
                valid.append(entity)
        return valid, wrapped

    def _execute(self, sql: str, signal: str, mode: str, metrics: dict) -> QueryResult:
        assert self._client is not None
        result = self._client.execute_result(sql)
        metrics["queries"] += 1
        metrics["runtime_seconds"] += result.runtime_seconds
        metrics[result.status] += 1
        if result.retry_count:
            metrics["retries"] += result.retry_count
        if not result.ok:
            self.helper.log_warning(f"[vectra-commonness] {mode}/{signal}: {result.status} {result.error_kind}")
        return result

    def _targeted(self, entities: list[dict], windows, metrics: dict) -> tuple[list[Observation], bool]:
        by_type = defaultdict(list)
        for entity in entities:
            by_type[entity["entity_type"]].append(entity["observable_value"])
        observations: list[Observation] = []
        complete = True
        for query in TARGETED_QUERIES:
            for chunk in batches(by_type[query.observable_type], self.batch_size):
                result = self._execute(query.build_targeted(chunk, windows), query.name, "lookup", metrics)
                if not result.ok:
                    complete = False
                    continue
                observations.extend(query.observations(result.rows))
        return observations, complete

    def _discover(self, windows, metrics: dict) -> tuple[list[Observation], bool]:
        observations: list[Observation] = []
        complete = True
        for query in DISCOVERY_QUERIES:
            result = self._execute(query.build_discovery(windows, self.discovery_limit), query.name, "discovery", metrics)
            if not result.ok:
                complete = False
                continue
            observations.extend(query.observations(result.rows))
        return observations, complete

    @staticmethod
    def _plans(observations: Iterable[Observation], discovery_keys: set[tuple[str, str]], entities: dict) -> dict[tuple[str, str], EvidencePlan]:
        grouped: dict[tuple[str, str], list[Observation]] = defaultdict(list)
        for observation in observations:
            grouped[(observation.observable_type, observation.value)].append(observation)
        return {key: EvidencePlan(key[0], key[1], rows, key in discovery_keys, entities.get(key))
                for key, rows in grouped.items()}

    def _find_observable(self, observable_type: str, value: str) -> dict | None:
        found = self.helper.api.stix_cyber_observable.list(
            types=[observable_type], first=1,
            filters={"mode": "and", "filters": [{"key": "value", "values": [value]}], "filterGroups": []},
            customAttributes="""id entity_type observable_value x_opencti_score objectLabel { id value } indicators(first: 1) { edges { node { id } } }""",
        )
        return found[0] if found else None

    def _create_observable(self, plan: EvidencePlan) -> dict | None:
        stix_type = "domain-name" if plan.observable_type == "Domain-Name" else "ipv4-addr"
        created = self.helper.api.stix_cyber_observable.create(observableData={
            "type": stix_type, "value": plan.value,
            "x_opencti_description": "Discovered as a recurring common endpoint by Vectra Metadata; commonness is not a benign verdict.",
        })
        return created or None

    def _ensure_label(self, entity: dict, label: str) -> None:
        if label in _labels(entity):
            return
        created = self.helper.api.label.create(value=label, color=LABEL_COLORS[label])
        self.helper.api.stix_cyber_observable.add_label(id=entity["id"], label_id=created["id"])

    @staticmethod
    def _note_id(source_id: str, observable_type: str, value: str) -> str:
        return "note--" + str(uuid.uuid5(NOTE_NAMESPACE, f"{source_id}|{observable_type}|{value}"))

    def _upsert_evidence(self, entity: dict, plan: EvidencePlan) -> None:
        grouped: dict[str, list[dict]] = defaultdict(list)
        for row in sorted(plan.observations, key=lambda item: (item.signal, item.window_id)):
            grouped[row.signal].append({
                "window": row.window_id, "breadth": row.breadth,
                "events": row.event_count, "first_seen": row.first_seen,
                "last_seen": row.last_seen,
            })
        payload = {
            "schema_version": 1, "query_version": QUERY_VERSION,
            "source_id": self.source_id, "observable_type": plan.observable_type,
            "signals": dict(grouped), "qualifying_signals": sorted(plan.qualifying_signals),
            "discovery": plan.discovery, "lookback_days": self.lookback_days,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        digest = hashlib.sha256(f"{plan.observable_type}:{plan.value}".encode()).hexdigest()[:12]
        self.helper.api.note.create(
            stix_id=self._note_id(self.source_id, plan.observable_type, plan.value),
            abstract=f"vectra-commonness:{self.source_id}:{digest}",
            content=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            objects=[entity["id"]], confidence=60, update=True,
        )

    def _write_plan(self, plan: EvidencePlan, allow_create: bool) -> str:
        entity = plan.entity or self._find_observable(plan.observable_type, plan.value)
        created = entity is None
        if created:
            if not allow_create:
                return "not_created"
            entity = self._create_observable(plan)
            if entity is None:
                return "failed"
            entity.setdefault("objectLabel", [])
            entity.setdefault("x_opencti_score", None)
        signals = plan.qualifying_signals
        if plan.observable_type == "Domain-Name":
            self._ensure_label(entity, LABEL_COMMON_DOMAIN)
        if "isession" in signals:
            self._ensure_label(entity, LABEL_COMMON_IP)
        if "m365" in signals:
            self._ensure_label(entity, LABEL_SHARED_AUTH_IP)
        if _is_conflict(entity):
            self._ensure_label(entity, LABEL_CONFLICT)
        self._upsert_evidence(entity, plan)
        return "created" if created else "updated"

    @staticmethod
    def _note_refs(note: dict) -> list[str]:
        objects = note.get("objects") or {}
        edges = objects.get("edges", []) if isinstance(objects, dict) else objects
        return [str((edge.get("node") or edge).get("id")) for edge in edges
                if isinstance(edge, dict) and (edge.get("node") or edge).get("id")]

    def _reconcile_stale(self) -> int:
        if not self.write_enabled or not self._sweep_complete or not all(self._wrapped.values()):
            return 0
        try:
            label_ids = []
            for value in OWNED_LABELS:
                label_ids.extend(label["id"] for label in self.helper.api.label.list(search=value, first=20)
                                 if label.get("value") == value)
            observables = [] if not label_ids else self.helper.api.stix_cyber_observable.list(
                filters={"mode": "and", "filters": [{"key": "objectLabel", "values": label_ids}], "filterGroups": []},
                first=500, getAll=True,
            )
            object_ids = [entity["id"] for entity in observables]
            notes_by_id = {}
            for index in range(0, len(object_ids), 50):
                notes = self.helper.api.note.list(
                    filters={"mode": "and", "filters": [{"key": "objects", "values": object_ids[index:index + 50]}], "filterGroups": []},
                    first=500, getAll=True,
                )
                for note in notes:
                    abstract = str(note.get("attribute_abstract") or note.get("abstract") or "")
                    if abstract.startswith(f"vectra-commonness:{self.source_id}:"):
                        notes_by_id[note["id"]] = note
        except Exception as exc:
            self.helper.log_warning(f"[vectra-commonness] stale reconciliation skipped: {exc}")
            return 0
        removed = 0
        for note in notes_by_id.values():
            for object_id in self._note_refs(note):
                entity = self.helper.api.stix_cyber_observable.read(id=object_id)
                if not entity:
                    continue
                value = (normalize_domain if entity.get("entity_type") == "Domain-Name" else normalize_ipv4)(entity.get("observable_value"))
                key = (entity.get("entity_type"), value) if value else None
                if key in self._sweep_active:
                    continue
                attached = self.helper.api.note.list(
                    filters={"mode": "and", "filters": [{"key": "objects", "values": [object_id]}], "filterGroups": []},
                    first=100, getAll=True,
                )
                commonness_refs = sum(str(item.get("attribute_abstract") or item.get("abstract") or "").startswith("vectra-commonness:")
                                      for item in attached)
                if commonness_refs <= 1:
                    for label in entity.get("objectLabel") or []:
                        if label.get("value") in OWNED_LABELS and label.get("id"):
                            self.helper.api.stix_cyber_observable.remove_label(id=object_id, label_id=label["id"])
                self.helper.api.stix_domain_object.delete(id=note["id"])
                removed += 1
        self._sweep_active.clear()
        self._sweep_complete = True
        self._wrapped = {"Domain-Name": False, "IPv4-Addr": False}
        return removed

    def _run_cycle(self, client: VectraMetadataClient) -> dict:
        self._client = client
        started = time.monotonic()
        metrics = defaultdict(int)
        windows = build_windows(lookback_days=self.lookback_days)
        entities_list = []
        for observable_type in ("Domain-Name", "IPv4-Addr"):
            page, _ = self._observable_page(observable_type)
            entities_list.extend(page)
        entities = {(item["entity_type"], item["observable_value"]): item for item in entities_list}
        lookup_rows, lookup_complete = self._targeted(entities_list, windows, metrics)
        discovery_rows, discovery_complete = self._discover(windows, metrics)
        discovery_keys = {(row.observable_type, row.value) for row in discovery_rows}
        plans = self._plans([*lookup_rows, *discovery_rows], discovery_keys, entities)
        qualified = {key: plan for key, plan in plans.items() if plan.qualifies}
        for plan in qualified.values():
            if plan.discovery and plan.entity is None:
                plan.entity = self._find_observable(plan.observable_type, plan.value)
        self._sweep_active.update(qualified)
        self._sweep_complete &= lookup_complete and discovery_complete
        missing_discovery = sorted(key for key, plan in qualified.items() if plan.discovery and plan.entity is None)
        selected_create = set(missing_discovery[:self.creation_limit])
        metrics["candidates"] = len(entities)
        metrics["discovered"] = len(discovery_keys)
        metrics["qualified"] = len(qualified)
        metrics["rejected"] = len(plans) - len(qualified)
        metrics["reused"] = sum(plan.entity is not None for plan in qualified.values())
        metrics["missing"] = len(missing_discovery)
        metrics["conflicts"] = sum(plan.entity is not None and _is_conflict(plan.entity) for plan in qualified.values())
        metrics["projected_writes"] = metrics["reused"] + (2 * len(selected_create))
        for name in ("partial", "error", "throttled", "unsupported", "created", "updated", "stale_removed"):
            metrics[name] += 0
        if self.write_enabled:
            for key, plan in sorted(qualified.items()):
                result = self._write_plan(plan, key in selected_create)
                metrics[result] += 1
            metrics["stale_removed"] = self._reconcile_stale()
        if all(self._wrapped.values()) and (not self.write_enabled or not self._sweep_complete):
            metrics["stale_skipped"] += int(self.write_enabled and not self._sweep_complete)
            self._sweep_active.clear()
            self._sweep_complete = True
            self._wrapped = {"Domain-Name": False, "IPv4-Addr": False}
        else:
            metrics["stale_skipped"] += 0
        metrics["elapsed_seconds"] = round(time.monotonic() - started, 3)
        summary = dict(metrics)
        summary["runtime_seconds"] = round(summary.get("runtime_seconds", 0), 3)
        summary["mode"] = "write" if self.write_enabled else "shadow"
        summary["source_id"] = self.source_id
        self.helper.log_info("[vectra-commonness] " + json.dumps(summary, sort_keys=True))
        return summary

    def run(self) -> None:
        self.helper.log_info(f"[vectra-commonness] starting mode={'write' if self.write_enabled else 'shadow'}")
        while True:
            if self._client is None:
                try:
                    self._client = self._build_client()
                except Exception as exc:
                    self.helper.log_error(f"[vectra-commonness] client init failed: {exc}\n{traceback.format_exc()}")
            if self._client is not None:
                try:
                    self._run_cycle(self._client)
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    self.helper.log_error(f"[vectra-commonness] cycle failed: {exc}\n{traceback.format_exc()}")
            time.sleep(self.interval_sec)


# Backward-compatible import name while deployment path remains unchanged.
VectraMetadataFPConnector = VectraMetadataCommonnessConnector

if __name__ == "__main__":
    VectraMetadataCommonnessConnector().run()
