#!/usr/bin/env python3
"""Audit/remove connector-owned legacy labels without changing scores or objects."""
from __future__ import annotations

import argparse
import json
import os
import sys

from pycti import OpenCTIApiClient

LEGACY_LABELS = {"vectra-metadata-benign", "vectra-metadata-popular-ip", "vectra-discovered-common"}
LEGACY_NOTE_MARKERS = ("Vectra FP:", "Vectra Metadata — Benign IOC Discovery")


def note_refs(note: dict) -> set[str]:
    objects = note.get("objects") or {}
    edges = objects.get("edges", []) if isinstance(objects, dict) else objects
    return {str((edge.get("node") or edge).get("id")) for edge in edges
            if isinstance(edge, dict) and (edge.get("node") or edge).get("id")}


def is_legacy_note(note: dict) -> bool:
    text = f"{note.get('attribute_abstract') or note.get('abstract') or ''}\n{note.get('content') or ''}"
    return any(marker in text for marker in LEGACY_NOTE_MARKERS)


def chunks(values, size=50):
    for index in range(0, len(values), size):
        yield values[index:index + size]


def run(api, apply: bool = False) -> dict:
    label_ids = []
    for value in LEGACY_LABELS:
        label_ids.extend(label["id"] for label in api.label.list(search=value, first=20)
                         if label.get("value") == value)
    if not label_ids:
        observables = []
    else:
        observables = api.stix_cyber_observable.list(
            filters={"mode": "and", "filters": [{"key": "objectLabel", "values": label_ids}], "filterGroups": []},
            first=500, getAll=True,
            customAttributes="""id x_opencti_description objectLabel { id value }""",
        )
    by_id = {item["id"]: item for item in observables}
    notes_by_id = {}
    for ids in chunks(list(by_id)):
        notes = api.note.list(
            filters={"mode": "and", "filters": [{"key": "objects", "values": ids}], "filterGroups": []},
            first=500, getAll=True,
        )
        for note in notes:
            if is_legacy_note(note):
                notes_by_id[note["id"]] = note
    supported = set().union(*(note_refs(note) for note in notes_by_id.values())) if notes_by_id else set()
    removable = []
    for object_id in supported:
        observable = by_id.get(object_id, {})
        for label in observable.get("objectLabel") or []:
            if label.get("value") in LEGACY_LABELS and label.get("id"):
                removable.append((object_id, label["id"]))
    if apply:
        for object_id, label_id in removable:
            api.stix_cyber_observable.remove_label(id=object_id, label_id=label_id)
        for note_id in notes_by_id:
            api.stix_domain_object.delete(id=note_id)
    legacy_associations = sum(label.get("value") in LEGACY_LABELS
                              for item in observables for label in item.get("objectLabel") or [])
    connector_created = sum("Auto-created by Vectra Metadata FP Discovery" in str(item.get("x_opencti_description") or "")
                            for item in observables)
    return {
        "mode": "apply" if apply else "dry-run",
        "legacy_labeled_observables": len(observables),
        "legacy_label_associations": legacy_associations,
        "legacy_notes": len(notes_by_id),
        "observables_with_matching_notes": len(supported),
        "connector_created_observables": connector_created,
        "label_associations_to_remove": len(removable),
        "unsupported_label_associations_retained": legacy_associations - len(removable),
        "scores_changed": 0,
        "observables_deleted": 0,
        "generic_fp_candidate_removed": 0,
        "generic_fp_candidate_touched": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("dry-run", "apply"), nargs="?", default="dry-run")
    args = parser.parse_args()
    url = os.environ.get("OPENCTI_URL")
    token = os.environ.get("OPENCTI_TOKEN") or os.environ.get("OPENCTI_ADMIN_TOKEN")
    if not url or not token:
        print("OPENCTI_URL and OPENCTI_TOKEN are required", file=sys.stderr)
        return 2
    print(json.dumps(run(OpenCTIApiClient(url, token), args.mode == "apply"), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
