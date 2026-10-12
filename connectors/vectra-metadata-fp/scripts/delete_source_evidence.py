#!/usr/bin/env python3
"""Delete one opaque source's commonness evidence without deleting Observables."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

from pycti import OpenCTIApiClient

OWNED_LABELS = {
    "vectra-metadata:common-domain", "vectra-metadata:common-ip",
    "vectra-metadata:shared-auth-ip", "vectra-metadata:commonness-conflict",
}


def refs(note: dict) -> list[str]:
    objects = note.get("objects") or {}
    edges = objects.get("edges", []) if isinstance(objects, dict) else objects
    return [str((edge.get("node") or edge).get("id")) for edge in edges
            if isinstance(edge, dict) and (edge.get("node") or edge).get("id")]


def run(api, source_id: str, apply: bool = False) -> dict:
    label_ids = []
    for value in OWNED_LABELS:
        label_ids.extend(label["id"] for label in api.label.list(search=value, first=20)
                         if label.get("value") == value)
    observables = [] if not label_ids else api.stix_cyber_observable.list(
        filters={"mode": "and", "filters": [{"key": "objectLabel", "values": label_ids}], "filterGroups": []},
        first=500, getAll=True,
    )
    notes_by_id = {}
    ids = [item["id"] for item in observables]
    for index in range(0, len(ids), 50):
        found = api.note.list(
            filters={"mode": "and", "filters": [{"key": "objects", "values": ids[index:index + 50]}], "filterGroups": []},
            first=500, getAll=True,
        )
        notes_by_id.update((note["id"], note) for note in found
                           if str(note.get("attribute_abstract") or note.get("abstract") or "").startswith("vectra-commonness:"))
    notes = list(notes_by_id.values())
    counts = Counter(object_id for note in notes for object_id in refs(note))
    selected = [note for note in notes if str(note.get("attribute_abstract") or note.get("abstract") or "").startswith(f"vectra-commonness:{source_id}:")]
    removed_labels = 0
    if apply:
        for note in selected:
            for object_id in refs(note):
                if counts[object_id] > 1:
                    continue
                observable = api.stix_cyber_observable.read(id=object_id) or {}
                for label in observable.get("objectLabel") or []:
                    if label.get("value") in OWNED_LABELS and label.get("id"):
                        api.stix_cyber_observable.remove_label(id=object_id, label_id=label["id"])
                        removed_labels += 1
            api.stix_domain_object.delete(id=note["id"])
    return {
        "mode": "apply" if apply else "dry-run", "source_id": source_id,
        "evidence_records": len(selected), "label_associations_removed": removed_labels,
        "observables_deleted": 0, "scores_changed": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_id")
    parser.add_argument("mode", choices=("dry-run", "apply"), nargs="?", default="dry-run")
    args = parser.parse_args()
    if not args.source_id or len(args.source_id) > 64 or not args.source_id.replace("-", "").replace("_", "").isalnum():
        parser.error("source_id must be an opaque 1-64 character ID")
    url = os.environ.get("OPENCTI_URL")
    token = os.environ.get("OPENCTI_TOKEN") or os.environ.get("OPENCTI_ADMIN_TOKEN")
    if not url or not token:
        print("OPENCTI_URL and OPENCTI_TOKEN are required", file=sys.stderr)
        return 2
    print(json.dumps(run(OpenCTIApiClient(url, token), args.source_id, args.mode == "apply"), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
