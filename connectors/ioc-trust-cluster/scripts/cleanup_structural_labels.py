#!/usr/bin/env python3
"""Remove obsolete structural trust-cluster labels and orphan definitions.

Structural parentage is relationship-backed. Cleanup removes a label association
only when the same child/parent pair has the connector-owned structural edge,
then deletes only unreferenced structural label definitions. Inherited verdict
and label-only grouping labels are always preserved.

Modes:
  dry-run  - inventory references across all object types; report only
  apply    - remove proven structural associations, then orphan definitions
  verify   - fail if removable associations, orphan definitions, or dangling
             trust-cluster object-label relationships remain

Env:
  OPENCTI_URL / OPENCTI_TOKEN              required for apply
  ELASTICSEARCH_URL=http://elasticsearch:9200
  OPENCTI_REL_INDEX=opencti_stix_core_relationships-000001
  OPENCTI_META_REL_INDEX=opencti_stix_meta_relationships-000001
  OPENCTI_LABEL_INDEX=opencti_stix_meta_objects-000001
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable

TRUST_REL_DESCRIPTION = "IOC trust-cluster structural parent link (auto-created)"
CLUSTER_PREFIX = "trust-cluster:"
PRESERVE_VALUES = {"trust-cluster:malicious-cascade", "trust-cluster:fp-candidate"}
PRESERVE_PREFIXES = ("trust-cluster:asn-owner:", "trust-cluster:tls-profile:")
STRUCTURAL_REL_TYPES = ("related-to",)


def es_post(base_url: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def scan(
    base_url: str,
    index: str,
    query: dict[str, Any],
    source: list[str],
    sort_field: str = "internal_id.keyword",
) -> list[dict[str, Any]]:
    body: dict[str, Any] = {
        "size": 1000,
        "_source": source,
        "query": query,
        "sort": [{sort_field: "asc"}],
    }
    out: list[dict[str, Any]] = []
    search_after = None
    while True:
        if search_after:
            body["search_after"] = search_after
        data = es_post(base_url, f"/{index}/_search", body)
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            return out
        out.extend(hit["_source"] for hit in hits)
        search_after = hits[-1].get("sort")


def endpoint(src: dict[str, Any], suffix: str) -> dict[str, Any]:
    role = f"{src.get('relationship_type')}_{suffix}"
    for conn in src.get("connections") or []:
        if conn.get("role") == role:
            return {
                "id": conn.get("internal_id"),
                "value": conn.get("name"),
                "types": conn.get("types") or [],
            }
    return {"id": None, "value": None, "types": []}


def is_preserved(value: str) -> bool:
    lower = value.lower()
    return lower in PRESERVE_VALUES or any(lower.startswith(prefix) for prefix in PRESERVE_PREFIXES)


def structural_label_value(parent_value: str | None) -> str | None:
    if not parent_value:
        return None
    value = f"{CLUSTER_PREFIX}{parent_value}"
    return None if is_preserved(value) else value


def load_relationships(es_url: str, rel_index: str) -> list[dict[str, Any]]:
    rels: list[dict[str, Any]] = []
    for rel_type in STRUCTURAL_REL_TYPES:
        query = {
            "bool": {
                "filter": [
                    {"term": {"relationship_type.keyword": rel_type}},
                    {"match_phrase": {"description": TRUST_REL_DESCRIPTION}},
                ]
            }
        }
        rows = scan(
            es_url,
            rel_index,
            query,
            ["internal_id", "relationship_type", "description", "connections"],
        )
        for src in rows:
            frm, to = endpoint(src, "from"), endpoint(src, "to")
            label_value = structural_label_value(to["value"])
            if frm["id"] and to["id"] and label_value:
                rels.append({"from": frm, "to": to, "label_value": label_value})
    return rels


def load_labels(es_url: str, label_index: str) -> dict[str, str]:
    query = {
        "bool": {
            "filter": [
                {"term": {"entity_type.keyword": "Label"}},
                {"wildcard": {"value.keyword": f"{CLUSTER_PREFIX}*"}},
            ]
        }
    }
    rows = scan(es_url, label_index, query, ["internal_id", "value"])
    return {
        row["internal_id"]: row["value"]
        for row in rows
        if row.get("internal_id") and row.get("value")
    }


def load_label_references(es_url: str, meta_rel_index: str) -> list[dict[str, Any]]:
    """Return authoritative trust-cluster object-label edges for every source type."""
    query = {
        "bool": {
            "filter": [
                {"term": {"relationship_type.keyword": "object-label"}},
                {
                    "nested": {
                        "path": "connections",
                        "query": {
                            "bool": {
                                "filter": [
                                    {"term": {"connections.role.keyword": "object-label_to"}},
                                    {"wildcard": {"connections.name.keyword": f"{CLUSTER_PREFIX}*"}},
                                ]
                            }
                        },
                    }
                },
            ]
        }
    }
    rows = scan(
        es_url,
        meta_rel_index,
        query,
        ["internal_id", "relationship_type", "connections"],
    )
    refs: list[dict[str, Any]] = []
    for src in rows:
        frm, to = endpoint(src, "from"), endpoint(src, "to")
        if frm["id"] and to["id"] and str(to["value"] or "").lower().startswith(CLUSTER_PREFIX):
            refs.append(
                {
                    "relationship_id": src.get("internal_id"),
                    "source_id": frm["id"],
                    "source_value": frm["value"] or "?",
                    "source_types": frm["types"],
                    "label_id": to["id"],
                    "label_value": to["value"],
                }
            )
    return refs


def removable_associations(
    rels: list[dict[str, Any]],
    labels: dict[str, str],
    refs: list[dict[str, Any]],
) -> list[dict[str, str]]:
    label_ids = {value: label_id for label_id, value in labels.items()}
    referenced_pairs = {(ref["source_id"], ref["label_id"]) for ref in refs}
    removals: dict[tuple[str, str], dict[str, str]] = {}
    for rel in rels:
        label_id = label_ids.get(rel["label_value"])
        if not label_id:
            continue
        for side in ("from", "to"):
            obs_id = rel[side]["id"]
            if (obs_id, label_id) in referenced_pairs:
                removals[(obs_id, label_id)] = {
                    "observable_id": obs_id,
                    "observable_value": rel[side]["value"] or "?",
                    "label_id": label_id,
                    "label_value": rel["label_value"],
                    "side": side,
                }
    return list(removals.values())


def label_cleanup_plan(
    labels: dict[str, str],
    refs: list[dict[str, Any]],
    ignored_reference_pairs: set[tuple[str, str]] | None = None,
) -> dict[str, list[dict[str, str]]]:
    ignored_reference_pairs = ignored_reference_pairs or set()
    active_refs = [
        ref
        for ref in refs
        if (ref["source_id"], ref["label_id"]) not in ignored_reference_pairs
    ]
    referenced_ids = {ref["label_id"] for ref in active_refs}
    orphaned, protected, referenced = [], [], []
    for label_id, value in labels.items():
        row = {"label_id": label_id, "label_value": value}
        if label_id in referenced_ids:
            referenced.append(row)
        elif is_preserved(value):
            protected.append(row)
        else:
            orphaned.append(row)
    dangling = [ref for ref in active_refs if ref["label_id"] not in labels]
    return {
        "orphaned": sorted(orphaned, key=lambda row: row["label_value"]),
        "protected": sorted(protected, key=lambda row: row["label_value"]),
        "referenced": sorted(referenced, key=lambda row: row["label_value"]),
        "dangling": dangling,
    }


def inventory(es_url: str, rel_index: str, meta_rel_index: str, label_index: str) -> dict[str, Any]:
    labels = load_labels(es_url, label_index)
    refs = load_label_references(es_url, meta_rel_index)
    rels = load_relationships(es_url, rel_index)
    removals = removable_associations(rels, labels, refs)
    return {
        "labels": labels,
        "references": refs,
        "removals": removals,
        "plan": label_cleanup_plan(labels, refs),
    }


def source_type(ref: dict[str, Any]) -> str:
    generic = {"Basic-Object", "Stix-Object", "Stix-Core-Object", "Stix-Cyber-Observable"}
    return next((value for value in ref.get("source_types", []) if value not in generic), "Unknown")


def report(state: dict[str, Any], sample: int, heading: str = "inventory") -> None:
    plan = state["plan"]
    refs = state["references"]
    print(f"{heading}:")
    print(f"  trust_cluster_label_definitions: {len(state['labels'])}")
    print(f"  object_label_references_all_types: {len(refs)}")
    print(f"  referenced_definitions: {len(plan['referenced'])}")
    print(f"  preserved_unreferenced_definitions: {len(plan['protected'])}")
    print(f"  removable_structural_associations: {len(state['removals'])}")
    print(f"  deletable_orphan_definitions: {len(plan['orphaned'])}")
    print(f"  dangling_object_label_references: {len(plan['dangling'])}")
    for entity_type, count in sorted(Counter(source_type(ref) for ref in refs).items()):
        print(f"  references[{entity_type}]: {count}")
    if sample and state["removals"]:
        print("sample_association_removals:")
        for row in state["removals"][:sample]:
            print(f"  {row['observable_id']} ({row['observable_value']}) remove {row['label_value']}")
    if sample and plan["orphaned"]:
        print("sample_orphan_definitions:")
        for row in plan["orphaned"][:sample]:
            print(f"  {row['label_id']} {row['label_value']}")


def graphql(endpoint: str, token: str, query: str, variables: dict[str, Any]) -> None:
    req = urllib.request.Request(
        endpoint,
        data=json.dumps({"query": query, "variables": variables}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode())
    if data.get("errors"):
        raise RuntimeError(data["errors"])


def remove_one(endpoint: str, token: str, row: dict[str, str]) -> None:
    query = """
    mutation StixCyberObservableRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
      stixCyberObservableEdit(id: $id) {
        relationDelete(toId: $toId, relationship_type: $relationship_type) { id }
      }
    }
    """
    graphql(
        endpoint,
        token,
        query,
        {"id": row["observable_id"], "toId": row["label_id"], "relationship_type": "object-label"},
    )


def delete_one(endpoint: str, token: str, row: dict[str, str]) -> None:
    query = """
    mutation LabelEdit($id: ID!) {
      labelEdit(id: $id) { delete }
    }
    """
    graphql(endpoint, token, query, {"id": row["label_id"]})


def execute(
    rows: list[dict[str, str]],
    operation: Callable[[dict[str, str]], None],
    workers: int,
    progress_name: str,
) -> tuple[list[dict[str, str]], list[tuple[dict[str, str], str]]]:
    completed: list[dict[str, str]] = []
    errors: list[tuple[dict[str, str], str]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(operation, row): row for row in rows}
        for future in as_completed(futures):
            row = futures[future]
            try:
                future.result()
                completed.append(row)
                if len(completed) % 500 == 0:
                    print(f"{progress_name}: {len(completed)}", flush=True)
            except Exception as exc:  # continue so one stale object does not hide the inventory
                errors.append((row, str(exc)))
    return completed, errors


def apply(state: dict[str, Any], limit: int | None, workers: int) -> int:
    url, token = os.environ.get("OPENCTI_URL"), os.environ.get("OPENCTI_TOKEN")
    if not url or not token:
        raise SystemExit("OPENCTI_URL and OPENCTI_TOKEN are required for apply")
    endpoint_url = url.rstrip("/") + "/graphql"
    budget = limit if limit is not None else float("inf")

    association_rows = state["removals"][: int(budget)] if limit is not None else state["removals"]
    removed, remove_errors = execute(
        association_rows,
        lambda row: remove_one(endpoint_url, token, row),
        workers,
        "removed_structural_associations",
    )
    budget -= len(association_rows)

    removed_pairs = {(row["observable_id"], row["label_id"]) for row in removed}
    post_removal_plan = label_cleanup_plan(state["labels"], state["references"], removed_pairs)
    orphan_rows = post_removal_plan["orphaned"]
    delete_rows = orphan_rows[: max(0, int(budget))] if limit is not None else orphan_rows
    deleted, delete_errors = execute(
        delete_rows,
        lambda row: delete_one(endpoint_url, token, row),
        workers,
        "deleted_orphan_definitions",
    )

    skipped = len(state["labels"]) - len(delete_rows)
    errors = remove_errors + delete_errors
    print(f"removed_structural_associations: {len(removed)}")
    print(f"deleted_orphan_definitions: {len(deleted)}")
    print(f"skipped_label_definitions: {skipped}")
    print(f"errors: {len(errors)}")
    for row, error in errors[:10]:
        print(f"  error {row.get('label_value', '?')}: {error}")
    return 1 if errors else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("dry-run", "apply", "verify"))
    parser.add_argument("--sample", type=int, default=10)
    parser.add_argument("--limit", type=int, default=0, help="apply at most N total changes; 0 means all")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--elasticsearch-url", default=os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200"))
    parser.add_argument("--rel-index", default=os.environ.get("OPENCTI_REL_INDEX", "opencti_stix_core_relationships-000001"))
    parser.add_argument("--meta-rel-index", default=os.environ.get("OPENCTI_META_REL_INDEX", "opencti_stix_meta_relationships-000001"))
    parser.add_argument("--label-index", default=os.environ.get("OPENCTI_LABEL_INDEX", "opencti_stix_meta_objects-000001"))
    args = parser.parse_args()

    state = inventory(args.elasticsearch_url, args.rel_index, args.meta_rel_index, args.label_index)
    report(state, args.sample)
    if args.mode == "dry-run":
        return 0
    if args.mode == "verify":
        plan = state["plan"]
        return 2 if state["removals"] or plan["orphaned"] or plan["dangling"] else 0
    return apply(state, args.limit or None, max(1, args.workers))


if __name__ == "__main__":
    sys.exit(main())
