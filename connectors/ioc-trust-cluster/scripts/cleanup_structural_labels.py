#!/usr/bin/env python3
"""Remove obsolete structural trust-cluster:<parent> labels.

Structural parentage is relationship-backed. This script removes only labels that
match an existing connector-created trust parent edge:

  child --related-to/description--> parent
  label value: trust-cluster:<parent observable value>

It preserves inherited verdict labels and label-only grouping labels.

Modes:
  dry-run  - report removable labels, no writes
  apply    - remove labels via OpenCTI API
  verify   - fail if removable labels remain

Env:
  OPENCTI_URL / OPENCTI_TOKEN              required for apply
  ELASTICSEARCH_URL=http://elasticsearch:9200
  OPENCTI_REL_INDEX=opencti_stix_core_relationships-000001
  OPENCTI_OBS_INDEX=opencti_stix_cyber_observables-000001
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
from typing import Any

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


def scan(base_url: str, index: str, query: dict[str, Any], source: list[str], sort_field: str = "internal_id.keyword") -> list[dict[str, Any]]:
    body: dict[str, Any] = {"size": 1000, "_source": source, "query": query, "sort": [{sort_field: "asc"}]}
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


def endpoint(src: dict[str, Any], suffix: str) -> dict[str, str | None]:
    role = f"{src.get('relationship_type')}_{suffix}"
    for conn in src.get("connections") or []:
        if conn.get("role") == role:
            return {"id": conn.get("internal_id"), "value": conn.get("name")}
    return {"id": None, "value": None}


def structural_label_value(parent_value: str | None) -> str | None:
    if not parent_value:
        return None
    value = f"{CLUSTER_PREFIX}{parent_value}"
    if value in PRESERVE_VALUES or any(value.startswith(prefix) for prefix in PRESERVE_PREFIXES):
        return None
    return value


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
        rows = scan(es_url, rel_index, query, ["internal_id", "relationship_type", "description", "connections"])
        for src in rows:
            frm, to = endpoint(src, "from"), endpoint(src, "to")
            label_value = structural_label_value(to["value"])
            if frm["id"] and to["id"] and label_value:
                rels.append({"from": frm, "to": to, "label_value": label_value})
    return rels


def load_labels(es_url: str, label_index: str) -> dict[str, str]:
    query = {"bool": {"filter": [{"term": {"entity_type.keyword": "Label"}}, {"wildcard": {"value.keyword": f"{CLUSTER_PREFIX}*"}}]}}
    rows = scan(es_url, label_index, query, ["internal_id", "value"])
    return {row["value"]: row["internal_id"] for row in rows if row.get("value")}


def chunks(items: list[str], size: int = 1000):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def load_observable_labels(es_url: str, obs_index: str, ids: set[str]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for batch in chunks(sorted(ids)):
        query = {"terms": {"internal_id.keyword": batch}}
        rows = scan(es_url, obs_index, query, ["internal_id", "rel_object-label.internal_id"])
        for row in rows:
            out[row["internal_id"]] = set(row.get("rel_object-label.internal_id") or [])
    return out


def inventory(es_url: str, rel_index: str, obs_index: str, label_index: str) -> list[dict[str, str]]:
    rels = load_relationships(es_url, rel_index)
    label_ids = load_labels(es_url, label_index)
    obs_ids = {rel["from"]["id"] for rel in rels} | {rel["to"]["id"] for rel in rels}
    obs_labels = load_observable_labels(es_url, obs_index, {oid for oid in obs_ids if oid})

    removals: dict[tuple[str, str], dict[str, str]] = {}
    for rel in rels:
        label_value = rel["label_value"]
        label_id = label_ids.get(label_value)
        if not label_id:
            continue
        for side in ("from", "to"):
            obs_id = rel[side]["id"]
            if obs_id and label_id in obs_labels.get(obs_id, set()):
                removals[(obs_id, label_id)] = {
                    "observable_id": obs_id,
                    "observable_value": rel[side]["value"] or "?",
                    "label_id": label_id,
                    "label_value": label_value,
                    "side": side,
                }
    return list(removals.values())


def report(removals: list[dict[str, str]], sample: int) -> None:
    print(f"removable_structural_labels: {len(removals)}")
    counts = Counter(row["side"] for row in removals)
    for side, count in sorted(counts.items()):
        print(f"  {side}: {count}")
    if removals and sample:
        print("sample_removals:")
        for row in removals[:sample]:
            print(f"  {row['observable_id']} ({row['observable_value']}) remove {row['label_value']}")


def remove_one(endpoint: str, token: str, row: dict[str, str]) -> bool:
    query = """
    mutation StixCyberObservableRemoveRelation($id: ID!, $toId: StixRef!, $relationship_type: String!) {
      stixCyberObservableEdit(id: $id) {
        relationDelete(toId: $toId, relationship_type: $relationship_type) { id }
      }
    }
    """
    payload = {
        "query": query,
        "variables": {
            "id": row["observable_id"],
            "toId": row["label_id"],
            "relationship_type": "object-label",
        },
    }
    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        data = json.loads(resp.read().decode())
    if data.get("errors"):
        raise RuntimeError(data["errors"])
    return True


def apply(removals: list[dict[str, str]], limit: int | None, workers: int) -> int:
    url, token = os.environ.get("OPENCTI_URL"), os.environ.get("OPENCTI_TOKEN")
    if not url or not token:
        raise SystemExit("OPENCTI_URL and OPENCTI_TOKEN are required for apply")
    endpoint = url.rstrip("/") + "/graphql"
    rows = removals[:limit]
    removed = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(remove_one, endpoint, token, row) for row in rows]
        for fut in as_completed(futures):
            fut.result()
            removed += 1
            if removed % 500 == 0:
                print(f"removed: {removed}", flush=True)
    return removed


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("dry-run", "apply", "verify"))
    parser.add_argument("--sample", type=int, default=10)
    parser.add_argument("--limit", type=int, default=0, help="apply at most N removals; 0 means all")
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--elasticsearch-url", default=os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200"))
    parser.add_argument("--rel-index", default=os.environ.get("OPENCTI_REL_INDEX", "opencti_stix_core_relationships-000001"))
    parser.add_argument("--obs-index", default=os.environ.get("OPENCTI_OBS_INDEX", "opencti_stix_cyber_observables-000001"))
    parser.add_argument("--label-index", default=os.environ.get("OPENCTI_LABEL_INDEX", "opencti_stix_meta_objects-000001"))
    args = parser.parse_args()

    removals = inventory(args.elasticsearch_url, args.rel_index, args.obs_index, args.label_index)
    report(removals, args.sample)
    if args.mode == "dry-run":
        return 0
    if args.mode == "verify":
        return 0 if not removals else 2
    removed = apply(removals, args.limit or None, args.workers)
    print(f"removed_structural_labels: {removed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
