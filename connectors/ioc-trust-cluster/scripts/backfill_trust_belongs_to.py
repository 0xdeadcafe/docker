#!/usr/bin/env python3
"""Audit the blocked related-to -> belongs-to trust-edge migration.

OpenCTI currently rejects belongs-to for structural SCO parentage pairs, so
related-to remains the connector-owned structural edge. This script is kept as a
feasibility/verification tool for future schema changes; apply refuses known-bad
pairs unless --force is used.

Modes:
  dry-run  - report related-to edges and missing belongs-to equivalents
  apply    - create missing child -> belongs-to -> parent edges, idempotently
  verify   - fail if any related-to edge lacks an equivalent belongs-to

Env:
  OPENCTI_URL / OPENCTI_TOKEN              required for apply
  ELASTICSEARCH_URL=http://elasticsearch:9200
  OPENCTI_REL_INDEX=opencti_stix_core_relationships-000001
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from collections import Counter
from typing import Any

TRUST_REL_DESCRIPTION = "IOC trust-cluster structural parent link (auto-created)"
SOURCE_REL_TYPE = "related-to"
TARGET_REL_TYPE = "belongs-to"
# OpenCTI currently rejects belongs-to for these SCO parentage pairs. The script
# keeps dry-run/verify useful, but apply refuses by default rather than failing
# halfway through a migration.
UNSUPPORTED_BELONGS_TO_TYPES = {
    "Domain-Name -> Domain-Name",
    "Url -> Domain-Name",
    "Url -> IPv4-Addr",
    "IPv4-Addr -> IPv4-Addr",
}


def es_post(base_url: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(
        base_url.rstrip("/") + path,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def endpoint_from_source(src: dict[str, Any], suffix: str) -> dict[str, Any]:
    role = f"{src.get('relationship_type')}_{suffix}"
    for conn in src.get("connections") or []:
        if conn.get("role") == role:
            return {
                "id": conn.get("internal_id"),
                "name": conn.get("name") or "?",
                "type": next((t for t in conn.get("types", []) if t not in {"Basic-Object", "Stix-Object", "Stix-Core-Object", "Stix-Cyber-Observable"}), "?"),
            }
    return {"id": None, "name": "?", "type": "?"}


def scan_es_rels(base_url: str, index: str, relationship_type: str) -> list[dict[str, Any]]:
    query = {
        "size": 1000,
        "_source": ["internal_id", "relationship_type", "description", "confidence", "connections"],
        "query": {
            "bool": {
                "filter": [
                    {"term": {"relationship_type.keyword": relationship_type}},
                    {"match_phrase": {"description": TRUST_REL_DESCRIPTION}},
                ]
            }
        },
        "sort": [{"internal_id.keyword": "asc"}],
    }
    out: list[dict[str, Any]] = []
    search_after = None
    while True:
        if search_after:
            query["search_after"] = search_after
        data = es_post(base_url, f"/{index}/_search", query)
        hits = data.get("hits", {}).get("hits", [])
        if not hits:
            return out
        for hit in hits:
            src = hit["_source"]
            frm, to = endpoint_from_source(src, "from"), endpoint_from_source(src, "to")
            if frm["id"] and to["id"]:
                out.append({
                    "id": src.get("internal_id") or hit.get("_id"),
                    "from": frm,
                    "to": to,
                    "confidence": src.get("confidence") or 75,
                })
        search_after = hits[-1].get("sort")


def key(rel: dict[str, Any]) -> tuple[str, str]:
    return rel["from"]["id"], rel["to"]["id"]


def load_state(es_url: str, index: str) -> tuple[list[dict[str, Any]], set[tuple[str, str]]]:
    source = scan_es_rels(es_url, index, SOURCE_REL_TYPE)
    target = scan_es_rels(es_url, index, TARGET_REL_TYPE)
    return source, {key(rel) for rel in target}


def print_report(source: list[dict[str, Any]], target_keys: set[tuple[str, str]], sample: int) -> list[dict[str, Any]]:
    missing = [rel for rel in source if key(rel) not in target_keys]
    type_counts = Counter(f"{rel['from']['type']} -> {rel['to']['type']}" for rel in source)
    print(f"source_{SOURCE_REL_TYPE}: {len(source)}")
    print(f"existing_equivalent_{TARGET_REL_TYPE}: {len(source) - len(missing)}")
    print(f"missing_{TARGET_REL_TYPE}: {len(missing)}")
    print("top_endpoint_types:")
    for rel_types, count in type_counts.most_common(10):
        print(f"  {count:7d}  {rel_types}")
    if missing and sample:
        print("sample_missing:")
        for rel in missing[:sample]:
            print(f"  {rel['from']['id']} ({rel['from']['name']}) -> {rel['to']['id']} ({rel['to']['name']})")
    return missing


def apply(missing: list[dict[str, Any]], limit: int | None) -> int:
    url, token = os.environ.get("OPENCTI_URL"), os.environ.get("OPENCTI_TOKEN")
    if not url or not token:
        raise SystemExit("OPENCTI_URL and OPENCTI_TOKEN are required for apply")
    from pycti import OpenCTIApiClient  # noqa: WPS433 - optional migration script
    api = OpenCTIApiClient(url, token)
    created = 0
    for rel in missing[:limit]:
        api.stix_core_relationship.create(
            fromId=rel["from"]["id"],
            toId=rel["to"]["id"],
            relationship_type=TARGET_REL_TYPE,
            description=TRUST_REL_DESCRIPTION,
            confidence=rel.get("confidence") or 75,
        )
        created += 1
        if created % 500 == 0:
            print(f"created: {created}", flush=True)
    return created


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("dry-run", "apply", "verify"))
    parser.add_argument("--sample", type=int, default=10)
    parser.add_argument("--limit", type=int, default=0, help="apply at most N edges; 0 means all")
    parser.add_argument("--force", action="store_true", help="attempt apply even for relationship pairs OpenCTI is known to reject")
    parser.add_argument("--elasticsearch-url", default=os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200"))
    parser.add_argument("--index", default=os.environ.get("OPENCTI_REL_INDEX", "opencti_stix_core_relationships-000001"))
    args = parser.parse_args()

    source, target_keys = load_state(args.elasticsearch_url, args.index)
    missing = print_report(source, target_keys, args.sample)
    if args.mode == "dry-run":
        return 0
    if args.mode == "verify":
        return 0 if not missing else 2
    unsupported = sorted({f"{rel['from']['type']} -> {rel['to']['type']}" for rel in missing} & UNSUPPORTED_BELONGS_TO_TYPES)
    if unsupported and not args.force:
        print("cannot_apply_belongs_to: OpenCTI rejects belongs-to for structural SCO parentage pairs:")
        for rel_types in unsupported:
            print(f"  {rel_types}")
        print("Use existing related-to trust edges for SCO parentage; CIDR->AS belongs-to remains supported.")
        return 3
    created = apply(missing, args.limit or None)
    print(f"created_{TARGET_REL_TYPE}: {created}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
