#!/usr/bin/env python3
"""Read-only IP/CIDR edge audit. No RDAP, enrichment, writes or apply mode.

Live: --raw-file NEW.json (OPENCTI_URL/TOKEN); offline: --snapshot SAVED.json.
Raw API pages are saved before assessment. A marker is not author attribution.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path

MARKER = "IOC trust-cluster structural parent link (auto-created)"
QUERY = """query CidrParentAudit($after: ID) {
  stixCoreRelationships(fromTypes: ["IPv4-Addr", "IPv6-Addr"],
                       toTypes: ["IPv4-Addr", "IPv6-Addr"], first: 100, after: $after) {
    pageInfo { endCursor hasNextPage globalCount }
    edges { node {
      id standard_id entity_type relationship_type description confidence created_at updated_at
      createdBy { ... on Identity { id name } }
      from { ... on BasicObject { id entity_type }
             ... on StixCyberObservable { observable_value x_opencti_score x_opencti_description created_at updated_at objectLabel { id value } } }
      to { ... on BasicObject { id entity_type }
           ... on StixCyberObservable { observable_value x_opencti_score x_opencti_description created_at updated_at objectLabel { id value } } }
    } }
  }
}"""


def collect(api, source_url: str, max_pages: int) -> dict:
    pages, cursors = [], set()
    after, complete = None, False
    # ponytail: 100 rows/page, finite page cap; partial scans are never certified.
    for _ in range(max_pages):
        try:
            page = api.query(QUERY, {"after": after})
        except Exception as exc:
            pages.append({"errors": [{"type": type(exc).__name__}]})
            break
        pages.append(page)
        if page.get("errors"):
            break
        info = ((page.get("data") or {}).get("stixCoreRelationships") or {}).get("pageInfo") or {}
        if info.get("hasNextPage") is False:
            complete = True
            break
        after = info.get("endCursor")
        if not after or after in cursors:
            break
        cursors.add(after)
    return {"captured_at": datetime.now(timezone.utc).isoformat(), "source_url": source_url,
            "read_only": True, "max_pages": max_pages, "complete": complete, "pages": pages}


def audit(snapshot: dict) -> dict:
    counts = Counter()
    invalid, unknown, ids, totals = [], [], set(), set()
    complete = snapshot.get("complete") is True and bool(snapshot.get("pages"))
    for page in snapshot["pages"]:
        connection = (page.get("data") or {}).get("stixCoreRelationships")
        if page.get("errors") or connection is None:
            complete = False
            continue
        info = connection.get("pageInfo") or {}
        if "hasNextPage" not in info:
            complete = False
        if info.get("globalCount") is not None:
            totals.add(info["globalCount"])
        for edge in connection.get("edges") or []:
            rel = edge.get("node") or {}
            rid = rel.get("id")
            if not rid or rid in ids:
                complete = False
                unknown.append({"reason": "missing_or_duplicate_id", "relationship": rel})
                continue
            ids.add(rid)
            counts["total_edges"] += 1
            child = (rel.get("from") or {}).get("observable_value")
            parent = (rel.get("to") or {}).get("observable_value")
            if not child or not parent:
                unknown.append({"reason": "endpoint_unavailable", "relationship": rel})
                continue
            if "/" not in parent:
                counts["not_cidr_parent"] += 1
                continue
            try:
                a, b = ipaddress.ip_network(child, strict=False), ipaddress.ip_network(parent, strict=False)
            except ValueError:
                unknown.append({"reason": "malformed_endpoint", "relationship": rel})
                continue
            counts["assessed"] += 1
            reason = "family_mismatch" if a.version != b.version else "not_contained" if not a.subnet_of(b) else None
            if reason:
                invalid.append({"reason": reason, "marker_matches": rel.get("description") == MARKER,
                                "assignment_ownership": "unproven", "relationship": rel})
            else:
                counts["contained"] += 1
    last = (((snapshot.get("pages") or [{}])[-1].get("data") or {}).get("stixCoreRelationships") or {}).get("pageInfo") or {}
    if last.get("hasNextPage") is not False or len(totals) > 1 or (totals and totals != {len(ids)}):
        complete = False
    return {"captured_at": snapshot.get("captured_at"), "source_url": snapshot.get("source_url"),
            "complete": complete, "counts": dict(counts), "invalid_count": len(invalid),
            "invalid": invalid, "unassessable": unknown, "mutation_authorized": False,
            "apply_limit": 0, "warning": "Mathematical containment does not prove RDAP ownership; markers do not prove authorship. Review full exports and obtain approval before repair."}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--snapshot", type=Path)
    mode.add_argument("--raw-file", type=Path)
    parser.add_argument("--max-pages", type=int, default=100)
    args = parser.parse_args()
    if args.max_pages < 1:
        parser.error("--max-pages must be positive")
    if args.snapshot:
        snapshot = json.loads(args.snapshot.read_text())
    else:
        if args.raw_file.exists():
            parser.error("raw evidence file already exists; choose a new path")
        url, token = os.environ.get("OPENCTI_URL"), os.environ.get("OPENCTI_TOKEN")
        if not url or not token:
            parser.error("live audit requires OPENCTI_URL and OPENCTI_TOKEN")
        from pycti import OpenCTIApiClient
        snapshot = collect(OpenCTIApiClient(url, token), url, args.max_pages)
        with args.raw_file.open("x") as stream:
            json.dump(snapshot, stream)
    report = audit(snapshot)
    print(json.dumps(report, indent=2))
    if not report["complete"] or report["unassessable"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
