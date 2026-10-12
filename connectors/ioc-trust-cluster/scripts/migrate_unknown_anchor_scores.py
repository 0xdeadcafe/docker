#!/usr/bin/env python3
"""Reset legacy synthetic UNKNOWN trust anchors from score 50 to score 0.

Only observables with the connector's generated description, score 50, and no
labels, linked indicators, external references, or creator are eligible. Apply
re-reads each candidate before changing it so concurrent evidence is preserved.

Modes:
  dry-run  - report eligible and protected observables
  apply    - set eligible scores to 0
  verify   - fail while eligible score-50 anchors remain

Env: OPENCTI_URL and OPENCTI_TOKEN are required.
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

ANCHOR_TYPES = ("IPv4-Addr", "IPv6-Addr", "Domain-Name")
DESCRIPTION_SUFFIX = "). UNKNOWN until a feed connector assigns a real score."
FIELDS = """
  id entity_type observable_value x_opencti_description x_opencti_score
  createdBy { id }
  objectLabel { id value }
  externalReferences { edges { node { id } } }
  indicators { edges { node { id } } }
"""


def graphql(endpoint: str, token: str, query: str, variables: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(
        endpoint,
        data=json.dumps({"query": query, "variables": variables}).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        result = json.loads(response.read().decode())
    if result.get("errors"):
        raise RuntimeError(result["errors"])
    return result["data"]


def related(value: Any) -> list[Any]:
    if not value:
        return []
    if isinstance(value, list):
        return value
    return [edge.get("node") for edge in value.get("edges", []) if edge.get("node")]


def is_synthetic_anchor(observable: dict[str, Any]) -> bool:
    entity_type = observable.get("entity_type")
    description = observable.get("x_opencti_description") or ""
    return entity_type in ANCHOR_TYPES and description.startswith(
        f"Auto-created trust-cluster anchor ({entity_type}: "
    ) and description.endswith(DESCRIPTION_SUFFIX)


def ineligible_reason(observable: dict[str, Any]) -> str | None:
    if not is_synthetic_anchor(observable):
        return "not_synthetic_anchor"
    try:
        if int(observable.get("x_opencti_score")) != 50:
            return "score_changed"
    except (TypeError, ValueError):
        return "score_changed"
    if observable.get("objectLabel"):
        return "has_labels"
    if related(observable.get("indicators")):
        return "has_indicators"
    if related(observable.get("externalReferences")):
        return "has_external_references"
    if observable.get("createdBy"):
        return "has_creator"
    return None


def list_score_50_observables(
    endpoint: str, token: str
) -> tuple[int, list[dict[str, Any]]]:
    query = """
    query LegacyUnknownAnchors($types: [String], $filters: FilterGroup, $first: Int, $after: ID) {
      stixCyberObservables(types: $types, filters: $filters, first: $first, after: $after) {
        edges { node { %s } }
        pageInfo { endCursor hasNextPage }
      }
    }
    """ % FIELDS
    variables: dict[str, Any] = {
        "types": list(ANCHOR_TYPES),
        "filters": {
            "mode": "and",
            "filters": [
                {"key": "x_opencti_score", "values": ["50"], "operator": "eq"},
                {
                    "key": "x_opencti_description",
                    "values": ["Auto-created trust-cluster anchor ("],
                    "operator": "starts_with",
                },
            ],
            "filterGroups": [],
        },
        "first": 500,
        "after": None,
    }
    observables: list[dict[str, Any]] = []
    while True:
        page = graphql(endpoint, token, query, variables)["stixCyberObservables"]
        observables.extend(edge["node"] for edge in page["edges"])
        if not page["pageInfo"]["hasNextPage"]:
            return len(observables), observables
        variables["after"] = page["pageInfo"]["endCursor"]


def read_observable(endpoint: str, token: str, observable_id: str) -> dict[str, Any] | None:
    query = """
    query LegacyUnknownAnchor($id: String!) {
      stixCyberObservable(id: $id) { %s }
    }
    """ % FIELDS
    return graphql(endpoint, token, query, {"id": observable_id})["stixCyberObservable"]


def set_score_zero(endpoint: str, token: str, observable_id: str) -> None:
    mutation = """
    mutation ResetUnknownAnchorScore($id: ID!, $input: [EditInput]!) {
      stixCyberObservableEdit(id: $id) {
        fieldPatch(input: $input) { id }
      }
    }
    """
    graphql(
        endpoint,
        token,
        mutation,
        {"id": observable_id, "input": [{"key": "x_opencti_score", "value": "0"}]},
    )


def report(
    scanned: int, observables: list[dict[str, Any]], sample: int
) -> list[dict[str, Any]]:
    reasons = Counter(ineligible_reason(observable) or "eligible" for observable in observables)
    eligible = [observable for observable in observables if ineligible_reason(observable) is None]
    print(f"score_50_observables_scanned: {scanned}")
    print(f"eligible_synthetic_unknown_anchors: {len(eligible)}")
    for reason, count in sorted(reasons.items()):
        if reason != "eligible":
            print(f"protected[{reason}]: {count}")
    for observable in eligible[:sample]:
        print(f"  eligible {observable['id']} ({observable.get('observable_value', '?')})")
    return eligible


def apply(
    endpoint: str,
    token: str,
    candidates: list[dict[str, Any]],
    limit: int | None,
    workers: int,
) -> int:
    def migrate(candidate: dict[str, Any]) -> str:
        current = read_observable(endpoint, token, candidate["id"])
        if not current or ineligible_reason(current) is not None:
            return "protected"
        set_score_zero(endpoint, token, current["id"])
        return "migrated"

    counts: Counter[str] = Counter()
    rows = candidates[:limit]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(migrate, row): row for row in rows}
        for future in as_completed(futures):
            try:
                counts[future.result()] += 1
                if counts["migrated"] and counts["migrated"] % 500 == 0:
                    print(f"migrated: {counts['migrated']}", flush=True)
            except Exception as exc:
                counts["errors"] += 1
                print(f"  error {futures[future]['id']}: {exc}")
    print(f"migrated_to_score_0: {counts['migrated']}")
    print(f"protected_at_apply: {counts['protected']}")
    print(f"errors: {counts['errors']}")
    return 1 if counts["errors"] else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("dry-run", "apply", "verify"))
    parser.add_argument("--sample", type=int, default=10)
    parser.add_argument("--limit", type=int, default=0, help="apply at most N anchors; 0 means all")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    url, token = os.environ.get("OPENCTI_URL"), os.environ.get("OPENCTI_TOKEN")
    if not url or not token:
        raise SystemExit("OPENCTI_URL and OPENCTI_TOKEN are required")
    endpoint = url.rstrip("/") + "/graphql"
    scanned, observables = list_score_50_observables(endpoint, token)
    candidates = report(scanned, observables, args.sample)
    if args.mode == "dry-run":
        return 0
    if args.mode == "verify":
        return 2 if candidates else 0
    return apply(endpoint, token, candidates, args.limit or None, max(1, args.workers))


if __name__ == "__main__":
    sys.exit(main())
