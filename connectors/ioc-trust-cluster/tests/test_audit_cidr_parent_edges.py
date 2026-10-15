import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import pytest

path = Path(__file__).resolve().parents[1] / "scripts/audit_cidr_parent_edges.py"
spec = importlib.util.spec_from_file_location("audit_cidrs", path)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def edge(child, parent, rid="edge"):
    return {"node": {"id": rid, "description": mod.MARKER, "createdBy": None,
                     "from": {"observable_value": child}, "to": {"observable_value": parent}}}


def page(edges, more=False, cursor=None, total=1):
    return {"data": {"stixCoreRelationships": {"edges": edges, "pageInfo": {
        "hasNextPage": more, "endCursor": cursor, "globalCount": total}}}}


def snapshot(*pages):
    return {"captured_at": "2026-10-15T15:10:54Z", "complete": True, "pages": list(pages)}


@pytest.mark.parametrize("child,parent,bad", [
    ("18.214.199.100", "18.32.0.0/11", True),
    ("18.214.199.100", "18.0.0.0/8", False),
    ("18.32.0.0/11", "18.32.0.0/24", True),
    ("2606:4700::1111", "2606:4700::/32", False),
    ("8.8.8.8", "2606:4700::/32", True),
])
def test_containment_including_full_child_network(child, parent, bad):
    report = mod.audit(snapshot(page([edge(child, parent)])))
    assert report["complete"]
    assert report["invalid_count"] == int(bad)
    assert report["mutation_authorized"] is False
    assert report["apply_limit"] == 0
    if bad:
        assert report["invalid"][0]["assignment_ownership"] == "unproven"


def test_marker_does_not_authorize_repair_of_manual_or_connector_edges():
    row = edge("8.8.8.8", "9.9.0.0/16")
    row["node"]["description"] = "manual analyst context"
    report = mod.audit(snapshot(page([row])))
    assert report["invalid_count"] == 1
    assert not report["invalid"][0]["marker_matches"]
    assert not report["mutation_authorized"]


@pytest.mark.parametrize("parent", [None, "invalid/24"])
def test_unavailable_and_malformed_endpoints_are_not_silently_skipped(parent):
    report = mod.audit(snapshot(page([edge("8.8.8.8", parent)])))
    assert len(report["unassessable"]) == 1
    assert report["invalid_count"] == 0


def test_paging_reaches_late_invalid_edge_without_any_mutation():
    api = MagicMock()
    api.query.side_effect = [page([edge("8.8.8.8", "8.0.0.0/8", "a")], True, "p2", 2),
                             page([edge("8.8.8.8", "9.9.0.0/16", "b")], total=2)]
    raw = mod.collect(api, "http://opencti:8080", 2)
    assert raw["complete"]
    assert mod.audit(raw)["invalid_count"] == 1
    assert api.query.call_args_list[1].args[1] == {"after": "p2"}
    assert all(call[0] == "query" for call in api.mock_calls)


@pytest.mark.parametrize("failure", ["cap", "cursor", "error", "count", "duplicate"])
def test_partial_inventory_is_never_certified(failure):
    api = MagicMock()
    row = edge("8.8.8.8", "8.0.0.0/8")
    api.query.return_value = page([row], True, "repeat")
    if failure == "error":
        api.query.side_effect = RuntimeError("unavailable")
    if failure == "count":
        api.query.return_value = page([row], total=2)
    if failure == "duplicate":
        api.query.return_value = page([row, row], total=2)
    raw = mod.collect(api, "http://opencti:8080", 1 if failure == "cap" else 3)
    assert not mod.audit(raw)["complete"]
    assert api.query.call_count <= 3
