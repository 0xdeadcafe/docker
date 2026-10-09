"""Focused tests for the trust-cluster label cleanup planner."""

import importlib.util
from pathlib import Path


_SCRIPT = Path(__file__).parents[1] / "scripts" / "cleanup_structural_labels.py"
_SPEC = importlib.util.spec_from_file_location("cleanup_structural_labels", _SCRIPT)
_mod = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader
_SPEC.loader.exec_module(_mod)


def _ref(source_id: str, label_id: str, label_value: str = "trust-cluster:example.com"):
    return {
        "relationship_id": f"rel-{source_id}-{label_id}",
        "source_id": source_id,
        "source_value": source_id,
        "source_types": ["Domain-Name", "Stix-Cyber-Observable"],
        "label_id": label_id,
        "label_value": label_value,
    }


def test_cleanup_plan_deletes_only_unreferenced_structural_definitions():
    labels = {
        "orphan": "trust-cluster:orphan.example",
        "used": "trust-cluster:used.example",
        "state": "trust-cluster:fp-candidate",
        "owner": "trust-cluster:asn-owner:EXAMPLE",
        "profile": "trust-cluster:tls-profile:t13d1516h2",
    }
    plan = _mod.label_cleanup_plan(labels, [_ref("domain-1", "used")])

    assert [row["label_id"] for row in plan["orphaned"]] == ["orphan"]
    assert {row["label_id"] for row in plan["protected"]} == {"state", "owner", "profile"}
    assert [row["label_id"] for row in plan["referenced"]] == ["used"]
    assert plan["dangling"] == []


def test_referenced_manual_label_is_preserved_and_dangling_ref_is_reported():
    labels = {"used": "trust-cluster:manual.example"}
    refs = [_ref("domain-1", "used"), _ref("domain-2", "missing")]
    plan = _mod.label_cleanup_plan(labels, refs)

    assert plan["orphaned"] == []
    assert [row["label_id"] for row in plan["referenced"]] == ["used"]
    assert [row["label_id"] for row in plan["dangling"]] == ["missing"]


def test_successful_structural_relation_removal_makes_definition_deletable():
    labels = {"label-1": "trust-cluster:parent.example"}
    refs = [_ref("child-1", "label-1", "trust-cluster:parent.example")]
    rels = [{
        "from": {"id": "child-1", "value": "host.parent.example"},
        "to": {"id": "parent-1", "value": "parent.example"},
        "label_value": "trust-cluster:parent.example",
    }]

    removals = _mod.removable_associations(rels, labels, refs)
    assert [(row["observable_id"], row["side"]) for row in removals] == [("child-1", "from")]

    removed_pairs = {(row["observable_id"], row["label_id"]) for row in removals}
    plan = _mod.label_cleanup_plan(labels, refs, removed_pairs)
    assert [row["label_id"] for row in plan["orphaned"]] == ["label-1"]


def test_structural_association_without_equivalent_graph_edge_is_not_removed():
    labels = {"label-1": "trust-cluster:parent.example"}
    refs = [_ref("unrelated-1", "label-1", "trust-cluster:parent.example")]
    rels = [{
        "from": {"id": "child-1", "value": "host.parent.example"},
        "to": {"id": "parent-1", "value": "parent.example"},
        "label_value": "trust-cluster:parent.example",
    }]

    assert _mod.removable_associations(rels, labels, refs) == []
    assert _mod.label_cleanup_plan(labels, refs)["orphaned"] == []
