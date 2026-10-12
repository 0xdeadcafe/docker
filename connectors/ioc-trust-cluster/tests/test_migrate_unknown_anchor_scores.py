"""Focused safety tests for legacy UNKNOWN-anchor score migration."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from migrate_unknown_anchor_scores import ineligible_reason


def _anchor(**overrides):
    observable = {
        "id": "anchor-1",
        "entity_type": "IPv4-Addr",
        "observable_value": "115.48.0.0/12",
        "x_opencti_score": 50,
        "x_opencti_description": (
            "Auto-created trust-cluster anchor (IPv4-Addr: 115.48.0.0/12). "
            "UNKNOWN until a feed connector assigns a real score."
        ),
        "objectLabel": [],
        "indicators": {"edges": []},
        "externalReferences": {"edges": []},
        "createdBy": None,
    }
    observable.update(overrides)
    return observable


def test_unassessed_synthetic_score_50_anchor_is_eligible():
    assert ineligible_reason(_anchor()) is None


def test_real_or_changed_observables_are_protected():
    assert ineligible_reason(_anchor(x_opencti_score=80)) == "score_changed"
    assert ineligible_reason(_anchor(objectLabel=[{"id": "label-1"}])) == "has_labels"
    assert ineligible_reason(_anchor(indicators={"edges": [{"node": {"id": "indicator-1"}}]})) == "has_indicators"
    assert ineligible_reason(_anchor(externalReferences={"edges": [{"node": {"id": "ref-1"}}]})) == "has_external_references"
    assert ineligible_reason(_anchor(createdBy={"id": "identity-1"})) == "has_creator"


def test_score_50_observable_without_exact_connector_marker_is_protected():
    assert ineligible_reason(_anchor(x_opencti_description="analyst supplied")) == "not_synthetic_anchor"
