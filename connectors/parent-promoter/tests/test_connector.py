"""
Tests for connectors/parent-promoter/src/connector.py
"""

from __future__ import annotations

import os
import sys
import types

import pytest

# ── path bootstrap ──────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ── pycti stub ──────────────────────────────────────────────────────────────
_pycti_stub = types.ModuleType("pycti")
_pycti_stub.OpenCTIConnectorHelper = type(
    "OpenCTIConnectorHelper", (), {"__init__": lambda *a, **k: None}
)
sys.modules.setdefault("pycti", _pycti_stub)

from unittest.mock import MagicMock, patch
from connector import ParentPromoterConnector, LABEL_FP_CANDIDATE, LABEL_MALICIOUS_CASCADE

# ── helpers ──────────────────────────────────────────────────────────────────

_ENV = {
    "OPENCTI_URL":   "http://fake:8080",
    "OPENCTI_TOKEN": "fake",
    "CONNECTOR_ID":  "test-id",
    "PROMOTER_MALICIOUS_SCORE_MIN":   "70",
    "PROMOTER_MALICIOUS_CHILD_PCT":   "0.60",
    "PROMOTER_BENIGN_CHILD_PCT":      "0.70",
    "PROMOTER_MIN_CHILDREN":          "3",
    "PROMOTER_MALICIOUS_SCORE":       "80",
    "CONNECTOR_CONFIDENCE_LEVEL":     "75",
}


def _make_connector(extra=None) -> ParentPromoterConnector:
    env = {**_ENV, **(extra or {})}
    with patch.dict(os.environ, env):
        c = ParentPromoterConnector()
    helper = MagicMock()
    helper.api.label.create.return_value = {"id": "lbl-stub"}
    helper.api.stix_cyber_observable.add_label.return_value = True
    helper.api.stix_cyber_observable.update_field.return_value = True
    helper.api.note.create.return_value = {"id": "note-stub"}
    c.helper = helper
    return c


def _obs(entity_id="parent-1", entity_type="IPv4-Addr", value="10.0.0.0/24",
         score=50, labels=None) -> dict:
    return {
        "id": entity_id,
        "entity_type": entity_type,
        "value": value,
        "x_opencti_score": score,
        "objectLabel": [{"value": lbl} for lbl in (labels or [])],
    }


def _rel(child_id: str, child_score=50, child_labels=None) -> dict:
    """Simulate a related-to relationship with embedded child data."""
    return {
        "from": {
            "id": child_id,
            "x_opencti_score": child_score,
            "objectLabel": [{"value": lbl} for lbl in (child_labels or [])],
        }
    }


def _wire(c: ParentPromoterConnector, parent: dict,
          rels: list[dict] | None = None) -> None:
    c.helper.api.stix_cyber_observable.read.return_value = parent
    c.helper.api.stix_core_relationship.list.return_value = rels or []


# ══════════════════════════════════════════════════════════════════════════════
# Skip guards
# ══════════════════════════════════════════════════════════════════════════════

class TestSkipGuards:

    def test_no_entity_id(self):
        c = _make_connector()
        assert "skipped" in c.process_message({"entity_type": "IPv4-Addr"})

    def test_unsupported_type(self):
        c = _make_connector()
        result = c.process_message({"entity_id": "x", "entity_type": "Malware"})
        assert "skipped" in result

    def test_entity_not_found(self):
        c = _make_connector()
        c.helper.api.stix_cyber_observable.read.return_value = None
        result = c.process_message({"entity_id": "x", "entity_type": "IPv4-Addr"})
        assert "skipped" in result

    def test_no_children(self):
        c = _make_connector()
        parent = _obs(score=50)
        _wire(c, parent, rels=[])
        result = c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})
        assert result == "no children"

    def test_insufficient_scored_children(self):
        """< PROMOTER_MIN_CHILDREN scored (score≠50) children → no promotion."""
        c = _make_connector()
        parent = _obs(score=50)
        # 2 scored children < min_children=3
        rels = [_rel("c1", child_score=80), _rel("c2", child_score=80)]
        _wire(c, parent, rels=rels)
        result = c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})
        assert "insufficient" in result


# ══════════════════════════════════════════════════════════════════════════════
# Malicious promotion
# ══════════════════════════════════════════════════════════════════════════════

class TestMaliciousPromotion:

    def test_malicious_promotion_fires_at_threshold(self):
        """60% malicious children → parent score promoted to 80."""
        c = _make_connector()
        parent = _obs(score=50)
        rels = [
            _rel("c1", child_score=80),
            _rel("c2", child_score=80),
            _rel("c3", child_score=80),   # 3/5 = 60% ≥ threshold
            _rel("c4", child_score=30),
            _rel("c5", child_score=15),
        ]
        _wire(c, parent, rels=rels)

        result = c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_cyber_observable.update_field.assert_called_once()
        call_kwargs = c.helper.api.stix_cyber_observable.update_field.call_args
        assert call_kwargs.kwargs["id"] == "parent-1"
        assert "80" in str(call_kwargs.kwargs["input"])
        assert "action" in result

    def test_malicious_promotion_blocked_by_cascade_label(self):
        """Children with malicious-cascade are inferred, not directly assessed — excluded."""
        c = _make_connector()
        parent = _obs(score=50)
        # All 5 children have malicious-cascade (inferred) — none count as malicious
        rels = [_rel(f"c{i}", child_score=80, child_labels=[LABEL_MALICIOUS_CASCADE])
                for i in range(5)]
        _wire(c, parent, rels=rels)

        c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_cyber_observable.update_field.assert_not_called()

    def test_malicious_promotion_not_repeated(self):
        """Idempotent: parent already at promoted score → no update."""
        c = _make_connector()
        parent = _obs(score=80)   # already promoted
        rels = [_rel(f"c{i}", child_score=80) for i in range(5)]
        _wire(c, parent, rels=rels)

        result = c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_cyber_observable.update_field.assert_not_called()
        assert "no actions" in result

    def test_below_threshold_no_promotion(self):
        """50% malicious < 60% threshold → no promotion."""
        c = _make_connector()
        parent = _obs(score=50)
        rels = [
            _rel("c1", child_score=80),
            _rel("c2", child_score=80),   # 2/4 = 50% < 60%
            _rel("c3", child_score=30),
            _rel("c4", child_score=15),
        ]
        _wire(c, parent, rels=rels)

        c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_cyber_observable.update_field.assert_not_called()

    def test_unknown_anchors_excluded_from_denominator(self):
        """Children with score=50 are unknown anchors and excluded from the denominator."""
        c = _make_connector()
        parent = _obs(score=50)
        # 3 malicious + 7 unknown anchors (score=50)
        # Denominator = 3 (scored only) → 3/3 = 100% ≥ 60% → promotes
        rels = (
            [_rel(f"c{i}", child_score=80) for i in range(3)] +
            [_rel(f"u{i}", child_score=50) for i in range(7)]
        )
        _wire(c, parent, rels=rels)

        c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_cyber_observable.update_field.assert_called_once()

    def test_note_created_on_promotion(self):
        c = _make_connector()
        parent = _obs(score=50)
        rels = [_rel(f"c{i}", child_score=80) for i in range(3)]
        _wire(c, parent, rels=rels)

        c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})

        c.helper.api.note.create.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════════
# Benign promotion
# ══════════════════════════════════════════════════════════════════════════════

class TestBenignPromotion:

    def test_benign_promotion_applies_fp_label_and_lowers_score(self):
        """70% fp-candidate children → parent gets fp-candidate + score lowered to 15."""
        c = _make_connector()
        parent = _obs(score=50)
        rels = [
            _rel("c1", child_score=15, child_labels=[LABEL_FP_CANDIDATE]),
            _rel("c2", child_score=15, child_labels=[LABEL_FP_CANDIDATE]),
            _rel("c3", child_score=15, child_labels=[LABEL_FP_CANDIDATE]),   # 3/4 = 75% ≥ 70%
            _rel("c4", child_score=30),
        ]
        _wire(c, parent, rels=rels)

        result = c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})

        label_calls = [kw.kwargs.get("value") for kw in c.helper.api.label.create.call_args_list]
        assert LABEL_FP_CANDIDATE in label_calls
        c.helper.api.stix_cyber_observable.update_field.assert_called()
        assert "action" in result

    def test_benign_promotion_blocked_by_any_malicious_child(self):
        """Even one malicious child blocks benign promotion."""
        c = _make_connector()
        parent = _obs(score=50)
        rels = [
            _rel("c1", child_score=15, child_labels=[LABEL_FP_CANDIDATE]),
            _rel("c2", child_score=15, child_labels=[LABEL_FP_CANDIDATE]),
            _rel("c3", child_score=15, child_labels=[LABEL_FP_CANDIDATE]),
            _rel("c4", child_score=80),   # one malicious child blocks benign
        ]
        _wire(c, parent, rels=rels)

        c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})

        label_calls = [kw.kwargs.get("value") for kw in c.helper.api.label.create.call_args_list]
        assert LABEL_FP_CANDIDATE not in label_calls

    def test_benign_promotion_idempotent_fp_label_already_present(self):
        """Parent already has fp-candidate → label not re-added; score still updated if needed."""
        c = _make_connector()
        parent = _obs(score=50, labels=[LABEL_FP_CANDIDATE])
        rels = [_rel(f"c{i}", child_score=15, child_labels=[LABEL_FP_CANDIDATE])
                for i in range(3)]
        _wire(c, parent, rels=rels)

        c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})

        label_calls = [kw.kwargs.get("value") for kw in c.helper.api.label.create.call_args_list]
        assert label_calls.count(LABEL_FP_CANDIDATE) == 0

    def test_benign_promotion_idempotent_score_already_15(self):
        """Parent score already 15 → score not updated again."""
        c = _make_connector()
        parent = _obs(score=15, labels=[LABEL_FP_CANDIDATE])
        rels = [_rel(f"c{i}", child_score=15, child_labels=[LABEL_FP_CANDIDATE])
                for i in range(3)]
        _wire(c, parent, rels=rels)

        result = c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_cyber_observable.update_field.assert_not_called()
        assert "no actions" in result

    def test_malicious_takes_priority_over_benign(self):
        """Malicious threshold met → malicious promotion, not benign."""
        c = _make_connector()
        parent = _obs(score=50)
        # 3 malicious (direct) + 3 fp → both thresholds met
        # malicious branch (elif) should fire first
        rels = [
            _rel("m1", child_score=80),
            _rel("m2", child_score=80),
            _rel("m3", child_score=80),
            _rel("f1", child_score=15, child_labels=[LABEL_FP_CANDIDATE]),
            _rel("f2", child_score=15, child_labels=[LABEL_FP_CANDIDATE]),
        ]
        _wire(c, parent, rels=rels)

        c.process_message({"entity_id": "parent-1", "entity_type": "IPv4-Addr"})

        update_calls = c.helper.api.stix_cyber_observable.update_field.call_args_list
        assert len(update_calls) == 1
        assert "80" in str(update_calls[0].kwargs["input"])
        label_calls = [kw.kwargs.get("value") for kw in c.helper.api.label.create.call_args_list]
        assert LABEL_FP_CANDIDATE not in label_calls
