from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from review import CommonnessReviewer, HERD_LABEL, reduce_evidence

NOW = datetime(2026, 10, 12, 20, 0, tzinfo=timezone.utc)


def entity(object_id="obs-1", observable_type="Domain-Name", labels=None, score=0):
    return {
        "id": object_id, "entity_type": observable_type, "x_opencti_score": score,
        "objectLabel": [{"id": f"label-{i}", "value": value} for i, value in enumerate(labels or [])],
        "indicators": {"edges": []},
    }


def source_note(source="tenant-01", object_id="obs-1", observable_type="Domain-Name",
                signals=("http",), updated=NOW, note_id=None, **overrides):
    payload = {
        "schema_version": 1, "query_version": "x39.1-commonness-v1",
        "source_id": source, "observable_type": observable_type,
        "qualifying_signals": list(signals),
        "updated_at": updated.isoformat().replace("+00:00", "Z"),
    }
    payload.update(overrides)
    return {
        "id": note_id or f"note-{source}",
        "attribute_abstract": f"vectra-commonness:{source}:digest",
        "content": json.dumps(payload),
        "objects": {"edges": [{"node": {"id": object_id}}]},
    }


def review_note(object_id="obs-1"):
    return {
        "id": "review-1", "attribute_abstract": "vectra-commonness-review:digest",
        "content": "{}", "objects": {"edges": [{"node": {"id": object_id}}]},
    }


def api_for(observables, notes):
    api = MagicMock()
    api.label.list.side_effect = lambda search, first: [
        {"id": f"id-{search}", "value": search}
    ] if search in {"vectra-metadata:common-domain", HERD_LABEL} else []
    api.stix_cyber_observable.list.return_value = {
        "entities": observables, "pagination": {"hasNextPage": False, "endCursor": None},
    }
    api.note.list.return_value = {
        "entities": notes, "pagination": {"hasNextPage": False, "endCursor": None},
    }
    api.label.create.return_value = {"id": "herd-label"}
    api.note.create.return_value = {"id": "review-created"}
    return api


def test_distinct_source_is_one_vote_and_newest_duplicate_wins():
    notes = [
        source_note(signals=("http",), updated=NOW - timedelta(hours=2), note_id="old"),
        source_note(signals=("dns",), updated=NOW - timedelta(hours=1), note_id="new"),
    ]
    plans, metrics = reduce_evidence([entity()], notes, now=NOW, max_age=timedelta(days=2))
    assert plans["obs-1"].source_count == 1
    assert plans["obs-1"].signals == ("dns",)
    assert plans["obs-1"].classification == "source-local"
    assert metrics["duplicates"] == 1


def test_two_sources_make_herd_while_threat_context_coexists():
    plans, metrics = reduce_evidence(
        [entity(score=90)], [source_note("tenant-01"), source_note("tenant-02", signals=("sni",))],
        now=NOW, max_age=timedelta(days=2),
    )
    plan = plans["obs-1"]
    assert plan.source_count == 2
    assert plan.classification == "herd-common"
    assert plan.conflict
    assert "not benignness" in plan.explanation
    assert metrics["herd"] == metrics["conflicts"] == 1


def test_stale_malformed_and_type_mismatch_do_not_vote():
    notes = [
        source_note("tenant-stale", updated=NOW - timedelta(days=3)),
        source_note("tenant-bad", schema_version=2),
        source_note("tenant-ip", observable_type="IPv4-Addr", signals=("m365",)),
    ]
    plans, metrics = reduce_evidence([entity()], notes, now=NOW, max_age=timedelta(days=2))
    assert plans == {}
    assert metrics["stale"] == 1
    assert metrics["malformed"] == 2


def test_freshness_boundary_is_inclusive_and_orphan_is_rejected():
    boundary = source_note("tenant-boundary", updated=NOW - timedelta(days=2))
    orphan = source_note("tenant-orphan", object_id="missing")
    plans, metrics = reduce_evidence([entity()], [boundary, orphan], now=NOW, max_age=timedelta(days=2))
    assert plans["obs-1"].source_count == 1
    assert metrics["malformed"] == 1


def test_bounded_pagination_follows_cursor():
    api = MagicMock()
    api.label.list.side_effect = lambda search, first: [{"id": "source-label", "value": search}] if search == "vectra-metadata:common-domain" else []
    api.stix_cyber_observable.list.side_effect = [
        {"entities": [entity("obs-1")], "pagination": {"hasNextPage": True, "endCursor": "next"}},
        {"entities": [entity("obs-2")], "pagination": {"hasNextPage": False, "endCursor": None}},
    ]
    api.note.list.return_value = {"entities": [], "pagination": {"hasNextPage": False}}
    summary = CommonnessReviewer(api, page_size=1, max_pages=2).run(now=NOW)
    assert summary["complete"] and summary["candidates"] == 2
    assert api.stix_cyber_observable.list.call_args_list[1].kwargs["after"] == "next"


def test_shadow_reports_aggregates_and_performs_no_mutations():
    api = api_for([entity(labels=["vectra-metadata:common-domain"])], [source_note()])
    summary = CommonnessReviewer(api).run(now=NOW)
    assert summary["mode"] == "shadow"
    assert summary["source_local"] == 1
    assert summary["herd"] == summary["projected_writes"] == 0
    assert "tenant-01" not in json.dumps(summary)
    api.stix_cyber_observable.add_label.assert_not_called()
    api.stix_cyber_observable.remove_label.assert_not_called()
    api.note.create.assert_not_called()
    api.stix_domain_object.delete.assert_not_called()


def test_apply_herd_adds_only_owned_label_and_aggregate_note():
    api = api_for(
        [entity(labels=["vectra-metadata:common-domain"])],
        [source_note("tenant-01"), source_note("tenant-02")],
    )
    summary = CommonnessReviewer(api, write=True).run(now=NOW)
    assert summary["herd"] == 1
    api.stix_cyber_observable.add_label.assert_called_once_with(id="obs-1", label_id="herd-label")
    kwargs = api.note.create.call_args.kwargs
    assert kwargs["update"] is True
    assert kwargs["objects"] == ["obs-1"]
    assert "tenant-01" not in kwargs["content"] and "tenant-02" not in kwargs["content"]
    api.stix_cyber_observable.update_field.assert_not_called()


def test_existing_herd_state_is_upserted_without_duplicate_label():
    api = api_for(
        [entity(labels=["vectra-metadata:common-domain", HERD_LABEL])],
        [source_note("tenant-01"), source_note("tenant-02"), review_note()],
    )
    CommonnessReviewer(api, write=True).run(now=NOW)
    api.stix_cyber_observable.add_label.assert_not_called()
    assert api.note.create.call_args.kwargs["stix_id"] == CommonnessReviewer._review_note_id("obs-1")


def test_apply_incomplete_scan_blocks_every_write():
    api = api_for([entity()], [source_note("tenant-01"), source_note("tenant-02")])
    api.stix_cyber_observable.list.return_value = {
        "entities": [entity()], "pagination": {"hasNextPage": True, "endCursor": "next"},
    }
    summary = CommonnessReviewer(api, max_pages=1, write=True).run(now=NOW)
    assert not summary["complete"] and summary["writes_blocked"] == 1
    api.stix_cyber_observable.add_label.assert_not_called()
    api.note.create.assert_not_called()
    api.stix_domain_object.delete.assert_not_called()


def test_complete_stale_cleanup_removes_only_reducer_state():
    item = entity(labels=["vectra-metadata:common-domain", HERD_LABEL])
    herd_label_id = item["objectLabel"][1]["id"]
    api = api_for([item], [
        source_note(updated=NOW - timedelta(days=3)), review_note(),
    ])
    summary = CommonnessReviewer(api, write=True).run(now=NOW)
    api.stix_cyber_observable.remove_label.assert_called_once_with(id="obs-1", label_id=herd_label_id)
    api.stix_domain_object.delete.assert_called_once_with(id="review-1")
    assert summary["labels_removed"] == summary["notes_removed"] == 1
    api.stix_cyber_observable.delete.assert_not_called()


def test_purge_removes_only_reducer_owned_state():
    item = entity(labels=["analyst-label", HERD_LABEL])
    api = api_for([item], [source_note(), review_note()])
    summary = CommonnessReviewer(api, write=True).purge()
    api.stix_cyber_observable.remove_label.assert_called_once_with(
        id="obs-1", label_id=item["objectLabel"][1]["id"],
    )
    api.stix_domain_object.delete.assert_called_once_with(id="review-1")
    assert summary["labels_removed"] == summary["notes_removed"] == 1
