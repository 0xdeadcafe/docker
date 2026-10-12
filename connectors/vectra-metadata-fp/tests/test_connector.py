"""Unit tests for Vectra endpoint-commonness behavior."""
from __future__ import annotations

import json
import os
import sys
import types
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
_pycti = types.ModuleType("pycti")
_pycti.OpenCTIConnectorHelper = type("OpenCTIConnectorHelper", (), {"__init__": lambda self, config: None})
_pycti.OpenCTIApiClient = MagicMock
sys.modules.setdefault("pycti", _pycti)

from metadata_client import QueryResult, VectraMetadataClient
from queries import (
    BATCH_SIZE, DISCOVERY_QUERIES, QUERY_BY_NAME, TARGETED_QUERIES,
    Observation, batches, build_windows, normalize_domain, normalize_ipv4,
)
from connector import (
    LABEL_COMMON_DOMAIN, LABEL_COMMON_IP, LABEL_CONFLICT, LABEL_SHARED_AUTH_IP,
    EvidencePlan, VectraMetadataCommonnessConnector, _is_conflict,
)


class TestNormalization:
    @pytest.mark.parametrize("raw,expected", [
        ("Example.COM.", "example.com"), ("a-b.example.net", "a-b.example.net"),
        ("printer.local", None), ("nodot", None), ("bad_domain.com", None),
        ("1.2.3.4", None),
    ])
    def test_domain(self, raw, expected):
        assert normalize_domain(raw) == expected

    @pytest.mark.parametrize("raw,expected", [
        ("8.8.8.8", "8.8.8.8"), ("10.0.0.1", None),
        ("127.0.0.1", None), ("1.2.3.0/24", None), ("example.com", None),
    ])
    def test_ipv4(self, raw, expected):
        assert normalize_ipv4(raw) == expected

    def test_batches_deduplicate_and_sort(self):
        assert list(batches(["b", "a", "a"], 2)) == [["a", "b"]]

    @pytest.mark.parametrize("size", [0, BATCH_SIZE + 1])
    def test_batches_reject_unsafe_size(self, size):
        with pytest.raises(ValueError):
            list(batches(["a"], size))


class TestQueries:
    @pytest.fixture
    def windows(self):
        return build_windows(datetime(2026, 10, 12, 18, 0, tzinfo=timezone.utc))

    def test_three_fixed_half_open_windows(self, windows):
        assert [w.id for w in windows] == ["w1", "w2", "w3"]
        assert all(windows[i].end == windows[i + 1].start for i in range(2))
        assert (windows[-1].end - windows[0].start).days == 30

    def test_invalid_lookback_rejected(self):
        with pytest.raises(ValueError):
            build_windows(lookback_days=31)

    @pytest.mark.parametrize("query", TARGETED_QUERIES, ids=lambda q: q.name)
    def test_targeted_has_partition_event_window_and_limit(self, query, windows):
        candidate = "example.com" if query.observable_type == "Domain-Name" else "8.8.8.8"
        sql = query.build_targeted([candidate], windows)
        assert "WHERE dt >=" in sql
        assert f"AND {query.event_time} >=" in sql
        assert " IN (" in sql
        assert "LIMIT 500" in sql
        assert "w1" in sql and "w2" in sql and "w3" in sql

    def test_targeted_rejects_more_than_50(self, windows):
        values = [f"a{i}.example.com" for i in range(51)]
        with pytest.raises(ValueError):
            QUERY_BY_NAME["dns"].build_targeted(values, windows)

    def test_discovery_allowlist(self, windows):
        assert {q.name for q in DISCOVERY_QUERIES} == {"http", "m365"}
        for name in ("dns", "sni", "isession"):
            with pytest.raises(ValueError, match="unsupported"):
                QUERY_BY_NAME[name].build_discovery(windows)

    def test_discovery_thresholds_and_cap(self, windows):
        assert ">= 10" in QUERY_BY_NAME["http"].build_discovery(windows)
        assert "status_code BETWEEN 200 AND 399" in QUERY_BY_NAME["http"].build_discovery(windows)
        assert ">= 3" in QUERY_BY_NAME["m365"].build_discovery(windows)
        assert "status.error_code = 0" in QUERY_BY_NAME["m365"].build_discovery(windows)
        with pytest.raises(ValueError):
            QUERY_BY_NAME["http"].build_discovery(windows, 501)

    def test_observations_drop_invalid_rows(self):
        rows = [
            {"candidate": "EXAMPLE.COM.", "window_id": "w2", "breadth": "10", "event_count": 20},
            {"candidate": "internal.local", "window_id": "w2", "breadth": 99},
            {"candidate": "ok.example", "window_id": "bad", "breadth": 99},
        ]
        observations = QUERY_BY_NAME["dns"].observations(rows)
        assert [(o.value, o.window_id, o.breadth) for o in observations] == [("example.com", "w2", 10)]


class TestStructuredMetadataResult:
    def test_query_result_distinguishes_zero_partial_and_error(self):
        assert QueryResult("zero").ok
        assert not QueryResult("partial", partial=True).ok
        assert not QueryResult("error", error_kind="sql_error").ok

    def test_native_rows_shapes(self):
        assert VectraMetadataClient._rows_from_native({"data": [{"a": 1}]}) == [{"a": 1}]
        assert VectraMetadataClient._rows_from_native({"results": {"rows": [{"b": 2}]}}) == [{"b": 2}]
        assert VectraMetadataClient._rows_from_native({}) == []

    def test_native_pagination_complete(self):
        client = object.__new__(VectraMetadataClient)
        client._page_size = 2
        client._max_pages = 10
        client._headers = MagicMock(return_value={})
        response = MagicMock()
        response.json.return_value = {"data": [{"x": 3}]}
        client._request = MagicMock(return_value=(response, 0))
        result = client._collect_native_pages("url", {
            "data": [{"x": 1}, {"x": 2}], "meta": {"num_rows_available": 3, "page_size": 2}
        }, 0)
        assert result.status == "ok"
        assert result.rows == [{"x": 1}, {"x": 2}, {"x": 3}]
        assert result.pages_fetched == 2

    def test_native_pagination_marks_max_page_partial(self):
        client = object.__new__(VectraMetadataClient)
        client._page_size = 1
        client._max_pages = 1
        result = client._collect_native_pages("url", {
            "data": [{"x": 1}], "meta": {"num_rows_available": 3, "page_size": 1}
        }, 0)
        assert result.status == "partial"
        assert result.partial and result.truncated
        assert result.available_rows == 3


_BASE_ENV = {
    "OPENCTI_URL": "http://fake:8080", "OPENCTI_TOKEN": "fake", "CONNECTOR_ID": "test-id",
    "VECTRA_COMMONNESS_SOURCE_ID": "tenant-01", "VECTRA_COMMONNESS_WRITE": "false",
    "VECTRA_COMMONNESS_BATCH_SIZE": "50", "VECTRA_COMMONNESS_PAGE_SIZE": "100",
    "VECTRA_COMMONNESS_DISCOVERY_LIMIT": "500", "VECTRA_COMMONNESS_CREATION_LIMIT": "100",
    "VECTRA_COMMONNESS_LOOKBACK_DAYS": "30", "VECTRA_COMMONNESS_INTERVAL_SEC": "86400",
}


def make_connector(extra=None):
    env = {**_BASE_ENV, **(extra or {})}
    with patch.dict(os.environ, env, clear=True):
        connector = VectraMetadataCommonnessConnector()
    connector.helper = MagicMock()
    connector.helper.api.label.create.side_effect = lambda **kwargs: {"id": "label-" + kwargs["value"], **kwargs}
    connector.helper.api.stix_cyber_observable.add_label.return_value = True
    connector.helper.api.note.create.return_value = {"id": "note-1"}
    return connector


def observation(signal="http", value="example.com", window="w1", breadth=None):
    query = QUERY_BY_NAME[signal]
    return Observation(signal, query.observable_type, value, window,
                       query.threshold if breadth is None else breadth, 20, "first", "last")


class TestConfiguration:
    def test_shadow_is_default(self):
        assert not make_connector().write_enabled

    @pytest.mark.parametrize("flag", ["VECTRA_FP_APPLY_FP_CANDIDATE", "VECTRA_FP_STRONG_RAW_IPS"])
    def test_legacy_promotion_flags_fail_closed(self, flag):
        with patch.dict(os.environ, {**_BASE_ENV, flag: "true"}, clear=True):
            with pytest.raises(ValueError, match="legacy"):
                VectraMetadataCommonnessConnector()

    def test_source_id_must_be_opaque(self):
        with patch.dict(os.environ, {**_BASE_ENV, "VECTRA_COMMONNESS_SOURCE_ID": "customer name"}, clear=True):
            with pytest.raises(ValueError, match="SOURCE_ID"):
                VectraMetadataCommonnessConnector()


class TestEvidencePlans:
    def test_requires_two_qualifying_windows(self):
        one = EvidencePlan("Domain-Name", "example.com", [observation(window="w1")])
        two = EvidencePlan("Domain-Name", "example.com", [observation(window="w1"), observation(window="w2")])
        assert not one.qualifies
        assert two.qualifies
        assert two.qualifying_signals == {"http"}

    def test_low_breadth_window_does_not_count(self):
        plan = EvidencePlan("Domain-Name", "example.com", [
            observation(window="w1"), observation(window="w2", breadth=9),
        ])
        assert not plan.qualifies

    def test_sources_count_once_per_window(self):
        plan = EvidencePlan("Domain-Name", "example.com", [
            observation(window="w1"), observation(window="w1", breadth=50),
        ])
        assert not plan.qualifies


class TestOpenCTIPaging:
    def test_page_continues_and_wraps(self):
        connector = make_connector()
        connector.helper.api.stix_cyber_observable.list.side_effect = [
            {"entities": [{"id": "1", "entity_type": "Domain-Name", "observable_value": "A.COM"}],
             "pagination": {"hasNextPage": True, "endCursor": "next"}},
            {"entities": [{"id": "2", "entity_type": "Domain-Name", "observable_value": "b.com"}],
             "pagination": {"hasNextPage": False, "endCursor": "done"}},
        ]
        first, wrapped1 = connector._observable_page("Domain-Name")
        second, wrapped2 = connector._observable_page("Domain-Name")
        assert first[0]["observable_value"] == "a.com"
        assert connector.helper.api.stix_cyber_observable.list.call_args_list[1].kwargs["after"] == "next"
        assert not wrapped1 and wrapped2
        assert connector._cursors["Domain-Name"] is None

    def test_invalid_cursor_resets_without_unbounded_retry(self):
        connector = make_connector()
        connector._cursors["IPv4-Addr"] = "stale"
        connector.helper.api.stix_cyber_observable.list.side_effect = RuntimeError("bad cursor")
        assert connector._observable_page("IPv4-Addr") == ([], False)
        assert connector._cursors["IPv4-Addr"] is None


class TestSafetyAndPersistence:
    def test_conflict_detection(self):
        assert _is_conflict({"x_opencti_score": 70})
        assert _is_conflict({"objectLabel": [{"value": "sinkholed"}]})
        assert _is_conflict({"indicators": {"edges": [{"node": {"id": "i"}}]}})
        assert not _is_conflict({"x_opencti_score": 0, "objectLabel": []})

    def test_note_id_is_source_isolated_and_deterministic(self):
        one = VectraMetadataCommonnessConnector._note_id("tenant-01", "Domain-Name", "example.com")
        assert one == VectraMetadataCommonnessConnector._note_id("tenant-01", "Domain-Name", "example.com")
        assert one != VectraMetadataCommonnessConnector._note_id("tenant-02", "Domain-Name", "example.com")

    def test_upsert_uses_stable_id_and_aggregate_only_content(self):
        connector = make_connector({"VECTRA_COMMONNESS_WRITE": "true"})
        plan = EvidencePlan("Domain-Name", "example.com", [observation(window="w1"), observation(window="w2")])
        connector._upsert_evidence({"id": "obs-1"}, plan)
        kwargs = connector.helper.api.note.create.call_args.kwargs
        assert kwargs["update"] is True
        assert kwargs["stix_id"].startswith("note--")
        payload = json.loads(kwargs["content"])
        assert payload["source_id"] == "tenant-01"
        assert "example.com" not in kwargs["content"]
        assert set(payload) <= {"schema_version", "query_version", "source_id", "observable_type", "signals", "qualifying_signals", "discovery", "lookback_days", "updated_at"}

    def test_write_plan_preserves_score_and_adds_conflict(self):
        connector = make_connector({"VECTRA_COMMONNESS_WRITE": "true"})
        entity = {"id": "obs", "entity_type": "Domain-Name", "observable_value": "example.com",
                  "x_opencti_score": 90, "objectLabel": []}
        plan = EvidencePlan("Domain-Name", "example.com", [observation(window="w1"), observation(window="w2")], entity=entity)
        assert connector._write_plan(plan, False) == "updated"
        labels = [call.kwargs["value"] for call in connector.helper.api.label.create.call_args_list]
        assert LABEL_COMMON_DOMAIN in labels and LABEL_CONFLICT in labels
        connector.helper.api.stix_cyber_observable.update_field.assert_not_called()
        connector.helper.api.stix_cyber_observable.create.assert_not_called()

    def test_create_has_no_score_or_indicator(self):
        connector = make_connector({"VECTRA_COMMONNESS_WRITE": "true"})
        connector.helper.api.stix_cyber_observable.list.return_value = []
        connector.helper.api.stix_cyber_observable.create.return_value = {"id": "new", "entity_type": "IPv4-Addr", "observable_value": "8.8.8.8"}
        plan = EvidencePlan("IPv4-Addr", "8.8.8.8", [
            observation("m365", "8.8.8.8", "w1"), observation("m365", "8.8.8.8", "w2")
        ], discovery=True)
        assert connector._write_plan(plan, True) == "created"
        data = connector.helper.api.stix_cyber_observable.create.call_args.kwargs["observableData"]
        assert "x_opencti_score" not in data
        assert data["type"] == "ipv4-addr"
        labels = [call.kwargs["value"] for call in connector.helper.api.label.create.call_args_list]
        assert LABEL_SHARED_AUTH_IP in labels
        assert all("benign" not in label and label != "fp-candidate" for label in labels)

    def test_shadow_cycle_never_mutates_opencti(self):
        connector = make_connector()
        page = {"entities": [], "pagination": {"hasNextPage": False}}
        connector.helper.api.stix_cyber_observable.list.side_effect = [page, page]
        client = MagicMock()
        client.execute_result.return_value = QueryResult("zero")
        summary = connector._run_cycle(client)
        assert summary["mode"] == "shadow"
        connector.helper.api.stix_cyber_observable.create.assert_not_called()
        connector.helper.api.stix_cyber_observable.add_label.assert_not_called()
        connector.helper.api.note.create.assert_not_called()
        connector.helper.api.stix_domain_object.delete.assert_not_called()

    def test_stale_cleanup_waits_for_complete_sweep(self):
        connector = make_connector({"VECTRA_COMMONNESS_WRITE": "true"})
        connector._wrapped = {"Domain-Name": True, "IPv4-Addr": True}
        connector._sweep_complete = False
        assert connector._reconcile_stale() == 0
        connector.helper.api.note.list.assert_not_called()


class TestLegacyAudit:
    def test_apply_touches_only_evidence_backed_legacy_labels(self):
        import importlib.util
        script = os.path.join(os.path.dirname(__file__), "..", "scripts", "audit_legacy_state.py")
        spec = importlib.util.spec_from_file_location("legacy_audit", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        api = MagicMock()
        api.note.list.return_value = [
            {"id": "note-1", "attribute_abstract": "Vectra FP: old", "content": "",
             "objects": {"edges": [{"node": {"id": "owned"}}]}},
        ]
        api.label.list.return_value = [
            {"id": "benign", "value": "vectra-metadata-benign"},
            {"id": "manual", "value": "fp-candidate"},
        ]
        api.stix_cyber_observable.list.return_value = [
            {"id": "owned", "objectLabel": [{"id": "benign", "value": "vectra-metadata-benign"}]},
            {"id": "not-owned", "objectLabel": [{"id": "benign", "value": "vectra-metadata-benign"}]},
        ]
        report = module.run(api, apply=True)
        api.stix_cyber_observable.remove_label.assert_called_once_with(id="owned", label_id="benign")
        api.stix_domain_object.delete.assert_called_once_with(id="note-1")
        assert report["generic_fp_candidate_touched"] == 0
        assert report["scores_changed"] == 0


    def test_source_deletion_retains_labels_when_other_source_exists(self):
        import importlib.util
        script = os.path.join(os.path.dirname(__file__), "..", "scripts", "delete_source_evidence.py")
        spec = importlib.util.spec_from_file_location("source_delete", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        api = MagicMock()
        api.label.list.return_value = [{"id": "label", "value": "vectra-metadata:common-ip"}]
        api.stix_cyber_observable.list.return_value = [{"id": "obs"}]
        api.note.list.return_value = [
            {"id": "n1", "attribute_abstract": "vectra-commonness:tenant-01:a", "objects": {"edges": [{"node": {"id": "obs"}}]}},
            {"id": "n2", "attribute_abstract": "vectra-commonness:tenant-02:b", "objects": {"edges": [{"node": {"id": "obs"}}]}},
        ]
        report = module.run(api, "tenant-01", apply=True)
        api.stix_cyber_observable.remove_label.assert_not_called()
        api.stix_domain_object.delete.assert_called_once_with(id="n1")
        assert report["evidence_records"] == 1
        assert report["observables_deleted"] == 0


class TestDiscoveryCap:
    def test_cycle_selects_at_most_100_missing_in_deterministic_order(self):
        connector = make_connector({"VECTRA_COMMONNESS_WRITE": "true"})
        connector.helper.api.stix_cyber_observable.list.side_effect = [
            {"entities": [], "pagination": {"hasNextPage": True, "endCursor": "d"}},
            {"entities": [], "pagination": {"hasNextPage": True, "endCursor": "i"}},
        ]
        rows = []
        for i in range(105):
            for window in ("w1", "w2"):
                rows.append({"candidate": f"a{i:03}.example.com", "window_id": window,
                             "breadth": 10, "event_count": 10})
        client = MagicMock()
        client.execute_result.side_effect = [QueryResult("ok", rows), QueryResult("zero")]
        connector._find_observable = MagicMock(return_value=None)
        connector._write_plan = MagicMock(return_value="created")
        summary = connector._run_cycle(client)
        allowed = [call.args[1] for call in connector._write_plan.call_args_list]
        assert sum(allowed) == 100
        assert summary["missing"] == 105
