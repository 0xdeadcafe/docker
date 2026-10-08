"""
Unit tests for the vectra-metadata-fp connector.

Covers:
  - IOC validation helpers (no network required)
  - SQL generation (parameter substitution)
  - IOC extraction from sample result rows (each of the 6 queries)
  - resp_domains array normalisation
  - Metadata client row-extraction helpers (no network required)
"""

from __future__ import annotations

import json
import os
import sys
import types

import pytest

# ── path bootstrap (src/ is not a package; tests run from connector root) ──────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# ── pycti stub: prevents FastAPI init crash when connector.py is imported ──────
_pycti_stub = types.ModuleType("pycti")
_pycti_stub.OpenCTIConnectorHelper = type("OpenCTIConnectorHelper", (), {"__init__": lambda *a, **k: None})
sys.modules.setdefault("pycti", _pycti_stub)

from queries import (
    ALL_QUERIES,
    BENIGN_BEACON_TYPES,
    IOCEntry,
    _is_private_ip,
    _is_valid_domain,
    _is_valid_ipv4,
    _parse_resp_domains,
)
from metadata_client import VectraMetadataClient


# ══════════════════════════════════════════════════════════════════════════════
# Validator helpers
# ══════════════════════════════════════════════════════════════════════════════

class TestIsPrivateIp:
    def test_rfc1918_10(self):       assert _is_private_ip("10.0.0.1")
    def test_rfc1918_172(self):      assert _is_private_ip("172.16.0.1")
    def test_rfc1918_192(self):      assert _is_private_ip("192.168.1.1")
    def test_loopback(self):         assert _is_private_ip("127.0.0.1")
    def test_link_local(self):       assert _is_private_ip("169.254.0.1")
    def test_public_ip(self):        assert not _is_private_ip("8.8.8.8")
    def test_public_ip2(self):       assert not _is_private_ip("1.1.1.1")
    def test_invalid_string(self):   assert _is_private_ip("not-an-ip")


class TestIsValidIpv4:
    def test_valid_public(self):     assert _is_valid_ipv4("1.2.3.4")
    def test_valid_public2(self):    assert _is_valid_ipv4("1.1.1.1")
    def test_private(self):          assert not _is_valid_ipv4("10.0.0.1")
    def test_loopback(self):         assert not _is_valid_ipv4("127.0.0.1")
    def test_cidr_rejected(self):    assert not _is_valid_ipv4("1.2.3.0/24")
    def test_empty(self):            assert not _is_valid_ipv4("")
    def test_domain(self):           assert not _is_valid_ipv4("evil.com")
    def test_ipv6(self):             assert not _is_valid_ipv4("::1")


class TestIsValidDomain:
    def test_valid(self):            assert _is_valid_domain("google.com")
    def test_valid_sub(self):        assert _is_valid_domain("api.stripe.com")
    def test_valid_deep(self):       assert _is_valid_domain("a.b.c.example.io")
    def test_arpa(self):             assert not _is_valid_domain("1.0.0.127.in-addr.arpa")
    def test_local(self):            assert not _is_valid_domain("printer.local")
    def test_internal(self):         assert not _is_valid_domain("dc01.internal")
    def test_corp(self):             assert not _is_valid_domain("srv.corp")
    def test_too_short(self):        assert not _is_valid_domain("ab")
    def test_no_dot(self):           assert not _is_valid_domain("nodot")
    def test_empty(self):            assert not _is_valid_domain("")
    def test_single_label(self):     assert not _is_valid_domain("localhost")
    def test_hyphen_ok(self):        assert _is_valid_domain("my-service.example.com")


class TestParseRespDomains:
    def test_none(self):             assert _parse_resp_domains(None) == []
    def test_empty_str(self):        assert _parse_resp_domains("") == []
    def test_single_str(self):       assert _parse_resp_domains("google.com") == ["google.com"]
    def test_list(self):             assert _parse_resp_domains(["a.com", "b.com"]) == ["a.com", "b.com"]
    def test_json_str(self):
        encoded = json.dumps(["x.com", "y.com"])
        assert _parse_resp_domains(encoded) == ["x.com", "y.com"]
    def test_list_with_none(self):
        assert _parse_resp_domains([None, "ok.com", ""]) == ["ok.com"]


# ══════════════════════════════════════════════════════════════════════════════
# SQL generation
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def default_sql_params():
    return dict(days=30, host_threshold=10, user_threshold=20, max_results=500)


class TestSqlGeneration:
    @pytest.mark.parametrize("qdef", ALL_QUERIES, ids=lambda q: q.name)
    def test_no_raw_placeholders(self, qdef, default_sql_params):
        sql = qdef.build_sql(**default_sql_params)
        assert '{' not in sql, f"Unresolved placeholder in {qdef.name}"
        assert '}' not in sql, f"Unresolved placeholder in {qdef.name}"

    @pytest.mark.parametrize("qdef", ALL_QUERIES, ids=lambda q: q.name)
    def test_contains_select(self, qdef, default_sql_params):
        sql = qdef.build_sql(**default_sql_params)
        assert sql.strip().upper().startswith("SELECT")

    @pytest.mark.parametrize("qdef", ALL_QUERIES, ids=lambda q: q.name)
    def test_contains_limit(self, qdef, default_sql_params):
        sql = qdef.build_sql(**default_sql_params)
        assert "LIMIT 500" in sql

    @pytest.mark.parametrize("qdef", ALL_QUERIES, ids=lambda q: q.name)
    def test_contains_dt_prune(self, qdef, default_sql_params):
        sql = qdef.build_sql(**default_sql_params)
        assert "dt" in sql.lower(), f"{qdef.name} missing dt partition prune"

    def test_beacon_uses_first_event_time(self, default_sql_params):
        beacon_q = next(q for q in ALL_QUERIES if q.name == "benign_beacons")
        sql = beacon_q.build_sql(**default_sql_params)
        assert "first_event_time" in sql
        # beacon must NOT filter on plain 'timestamp' for event time
        # (it still uses dt for partition pruning)
        lines = [l.strip() for l in sql.splitlines()]
        ts_filters = [l for l in lines if "timestamp" in l.lower()
                      and "between" in l.lower()]
        assert not ts_filters, (
            "benign_beacons should NOT use timestamp BETWEEN — "
            "use first_event_time instead"
        )

    def test_isession_uses_local_orig_resp(self, default_sql_params):
        q = next(q for q in ALL_QUERIES if q.name == "broad_reach_ips")
        sql = q.build_sql(**default_sql_params)
        assert "local_resp" in sql
        assert "local_orig" in sql

    def test_isession_uses_orig_ip_bytes(self, default_sql_params):
        q = next(q for q in ALL_QUERIES if q.name == "broad_reach_ips")
        sql = q.build_sql(**default_sql_params)
        assert "orig_ip_bytes" in sql
        assert "resp_ip_bytes" in sql
        # Must NOT reference bare 'orig_bytes' as a standalone column name
        import re as _re
        bare_refs = _re.findall(r'\borig_bytes\b', sql)
        assert not bare_refs, f"bare orig_bytes found: {bare_refs}"

    def test_isession_breadth_grouped_by_ip_only(self, default_sql_params):
        """vs1.1: ports/domains/services must not split IP breadth."""
        q = next(q for q in ALL_QUERIES if q.name == "broad_reach_ips")
        sql = q.build_sql(**default_sql_params)
        assert "GROUP BY id.resp_h\n" in sql
        assert "GROUP BY id.resp_h, resp_domain, id.resp_p, service" not in sql
        assert "COUNT(DISTINCT resp_domain)" in sql
        assert "COUNT(DISTINCT id.resp_p)" in sql
        assert "COUNT(DISTINCT service)" in sql

    def test_no_joins_or_ctes(self, default_sql_params):
        for qdef in ALL_QUERIES:
            sql = qdef.build_sql(**default_sql_params).upper()
            assert " JOIN " not in sql, f"{qdef.name} contains JOIN"
            assert sql.strip().startswith("SELECT"), f"{qdef.name} starts with CTE/WITH"

    def test_dns_filters_private_answers(self, default_sql_params):
        q = next(q for q in ALL_QUERIES if q.name == "broad_reach_dns")
        sql = q.build_sql(**default_sql_params)
        # Filter must use HAVING (post-GROUP BY) so CNAME-only rows can't sneak
        # an internal hostname through when its sibling rows resolve to private IPs.
        assert "HAVING" in sql
        assert "any_match" in sql
        assert "SUM" in sql
        # RFC1918 ranges expressed as character-class [.] to avoid lambda escape issues
        assert "10[.]" in sql
        assert "192[.]168[.]" in sql
        assert "172[.]" in sql

    def test_tls_sni_filters_private_resp_h(self, default_sql_params):
        q = next(q for q in ALL_QUERIES if q.name == "broad_reach_tls_sni")
        sql = q.build_sql(**default_sql_params)
        assert "REGEXP_LIKE" in sql
        assert "id.resp_h" in sql
        assert "10\\." in sql

    def test_http_filters_private_resp_h(self, default_sql_params):
        q = next(q for q in ALL_QUERIES if q.name == "broad_reach_http")
        sql = q.build_sql(**default_sql_params)
        assert "REGEXP_LIKE" in sql
        assert "id.resp_h" in sql

    def test_http_normalizes_host_port_before_grouping(self, default_sql_params):
        """vs1.2: example.com:80 and example.com:8080 share one breadth group."""
        q = next(q for q in ALL_QUERIES if q.name == "broad_reach_http")
        sql = q.build_sql(**default_sql_params)
        assert "REGEXP_REPLACE(host, ':[0-9]+$', '')" in sql
        assert "GROUP BY CASE" in sql
        assert "GROUP BY host" not in sql

    def test_beacons_filters_private_resp_h(self, default_sql_params):
        q = next(q for q in ALL_QUERIES if q.name == "benign_beacons")
        sql = q.build_sql(**default_sql_params)
        assert "REGEXP_LIKE" in sql
        assert "id.resp_h" in sql

    def test_isession_already_uses_local_resp(self, default_sql_params):
        """Q1 uses Vectra's authoritative local_resp flag — no REGEXP needed."""
        q = next(q for q in ALL_QUERIES if q.name == "broad_reach_ips")
        sql = q.build_sql(**default_sql_params)
        assert "local_resp" in sql
        assert "local_orig" in sql

    # ── Concern 3: Q5 denylist → safelist ──────────────────────────────────────────────────

    def test_beacon_uses_safelist_not_denylist(self, default_sql_params):
        """
        Q5 must use IN (safelist) not NOT IN (denylist) for beacon_type so that
        future Vectra malicious beacon types are excluded automatically.
        """
        q = next(q for q in ALL_QUERIES if q.name == "benign_beacons")
        sql = q.build_sql(**default_sql_params)
        upper = sql.upper()
        assert "BEACON_TYPE IN" in upper, (
            "Q5 must use IN (safelist) — denylist (NOT IN) silently passes "
            "any new Vectra malicious beacon_type values"
        )
        assert "BEACON_TYPE NOT IN" not in upper

    def test_beacon_safelist_contains_all_canonical_types(self, default_sql_params):
        """
        Every entry in BENIGN_BEACON_TYPES must appear literally in the Q5 SQL
        so the constant and the SQL template stay in sync.
        """
        q = next(q for q in ALL_QUERIES if q.name == "benign_beacons")
        sql = q.build_sql(**default_sql_params)
        for btype in BENIGN_BEACON_TYPES:
            assert f"'{btype}'" in sql, (
                f"BENIGN_BEACON_TYPES entry '{btype}' is missing from the "
                "Q5 SQL safelist — update the SQL to match the constant"
            )

    def test_beacon_breadth_not_split_by_service_or_beacon_type(self, default_sql_params):
        """vs1.3: Q5 breadth is per emitted destination, not service/type shard."""
        q = next(q for q in ALL_QUERIES if q.name == "benign_beacons")
        sql = q.build_sql(**default_sql_params)
        assert "GROUP BY resp_domains, id.resp_h" in sql
        assert "GROUP BY resp_domains, id.resp_h, service, beacon_type" not in sql
        assert "COUNT(DISTINCT service)" in sql
        assert "COUNT(DISTINCT beacon_type)" in sql

    # ── Concern 5: Q6 invalid column name ──────────────────────────────────────────────

    def test_m365_signins_uses_timestamp_for_first_last_seen(self, default_sql_params):
        """
        Q6 must use the standard 'timestamp' column for MIN/MAX aggregations.
        'created_date_type' is not a valid column in the M365 signins schema
        and would cause every Q6 execution to fail silently with NULL values
        or a hard query error depending on the Trino deployment.
        """
        q = next(q for q in ALL_QUERIES if q.name == "shared_auth_ips")
        sql = q.build_sql(**default_sql_params)
        assert "created_date_type" not in sql, (
            "Q6 must not reference created_date_type — use timestamp instead"
        )
        assert "MIN(timestamp)" in sql
        assert "MAX(timestamp)" in sql


# ══════════════════════════════════════════════════════════════════════════════
# IOC extraction — Q1: broad_reach_ips
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def q_broad_reach_ips():
    return next(q for q in ALL_QUERIES if q.name == "broad_reach_ips")


class TestExtractBroadReachIps:
    def test_valid_public_ip(self, q_broad_reach_ips):
        rows = [{"resp_ip": "8.8.8.8", "resp_domain": "dns.google",
                 "resp_port": 443, "service": "ssl",
                 "src_host_count": 47, "session_count": 1000}]
        entries = list(q_broad_reach_ips.extract_iocs(rows))
        assert len(entries) == 1
        assert entries[0].ioc_type == "IPv4-Addr"
        assert entries[0].value == "8.8.8.8"
        assert entries[0].breadth == 47

    def test_private_ip_skipped(self, q_broad_reach_ips):
        rows = [{"resp_ip": "192.168.1.1", "src_host_count": 50}]
        assert list(q_broad_reach_ips.extract_iocs(rows)) == []

    def test_empty_ip_skipped(self, q_broad_reach_ips):
        rows = [{"resp_ip": "", "src_host_count": 20}]
        assert list(q_broad_reach_ips.extract_iocs(rows)) == []

    def test_none_ip_skipped(self, q_broad_reach_ips):
        rows = [{"resp_ip": None, "src_host_count": 20}]
        assert list(q_broad_reach_ips.extract_iocs(rows)) == []


# ══════════════════════════════════════════════════════════════════════════════
# IOC extraction — Q2: broad_reach_dns
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def q_broad_reach_dns():
    return next(q for q in ALL_QUERIES if q.name == "broad_reach_dns")


class TestExtractBroadReachDns:
    def test_valid_domain(self, q_broad_reach_dns):
        rows = [{"domain": "updates.microsoft.com",
                 "resolver_count": 120, "total_queries": 5000}]
        entries = list(q_broad_reach_dns.extract_iocs(rows))
        assert len(entries) == 1
        assert entries[0].ioc_type == "Domain-Name"
        assert entries[0].value == "updates.microsoft.com"
        assert entries[0].breadth == 120

    def test_arpa_skipped(self, q_broad_reach_dns):
        rows = [{"domain": "1.0.0.127.in-addr.arpa", "resolver_count": 50}]
        assert list(q_broad_reach_dns.extract_iocs(rows)) == []

    def test_local_skipped(self, q_broad_reach_dns):
        rows = [{"domain": "printer.local", "resolver_count": 30}]
        assert list(q_broad_reach_dns.extract_iocs(rows)) == []

    def test_domain_lowercased(self, q_broad_reach_dns):
        rows = [{"domain": "WINDOWS.COM", "resolver_count": 10}]
        entries = list(q_broad_reach_dns.extract_iocs(rows))
        assert entries[0].value == "windows.com"


# ══════════════════════════════════════════════════════════════════════════════
# IOC extraction — Q3: broad_reach_tls_sni
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def q_tls_sni():
    return next(q for q in ALL_QUERIES if q.name == "broad_reach_tls_sni")


class TestExtractTlsSni:
    def test_domain_sni(self, q_tls_sni):
        rows = [{"server_name": "api.github.com", "src_host_count": 55}]
        entries = list(q_tls_sni.extract_iocs(rows))
        assert entries[0].ioc_type == "Domain-Name"
        assert entries[0].value == "api.github.com"

    def test_ip_sni(self, q_tls_sni):
        rows = [{"server_name": "1.2.3.4", "src_host_count": 20}]
        entries = list(q_tls_sni.extract_iocs(rows))
        assert entries[0].ioc_type == "IPv4-Addr"

    def test_private_ip_sni_skipped(self, q_tls_sni):
        rows = [{"server_name": "10.0.0.5", "src_host_count": 80}]
        assert list(q_tls_sni.extract_iocs(rows)) == []

    def test_empty_sni_skipped(self, q_tls_sni):
        rows = [{"server_name": "", "src_host_count": 30}]
        assert list(q_tls_sni.extract_iocs(rows)) == []


# ══════════════════════════════════════════════════════════════════════════════
# IOC extraction — Q4: broad_reach_http
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def q_http():
    return next(q for q in ALL_QUERIES if q.name == "broad_reach_http")


class TestExtractBroadReachHttp:
    def test_domain(self, q_http):
        rows = [{"host": "downloads.mozilla.org", "src_host_count": 25,
                 "request_count": 300, "success_count": 295}]
        entries = list(q_http.extract_iocs(rows))
        assert entries[0].ioc_type == "Domain-Name"
        assert entries[0].value == "downloads.mozilla.org"

    def test_host_with_port(self, q_http):
        rows = [{"host": "proxy.example.com:8080", "src_host_count": 40}]
        entries = list(q_http.extract_iocs(rows))
        assert entries[0].value == "proxy.example.com"

    def test_ip_host(self, q_http):
        rows = [{"host": "1.2.3.4", "src_host_count": 15}]
        entries = list(q_http.extract_iocs(rows))
        assert entries[0].ioc_type == "IPv4-Addr"

    def test_private_ip_skipped(self, q_http):
        rows = [{"host": "172.16.0.1", "src_host_count": 100}]
        assert list(q_http.extract_iocs(rows)) == []

    def test_bracketed_ipv6_with_port_skipped(self, q_http):
        rows = [{"host": "[2001:db8::1]:443", "src_host_count": 100}]
        assert list(q_http.extract_iocs(rows)) == []


# ══════════════════════════════════════════════════════════════════════════════
# IOC extraction — Q5: benign_beacons
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def q_beacons():
    return next(q for q in ALL_QUERIES if q.name == "benign_beacons")


class TestExtractBenignBeacons:
    def test_domain_from_list(self, q_beacons):
        rows = [{"resp_domains": ["telemetry.microsoft.com"],
                 "resp_ip": None, "service": "ssl",
                 "beacon_type": "regular", "src_host_count": 60}]
        entries = list(q_beacons.extract_iocs(rows))
        assert any(e.value == "telemetry.microsoft.com" for e in entries)

    def test_domain_from_json_string(self, q_beacons):
        rows = [{"resp_domains": json.dumps(["ocsp.digicert.com"]),
                 "resp_ip": None, "service": "ssl",
                 "beacon_type": "known", "src_host_count": 80}]
        entries = list(q_beacons.extract_iocs(rows))
        assert any(e.value == "ocsp.digicert.com" for e in entries)

    def test_ip_extracted(self, q_beacons):
        rows = [{"resp_domains": None, "resp_ip": "13.32.99.1",
                 "service": "ssl", "beacon_type": "normal", "src_host_count": 30}]
        entries = list(q_beacons.extract_iocs(rows))
        assert any(e.ioc_type == "IPv4-Addr" and e.value == "13.32.99.1"
                   for e in entries)

    def test_private_ip_in_beacon_skipped(self, q_beacons):
        rows = [{"resp_domains": None, "resp_ip": "10.1.1.1",
                 "src_host_count": 200}]
        assert list(q_beacons.extract_iocs(rows)) == []

    def test_both_domain_and_ip(self, q_beacons):
        rows = [{"resp_domains": ["cdn.example.com"], "resp_ip": "5.6.7.8",
                 "service": "ssl", "beacon_type": "regular", "src_host_count": 15}]
        entries = list(q_beacons.extract_iocs(rows))
        types = {e.ioc_type for e in entries}
        assert "Domain-Name" in types
        assert "IPv4-Addr" in types


# ══════════════════════════════════════════════════════════════════════════════
# IOC extraction — Q6: shared_auth_ips
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def q_auth_ips():
    return next(q for q in ALL_QUERIES if q.name == "shared_auth_ips")


class TestExtractSharedAuthIps:
    def test_valid(self, q_auth_ips):
        rows = [{"ip_address": "8.8.4.4", "country": "US",
                 "city": "Ashburn", "unique_user_count": 35, "total_signins": 870}]
        entries = list(q_auth_ips.extract_iocs(rows))
        assert len(entries) == 1
        assert entries[0].value == "8.8.4.4"
        assert entries[0].ioc_type == "IPv4-Addr"
        assert entries[0].breadth == 35

    def test_private_ip_skipped(self, q_auth_ips):
        rows = [{"ip_address": "192.168.0.1", "unique_user_count": 100}]
        assert list(q_auth_ips.extract_iocs(rows)) == []

    def test_empty_skipped(self, q_auth_ips):
        rows = [{"ip_address": "", "unique_user_count": 25}]
        assert list(q_auth_ips.extract_iocs(rows)) == []


# ══════════════════════════════════════════════════════════════════════════════
# Metadata client — row extraction (no network)
# ══════════════════════════════════════════════════════════════════════════════

class TestMetadataClientRowExtraction:
    """Test static helpers — no actual Vectra connection needed."""

    def test_rows_from_native_results_data(self):
        response = {"meta": {"query_status": "SUCCESS"},
                    "results": {"data": [{"a": 1}, {"a": 2}]}}
        rows = VectraMetadataClient._rows_from_native(response)
        assert rows == [{"a": 1}, {"a": 2}]

    def test_rows_from_native_results_rows(self):
        response = {"results": {"rows": [{"b": 3}]}}
        rows = VectraMetadataClient._rows_from_native(response)
        assert rows == [{"b": 3}]

    def test_rows_from_native_data_fallback(self):
        response = {"data": [{"c": 4}]}
        rows = VectraMetadataClient._rows_from_native(response)
        assert rows == [{"c": 4}]

    def test_rows_from_native_empty(self):
        assert VectraMetadataClient._rows_from_native({}) == []

    def test_rows_from_native_results_direct_list(self):
        """V8: results:[...] list branch was missing; fell to data fallback returning []."""
        response = {"results": [{"a": 1}, {"a": 2}]}
        rows = VectraMetadataClient._rows_from_native(response)
        assert rows == [{"a": 1}, {"a": 2}]

    def test_rows_from_cantina_direct_list(self):
        dummy_client = object.__new__(VectraMetadataClient)
        dummy_client._ROW_PATHS = VectraMetadataClient._ROW_PATHS
        rows = dummy_client._rows_from_cantina([{"x": 1}])
        assert rows == [{"x": 1}]

    def test_rows_from_cantina_nested_results(self):
        dummy_client = object.__new__(VectraMetadataClient)
        dummy_client._ROW_PATHS = VectraMetadataClient._ROW_PATHS
        body = {"results": [{"y": 2}, {"y": 3}]}
        rows = dummy_client._rows_from_cantina(body)
        assert rows == [{"y": 2}, {"y": 3}]

    def test_rows_from_cantina_json_string_body(self):
        dummy_client = object.__new__(VectraMetadataClient)
        dummy_client._ROW_PATHS = VectraMetadataClient._ROW_PATHS
        body = {"data": json.dumps([{"z": 5}])}
        rows = dummy_client._rows_from_cantina(body)
        assert rows == [{"z": 5}]

    def test_rows_from_cantina_empty(self):
        dummy_client = object.__new__(VectraMetadataClient)
        dummy_client._ROW_PATHS = VectraMetadataClient._ROW_PATHS
        rows = dummy_client._rows_from_cantina({})
        assert rows == []


# ══════════════════════════════════════════════════════════════════════════════
# Connector breadth bucketing
# ══════════════════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════════════════
# V17 — Threshold validation
# ══════════════════════════════════════════════════════════════════════════════

class TestThresholdValidation:
    """V17: dangerously low thresholds are rejected at init."""

    def _make_raw(self, extra):
        """Construct a connector, bypassing the _make_conn helper for invalid configs."""
        from connector import VectraMetadataFPConnector
        env = {**_ENV_BASE_CONN, **extra}
        with patch.dict(os.environ, env):
            return VectraMetadataFPConnector

    def test_host_threshold_zero_raises(self):
        """V17: VECTRA_FP_HOST_BREADTH_THRESHOLD=0 must raise at init."""
        from connector import VectraMetadataFPConnector
        with pytest.raises(ValueError, match="HOST_BREADTH_THRESHOLD"):
            with patch.dict(os.environ, {**_ENV_BASE_CONN,
                                         "VECTRA_FP_HOST_BREADTH_THRESHOLD": "0"}):
                VectraMetadataFPConnector()

    def test_host_threshold_one_raises(self):
        from connector import VectraMetadataFPConnector
        with pytest.raises(ValueError):
            with patch.dict(os.environ, {**_ENV_BASE_CONN,
                                         "VECTRA_FP_HOST_BREADTH_THRESHOLD": "1"}):
                VectraMetadataFPConnector()

    def test_user_threshold_zero_raises(self):
        """V17: VECTRA_FP_USER_BREADTH_THRESHOLD=0 must raise at init."""
        from connector import VectraMetadataFPConnector
        with pytest.raises(ValueError, match="USER_BREADTH_THRESHOLD"):
            with patch.dict(os.environ, {**_ENV_BASE_CONN,
                                         "VECTRA_FP_USER_BREADTH_THRESHOLD": "0"}):
                VectraMetadataFPConnector()

    def test_default_thresholds_start_normally(self):
        """V17: defaults (host=10, user=20) must not raise."""
        c = _make_conn()   # uses default thresholds from _ENV_BASE_CONN
        assert c.host_threshold == 10
        assert c.user_threshold == 20

    def test_threshold_two_is_accepted(self):
        """V17: minimum valid value (2) must be accepted."""
        c = _make_conn({"VECTRA_FP_HOST_BREADTH_THRESHOLD": "2",
                        "VECTRA_FP_USER_BREADTH_THRESHOLD": "2"})
        assert c.host_threshold == 2
        assert c.user_threshold == 2


# Connector breadth bucketing
# ══════════════════════════════════════════════════════════════════════════════

class TestBreadthBucket:

    @pytest.mark.parametrize("n, expected", [
        (0,  "1-9"),    # V14: below threshold floor
        (1,  "1-9"),
        (9,  "1-9"),
        (10, "10-19"),
        (19, "10-19"),
        (20, "20-49"),
        (49, "20-49"),
        (50, "50-99"),
        (99, "50-99"),
        (100, "100-249"),
        (249, "100-249"),
        (250, "250-499"),
        (499, "250-499"),
        (500, "500+"),
        (9999, "500+"),
    ])
    def test_bucket(self, n, expected):
        from connector import VectraMetadataFPConnector
        assert VectraMetadataFPConnector._breadth_bucket(n) == expected


# ══════════════════════════════════════════════════════════════════════════════
# Connector-level unit tests (V3, V4, V5, V6)
# ══════════════════════════════════════════════════════════════════════════════

import os
import types as _types
from unittest.mock import MagicMock, patch

_ENV_BASE_CONN = {
    "OPENCTI_URL":   "http://fake:8080",
    "OPENCTI_TOKEN": "fake",
    "CONNECTOR_ID":  "test-id",
    "VECTRA_FP_SCORE":                 "15",
    "VECTRA_FP_MALICIOUS_GUARD_SCORE": "70",
    "VECTRA_FP_LOOKBACK_DAYS":         "30",
    "VECTRA_FP_HOST_BREADTH_THRESHOLD":"10",
    "VECTRA_FP_USER_BREADTH_THRESHOLD":"20",
    "VECTRA_FP_MAX_RESULTS":           "500",
    "VECTRA_FP_INTERVAL_SEC":          "86400",
    "VECTRA_FP_INTER_QUERY_DELAY_SEC": "0",
    "VECTRA_FP_CONFIDENCE":            "60",
}


def _make_conn(extra=None):
    from connector import VectraMetadataFPConnector
    env = {**_ENV_BASE_CONN, **(extra or {})}
    with patch.dict(os.environ, env):
        c = VectraMetadataFPConnector()
    helper = MagicMock()
    helper.api.label.create.return_value = {"id": "lbl-stub"}
    helper.api.stix_cyber_observable.add_label.return_value = True
    helper.api.note.create.return_value = {"id": "note-stub"}
    c.helper = helper
    return c


def _ioc_entry(ioc_type="IPv4-Addr", value="1.2.3.4", breadth=50, query_name="broad_reach_ips"):
    from queries import IOCEntry
    return IOCEntry(ioc_type=ioc_type, value=value, breadth=breadth,
                    query_name=query_name, context={"src_host_count": breadth})


class TestAddLabel:
    """V3: _add_label returns bool and logs WARNING on failure."""

    def test_success_returns_true(self):
        c = _make_conn()
        c.helper.api.label.create.return_value = {"id": "lbl-1"}
        assert c._add_label("obs-1", "fp-candidate", "#green") is True

    def test_missing_id_returns_false_and_warns(self):
        """V3: label.create returns {} (no id) — KeyError caught as WARNING, returns False."""
        c = _make_conn()
        c.helper.api.label.create.return_value = {}   # missing 'id'
        result = c._add_label("obs-1", "fp-candidate", "#green")
        assert result is False
        assert c.helper.log_warning.called

    def test_api_exception_returns_false_and_warns(self):
        c = _make_conn()
        c.helper.api.label.create.side_effect = RuntimeError("network error")
        result = c._add_label("obs-1", "fp-candidate", "#green")
        assert result is False
        assert c.helper.log_warning.called


class TestImportIoc:
    """V4, V5: _import_ioc note gating and independent label tracking."""

    def _existing_obs(self, obs_id="obs-1", labels=None, score=50):
        return {
            "id": obs_id,
            "x_opencti_score": score,
            "objectLabel": [{"value": lbl} for lbl in (labels or [])],
        }

    # ---- V4: note is gated on ok_fp ------------------------------------------

    def test_note_not_created_when_label_fails(self):
        """V4: note must NOT be created if _add_label returns False for fp-candidate."""
        c = _make_conn()
        c.helper.api.stix_cyber_observable.list.return_value = []
        c.helper.api.stix_cyber_observable.create.return_value = {"id": "obs-new"}
        # label.create always fails
        c.helper.api.label.create.return_value = {}

        entry = _ioc_entry()
        c._import_ioc(entry, "test query")

        c.helper.api.note.create.assert_not_called()

    def test_note_created_exactly_once_on_success(self):
        """V4: on successful source-label application, note is created exactly once."""
        c = _make_conn()
        c.helper.api.stix_cyber_observable.list.return_value = []
        c.helper.api.stix_cyber_observable.create.return_value = {"id": "obs-new"}

        entry = _ioc_entry()
        c._import_ioc(entry, "test query")
        c._import_ioc(entry, "test query")  # second call: key in _seen_this_cycle

        # Note created only once (dedup via _seen_this_cycle within a cycle)
        assert c.helper.api.note.create.call_count == 1

    def test_default_does_not_apply_fp_candidate(self):
        """2xp: high-breadth Vectra context is not cascade-capable by default."""
        c = _make_conn()
        c.helper.api.stix_cyber_observable.list.return_value = []
        c.helper.api.stix_cyber_observable.create.return_value = {"id": "obs-new"}

        c._import_ioc(_ioc_entry(), "test query")

        label_calls = [call.kwargs.get("value") for call in c.helper.api.label.create.call_args_list]
        assert "fp-candidate" not in label_calls
        assert "vectra-metadata-popular-ip" in label_calls
        assert "vectra-metadata-benign" not in label_calls
        assert "breadth:50-99" in label_calls

    def test_default_creates_missing_for_whitelist_mining(self):
        """05t: default keeps metadata-mining inventory/cache behavior."""
        c = _make_conn()
        c.helper.api.stix_cyber_observable.list.return_value = []
        c.helper.api.stix_cyber_observable.create.return_value = {"id": "obs-new"}

        assert c._import_ioc(_ioc_entry(), "test query") is True

        c.helper.api.stix_cyber_observable.create.assert_called_once()

    def test_create_missing_can_be_disabled(self):
        """05t: enrichment-only deployments can opt out of benign inventory."""
        c = _make_conn({"VECTRA_FP_CREATE_MISSING": "false"})
        c.helper.api.stix_cyber_observable.list.return_value = []

        assert c._import_ioc(_ioc_entry(), "test query") is False

        c.helper.api.stix_cyber_observable.create.assert_not_called()
        assert c._skipped_missing == 1

    def test_score_zero_existing_observable_not_blocked_by_malicious_guard(self):
        """V18: score=0 must stay 0, not become fallback 50 via `or 50`."""
        c = _make_conn({"VECTRA_FP_MALICIOUS_GUARD_SCORE": "1"})
        c.helper.api.stix_cyber_observable.list.return_value = [
            self._existing_obs(score=0)
        ]

        assert c._import_ioc(_ioc_entry(), "test query") is True

        label_calls = [call.kwargs.get("value") for call in c.helper.api.label.create.call_args_list]
        assert "vectra-metadata-popular-ip" in label_calls

    def test_malicious_guard_still_blocks_high_score_existing_observable(self):
        c = _make_conn({"VECTRA_FP_MALICIOUS_GUARD_SCORE": "70"})
        c.helper.api.stix_cyber_observable.list.return_value = [
            self._existing_obs(score=70)
        ]

        assert c._import_ioc(_ioc_entry(), "test query") is False

        c.helper.api.label.create.assert_not_called()

    def test_fp_candidate_is_opt_in(self):
        """2xp: env flag preserves cascade-capable label behavior when requested."""
        c = _make_conn({"VECTRA_FP_APPLY_FP_CANDIDATE": "true"})
        c.helper.api.stix_cyber_observable.list.return_value = []
        c.helper.api.stix_cyber_observable.create.return_value = {"id": "obs-new"}

        c._import_ioc(_ioc_entry(), "test query")

        label_calls = [call.kwargs.get("value") for call in c.helper.api.label.create.call_args_list]
        assert "fp-candidate" in label_calls
        assert "vectra-metadata-popular-ip" in label_calls
        assert "vectra-metadata-benign" not in label_calls

    def test_dns_domain_uses_strong_vectra_benign_label(self):
        """lo3.1: domain signals stay on the stronger benign path."""
        c = _make_conn()
        c.helper.api.stix_cyber_observable.list.return_value = []
        c.helper.api.stix_cyber_observable.create.return_value = {"id": "obs-new"}
        entry = _ioc_entry(
            ioc_type="Domain-Name", value="example.com", query_name="broad_reach_dns"
        )

        c._import_ioc(entry, "test query")

        label_calls = [call.kwargs.get("value") for call in c.helper.api.label.create.call_args_list]
        assert "vectra-metadata-benign" in label_calls
        assert "vectra-metadata-popular-ip" not in label_calls

    def test_strong_raw_ips_env_adds_vectra_benign_to_q1(self):
        """lo3.1: operators can opt into treating raw IP breadth as strong."""
        c = _make_conn({"VECTRA_FP_STRONG_RAW_IPS": "true"})
        c.helper.api.stix_cyber_observable.list.return_value = []
        c.helper.api.stix_cyber_observable.create.return_value = {"id": "obs-new"}

        c._import_ioc(_ioc_entry(), "test query")

        label_calls = [call.kwargs.get("value") for call in c.helper.api.label.create.call_args_list]
        assert "vectra-metadata-popular-ip" in label_calls
        assert "vectra-metadata-benign" in label_calls

    def test_m365_shared_auth_ip_uses_strong_vectra_benign_label(self):
        """lo3.1: M365 egress/proxy IPs stay on the stronger benign path."""
        c = _make_conn()
        c.helper.api.stix_cyber_observable.list.return_value = []
        c.helper.api.stix_cyber_observable.create.return_value = {"id": "obs-new"}
        entry = _ioc_entry(query_name="shared_auth_ips")

        c._import_ioc(entry, "test query")

        label_calls = [call.kwargs.get("value") for call in c.helper.api.label.create.call_args_list]
        assert "vectra-metadata-benign" in label_calls
        assert "vectra-metadata-popular-ip" not in label_calls

    def test_no_duplicate_note_across_cycles(self):
        """V4: second cycle for same observable with fp-candidate already present → no new note."""
        c = _make_conn()
        # Existing observable with source labels already applied
        existing = self._existing_obs(labels=[
            "fp-candidate", "vectra-metadata-benign", "vectra-metadata-popular-ip"
        ])
        c.helper.api.stix_cyber_observable.list.return_value = [existing]

        c._import_ioc(_ioc_entry(), "test query")

        c.helper.api.note.create.assert_not_called()

    # ---- V5: vectra-metadata-benign tracked independently -------------------

    def test_vectra_benign_applied_when_only_fp_present(self):
        """V5: observable with fp-candidate but no vectra-metadata-benign gets the missing label."""
        c = _make_conn()
        existing = self._existing_obs(labels=["fp-candidate"])  # missing vectra-benign
        c.helper.api.stix_cyber_observable.list.return_value = [existing]
        entry = _ioc_entry(
            ioc_type="Domain-Name", value="example.com", query_name="broad_reach_dns"
        )

        c._import_ioc(entry, "test query")

        label_calls = [call.kwargs.get("value") for call in c.helper.api.label.create.call_args_list]
        assert "vectra-metadata-benign" in label_calls
        # fp-candidate already present — must not be re-added
        assert label_calls.count("fp-candidate") == 0

    def test_fp_candidate_not_reapplied_when_already_present(self):
        """V5: fp-candidate already on observable → only missing labels are applied."""
        c = _make_conn()
        existing = self._existing_obs(labels=["fp-candidate", "vectra-metadata-benign"])
        c.helper.api.stix_cyber_observable.list.return_value = [existing]
        entry = _ioc_entry(
            ioc_type="Domain-Name", value="example.com", query_name="broad_reach_dns"
        )

        c._import_ioc(entry, "test query")

        label_calls = [call.kwargs.get("value") for call in c.helper.api.label.create.call_args_list]
        # Neither fp nor vectra-benign should be re-added (both present)
        assert "fp-candidate" not in label_calls
        assert "vectra-metadata-benign" not in label_calls


class TestCycleAggregation:
    """thx: collect duplicate query hits, import once, keep all signals."""

    class _FakeQuery:
        def __init__(self, name, label):
            self.name = name
            self.label = label

        def build_sql(self, **kwargs):
            return self.name

        def extract_iocs(self, rows):
            yield from rows

    def test_duplicate_ioc_imported_once_with_all_query_names_in_note(self):
        import connector as connector_mod
        c = _make_conn()
        c.helper.api.stix_cyber_observable.list.return_value = []
        c.helper.api.stix_cyber_observable.create.return_value = {"id": "obs-new"}

        q1 = self._FakeQuery("q1", "First signal")
        q2 = self._FakeQuery("q2", "Second signal")
        client = MagicMock()
        client.execute.side_effect = lambda sql: {
            "q1": [_ioc_entry(value="1.2.3.4", breadth=20, query_name="q1")],
            "q2": [_ioc_entry(value="1.2.3.4", breadth=80, query_name="q2")],
        }[sql]

        with patch.object(connector_mod, "ALL_QUERIES", [q1, q2]):
            c._run_cycle(client)

        assert c.helper.api.stix_cyber_observable.list.call_count == 1
        assert c.helper.api.stix_cyber_observable.create.call_count == 1
        note = c.helper.api.note.create.call_args.kwargs
        assert "q1" in note["content"]
        assert "q2" in note["content"]
        assert "First signal" in note["content"]
        assert "Second signal" in note["content"]
        assert "breadth=80" in note["abstract"]

    def test_cycle_summary_reports_skipped_missing(self):
        import connector as connector_mod
        c = _make_conn({"VECTRA_FP_CREATE_MISSING": "false"})
        c.helper.api.stix_cyber_observable.list.return_value = []

        q1 = self._FakeQuery("q1", "First signal")
        client = MagicMock()
        client.execute.return_value = [_ioc_entry(value="1.2.3.4", query_name="q1")]

        with patch.object(connector_mod, "ALL_QUERIES", [q1]):
            c._run_cycle(client)

        c.helper.api.stix_cyber_observable.create.assert_not_called()
        logs = "\n".join(str(call.args[0]) for call in c.helper.log_info.call_args_list)
        assert "skipped_missing=1" in logs


class TestNativeExecuteV6:
    """V6: 5xx non-JSON poll response raises VectraMetadataError, not HTTPError."""

    def test_non_json_5xx_raises_vectra_error_not_http_error(self):
        import requests as _requests
        from metadata_client import VectraMetadataClient, VectraMetadataError

        client = object.__new__(VectraMetadataClient)
        client._mode = "native"
        client._ndr_url = "https://fake"
        client._timeout = 5
        client.POLL_INTERVAL_SEC = 0
        client._log = MagicMock()

        # Stub _auth_headers and submit
        client._auth_headers = MagicMock(return_value={})
        submit_resp = MagicMock()
        submit_resp.raise_for_status = MagicMock()
        submit_resp.json.return_value = {"requestId": "req-1"}

        # Poll returns HTTP 503 with non-JSON HTML body
        poll_resp = MagicMock()
        poll_resp.json.side_effect = ValueError("not JSON")
        poll_resp.status_code = 503
        poll_resp.raise_for_status.side_effect = _requests.HTTPError(
            "503 Server Error"
        )

        with patch("requests.post", return_value=submit_resp), \
             patch("requests.get", return_value=poll_resp):
            with pytest.raises(VectraMetadataError):
                client._native_execute("SELECT 1")

        # Must NOT have raised requests.HTTPError directly
        # (verified by the pytest.raises(VectraMetadataError) above)


class TestCycleTraceback:
    """V7: cycle exceptions include full traceback in log_error."""

    def test_traceback_included_in_cycle_error_log(self):
        import time as _time
        c = _make_conn()
        mock_client = MagicMock()
        c._build_client = MagicMock(return_value=mock_client)

        def boom(client):
            raise RuntimeError("something went wrong")

        c._run_cycle = boom

        class _Stop(Exception): pass

        # Run one iteration: cycle fails, then time.sleep raises _Stop to exit loop
        with patch("time.sleep", side_effect=_Stop):
            try:
                c.run()
            except _Stop:
                pass

        assert c.helper.log_error.called
        error_text = str(c.helper.log_error.call_args)
        # traceback.format_exc() produces 'Traceback (most recent call last):'
        assert "Traceback" in error_text or "RuntimeError" in error_text


class TestClientCaching:
    """V11: client is cached across cycles; V16: _build_client crash doesn't kill loop."""

    def test_build_client_called_once_across_cycles(self):
        """V11: _build_client called only on first cycle; token cache preserved."""
        c = _make_conn()
        mock_client = MagicMock()
        c._build_client = MagicMock(return_value=mock_client)
        c._run_cycle = MagicMock()

        call_count = 0

        class _Stop(Exception):
            pass

        def stop_after_two(secs):
            nonlocal call_count
            call_count += 1
            if call_count >= 2:
                raise _Stop

        with patch("time.sleep", side_effect=stop_after_two):
            try:
                c.run()
            except _Stop:
                pass

        assert c._build_client.call_count == 1   # built once, reused
        assert c._run_cycle.call_count == 2       # ran both cycles

    def test_build_client_exception_logs_error_and_continues(self):
        """V16: unexpected exception from _build_client logs ERROR, sleeps, does not crash."""
        c = _make_conn()
        c._build_client = MagicMock(side_effect=RuntimeError("unexpected env error"))

        class _Stop(Exception):
            pass

        with patch("time.sleep", side_effect=_Stop):
            try:
                c.run()
            except _Stop:
                pass

        assert c.helper.log_error.called
        assert c._client is None   # client was never set

    def test_cycle_error_does_not_clear_cached_client(self):
        """V11: non-auth cycle errors do not reset self._client."""
        c = _make_conn()
        mock_client = MagicMock()
        c._build_client = MagicMock(return_value=mock_client)
        c._run_cycle = MagicMock(side_effect=RuntimeError("data error"))

        class _Stop(Exception):
            pass

        with patch("time.sleep", side_effect=_Stop):
            try:
                c.run()
            except _Stop:
                pass

        # Client stays cached — a generic cycle error should not force a rebuild
        assert c._client is mock_client


class TestFindObservableWarning:
    """V15: _find_observable failure logs at WARNING."""

    def test_lookup_failure_logs_warning(self):
        c = _make_conn()
        c.helper.api.stix_cyber_observable.list.side_effect = RuntimeError("API down")
        result = c._find_observable("IPv4-Addr", "1.2.3.4")
        assert result is None
        assert c.helper.log_warning.called
