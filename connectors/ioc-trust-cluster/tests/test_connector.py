"""
tests/test_connector.py
=======================
Comprehensive test suite for connectors/ioc-trust-cluster/src/connector.py

Coverage map
────────────
  ① _extract_tls_profile       JA4/JA4S profile extraction vs JA3/JA4X no-ops
  ② _classify_parent           three-state verdict logic (all boundary conditions)
  ③ _extract_parent            all supported observable types + edge cases
  ④ _get_announced_cidr        RDAP lookup, caching, side-effects, fallback paths
  ⑤ _get_asn_owner             RDAP ASN resolution, cache hits, failure paths
  ⑥ process_message            full pipeline:
       • CIDR parent creation + child→parent relationship
       • cluster label applied to both child and parent
       • trust propagation — malicious-cascade DOWN from confirmed CIDR
       • trust propagation — fp-candidate DOWN from benign CIDR
       • cascaded parent (malicious-cascade label) stops further propagation
       • label-only path — ASN owner cluster label
       • label-only path — TLS profile cluster label
       • ubiquity heuristic (sightings threshold)
       • skip guards (no entity_id, unsupported type, entity not found)
       • domain + URL + X509 structural linking
       • audit note creation
"""

# ── Bootstrap: register third-party stubs *before* importing the connector ──
import sys
import types
import os
import json
from io import BytesIO
from unittest.mock import MagicMock, patch, call
import pytest
import ipaddress
import dns.resolver as _dns_resolver

# ── pycti stub ──────────────────────────────────────────────────────────────
_pycti = types.ModuleType("pycti")
_pycti.OpenCTIConnectorHelper = MagicMock   # callable → returns MagicMock instance
sys.modules.setdefault("pycti", _pycti)

# ── ipwhois stubs ────────────────────────────────────────────────────────────
_ipwhois_mod = types.ModuleType("ipwhois")
_ipwhois_exc = types.ModuleType("ipwhois.exceptions")

class _FakeIPDefinedError(Exception):
    """Stand-in for ipwhois.exceptions.IPDefinedError."""

_ipwhois_exc.IPDefinedError = _FakeIPDefinedError
_ipwhois_mod.IPWhois = MagicMock()
_ipwhois_mod.exceptions = _ipwhois_exc
sys.modules.setdefault("ipwhois", _ipwhois_mod)
sys.modules.setdefault("ipwhois.exceptions", _ipwhois_exc)

# ── Connector import (safe after stubs) ──────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import connector as _mod
from connector import (
    IocTrustClusterConnector,
    LABEL_FP_CANDIDATE,
    LABEL_FP_CONFIRMED,
    LABEL_MALICIOUS_CASCADE,
    LABEL_INHERITED_FP_CANDIDATE,
    LABEL_INHERITED_MALICIOUS_CASCADE,
    LABEL_SINKHOLE,
    LABEL_SINKHOLED,
    LABEL_ONLY,
    CLUSTER_LABEL_PREFIX,
    ASN_REL_DESCRIPTION,
    COLOR_CLUSTER,
    COLOR_FP,
    COLOR_MALICIOUS,
    COLOR_SINKHOLED,
)

# ══════════════════════════════════════════════════════════════════════════════
# Shared test helpers
# ══════════════════════════════════════════════════════════════════════════════

_ENV_BASE = {
    "OPENCTI_URL":                          "http://fake:8080",
    "OPENCTI_TOKEN":                        "fake-token",
    "CONNECTOR_ID":                         "test-connector-id",
    "TRUST_CLUSTER_USE_RDAP":              "false",   # RDAP OFF by default
    "TRUST_CLUSTER_USE_NS_LOOKUP":         "false",   # NS lookup OFF by default
    "TRUST_CLUSTER_SINKHOLE_IPS":          "",        # sinkhole OFF by default
    "TRUST_CLUSTER_MALICIOUS_SCORE_MIN":   "70",
    "TRUST_CLUSTER_FP_SIGHTING_THRESHOLD": "10",
    "TRUST_CLUSTER_UNKNOWN_SCORE_MAX":     "50",
    "TRUST_CLUSTER_FP_CASCADE_SCORE_MAX":  "50",      # explicit default — matches UNKNOWN_SCORE_MAX
    "TRUST_CLUSTER_CIDR_FALLBACK_PREFIX":  "24",
    "TRUST_CLUSTER_IPV6_FALLBACK_PREFIX":  "48",
    "TRUST_CLUSTER_RDAP_TIMEOUT":          "5",
    "TRUST_CLUSTER_NS_TIMEOUT":            "5",
}


def _make_connector(extra_env: dict | None = None) -> IocTrustClusterConnector:
    """
    Build a connector with a fully mocked OpenCTI helper.

    Extra env vars can override TRUST_CLUSTER_* defaults.
    API method defaults are set to no-op/stub returns so individual tests
    only need to configure the behaviour they actually care about.
    """
    env = {**_ENV_BASE, **(extra_env or {})}
    with patch.dict(os.environ, env, clear=False):
        c = IocTrustClusterConnector()

    helper = MagicMock()
    helper.log_info    = MagicMock()
    helper.log_debug   = MagicMock()
    helper.log_warning = MagicMock()
    helper.log_error   = MagicMock()
    # Default: every label.create returns a valid id
    helper.api.label.create.return_value = {"id": "label-id-stub"}
    helper.api.stix_cyber_observable.add_label.return_value = True
    helper.api.stix_core_relationship.create.return_value   = {"id": "rel-stub"}
    helper.api.stix_core_relationship.list.return_value     = []
    helper.api.stix_sighting_relationship.list.return_value = []
    helper.api.note.create.return_value = {"id": "note-stub"}
    c.helper = helper
    return c


def _obs(
    entity_id:   str       = "obs-001",
    entity_type: str       = "IPv4-Addr",
    value:       str       = "1.2.3.4",
    score:       int       = 50,
    labels:      list[str] | None = None,
    issuer:      str       = "",
    subject:     str       = "",
    **kwargs,
) -> dict:
    """Build a minimal observable dict as returned by the OpenCTI API."""
    d = {
        "id":                entity_id,
        "entity_type":       entity_type,
        "value":             value,
        "x_opencti_score":   score,
        "objectLabel":       [{"id": f"label-{i}", "value": lbl} for i, lbl in enumerate(labels or [])],
        "indicators":        [],
    }
    if issuer:
        d["issuer"] = issuer
    if subject:
        d["subject"] = subject
    d.update(kwargs)
    return d


def _labels_created(helper) -> list[str]:
    """Collect every label value passed to helper.api.label.create()."""
    return [
        c.kwargs.get("value") or (c.args[0] if c.args else "")
        for c in helper.api.label.create.call_args_list
    ]


def _relationship_made(helper) -> bool:
    return helper.api.stix_core_relationship.create.called


def _trust_rel(parent: dict) -> dict:
    return {
        "description": "IOC trust-cluster structural parent link (auto-created)",
        "toId": parent["id"],
        "to": parent,
    }


def _child_rel(child: dict) -> dict:
    return {
        "description": "IOC trust-cluster structural parent link (auto-created)",
        "fromId": child["id"],
        "from": child,
    }


# ══════════════════════════════════════════════════════════════════════════════
# ① _extract_tls_profile
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractTlsProfile:
    """Static helper — no connector state required."""

    def test_ja4_returns_profile_prefix(self):
        e = {"value": "t13d1516h2_8daaf6152771_e5627efa2ab1"}
        assert IocTrustClusterConnector._extract_tls_profile(e) == "t13d1516h2"

    def test_ja4_profile_is_lowercased(self):
        e = {"value": "T13D1516H2_8DAAF6152771_E5627EFA2AB1"}
        assert IocTrustClusterConnector._extract_tls_profile(e) == "t13d1516h2"

    def test_ja4_no_alpn_variant_returns_prefix(self):
        # Variant without trailing alpha chars (s-prefix = server-side ja4)
        e = {"value": "s13d1516_8daaf6152771_e5627efa2ab1"}
        assert IocTrustClusterConnector._extract_tls_profile(e) == "s13d1516"

    def test_ja3_32hex_returns_none(self):
        e = {"value": "0cc9d7dbbdcbaa0aa48e7c5f87c83cf8"}   # 32-char MD5
        assert IocTrustClusterConnector._extract_tls_profile(e) is None

    def test_ja4x_cert_fingerprint_returns_none(self):
        # JA4X format — no structured profile prefix extractable
        e = {"value": "2_fae1b9d3a4c77b9218_e23def456abcde12"}
        assert IocTrustClusterConnector._extract_tls_profile(e) is None

    def test_empty_entity_returns_none(self):
        assert IocTrustClusterConnector._extract_tls_profile({}) is None

    def test_value_from_hashes_dict(self):
        e = {"hashes": {"JA4": "t13d1516h2_8daaf6152771_e5627efa2ab1"}}
        assert IocTrustClusterConnector._extract_tls_profile(e) == "t13d1516h2"

    def test_value_from_tls_ext_extension(self):
        e = {
            "extensions": {
                "tls-ext": {"ja4_hash": "t13d1516h2_8daaf6152771_e5627efa2ab1"}
            }
        }
        assert IocTrustClusterConnector._extract_tls_profile(e) == "t13d1516h2"


# ══════════════════════════════════════════════════════════════════════════════
# ② _classify_parent
# ══════════════════════════════════════════════════════════════════════════════

class TestClassifyParent:
    """Three-state verdict — pure logic, no I/O."""

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()

    def test_high_score_no_labels_is_confirmed_malicious(self):
        assert self.c._classify_parent(80, set()) == "CONFIRMED_MALICIOUS"

    def test_score_at_threshold_is_confirmed_malicious(self):
        assert self.c._classify_parent(70, set()) == "CONFIRMED_MALICIOUS"

    def test_score_one_below_threshold_is_unknown(self):
        assert self.c._classify_parent(69, set()) == "UNKNOWN"

    def test_high_score_with_malicious_cascade_label_is_unknown(self):
        # Parent was itself cascade-inferred — propagating further would
        # let a single hot child contaminate its entire sibling population.
        assert self.c._classify_parent(80, {LABEL_MALICIOUS_CASCADE}) == "UNKNOWN"

    def test_fp_candidate_low_score_is_unknown(self):
        assert self.c._classify_parent(30, {LABEL_FP_CANDIDATE}) == "UNKNOWN"

    def test_fp_confirmed_low_score_is_confirmed_benign(self):
        assert self.c._classify_parent(30, {LABEL_FP_CONFIRMED}) == "CONFIRMED_BENIGN"

    def test_vectra_metadata_benign_low_score_is_unknown(self):
        assert self.c._classify_parent(30, {"vectra-metadata-benign"}) == "UNKNOWN"

    def test_fp_candidate_but_high_score_is_confirmed_malicious(self):
        # Malicious verdict takes priority over fp-candidate label
        assert self.c._classify_parent(80, {LABEL_FP_CANDIDATE}) == "CONFIRMED_MALICIOUS"

    def test_no_labels_neutral_score_is_unknown(self):
        assert self.c._classify_parent(50, set()) == "UNKNOWN"

    def test_zero_score_is_unknown(self):
        assert self.c._classify_parent(0, set()) == "UNKNOWN"

    @pytest.mark.parametrize("label", [LABEL_SINKHOLE, LABEL_SINKHOLED])
    @pytest.mark.parametrize("score", [0, 30, 80])
    def test_sinkhole_labels_are_confirmed_malicious_regardless_of_score(
        self, label, score
    ):
        assert self.c._classify_parent(score, {label}) == "CONFIRMED_MALICIOUS"

    @pytest.mark.parametrize("label", [LABEL_SINKHOLE, LABEL_SINKHOLED])
    def test_sinkhole_labels_override_malicious_cascade(self, label):
        assert self.c._classify_parent(
            30, {label, LABEL_MALICIOUS_CASCADE}
        ) == "CONFIRMED_MALICIOUS"


# ══════════════════════════════════════════════════════════════════════════════
# ③ _extract_parent — per-type unit tests
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractParentIPv4:
    """IPv4-Addr parent extraction — ASN/RDAP CIDR only, no random /24."""

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()   # use_rdap=False

    def test_public_ip_without_rdap_returns_none(self):
        assert self.c._extract_parent("IPv4-Addr", "1.2.3.100") is None

    def test_cidr_notation_input_returns_none(self):
        # A CIDR observable is itself a parent — no further parent extraction
        assert self.c._extract_parent("IPv4-Addr", "1.2.3.0/24") is None

    def test_private_ip_returns_none(self):
        assert self.c._extract_parent("IPv4-Addr", "192.168.1.100") is None

    def test_custom_fallback_prefix_does_not_create_random_parent(self):
        c2 = _make_connector({"TRUST_CLUSTER_CIDR_FALLBACK_PREFIX": "16"})
        assert c2._extract_parent("IPv4-Addr", "10.20.30.40") is None


class TestExtractParentIPv4Rdap:
    """IPv4-Addr parent extraction — RDAP enabled."""

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})

    def test_rdap_announced_cidr_used_when_available(self):
        self.c._get_announced_cidr = MagicMock(return_value="8.8.0.0/16")
        p = self.c._extract_parent("IPv4-Addr", "8.8.8.8")
        assert p == ("IPv4-Addr", "8.8.0.0/16")
        self.c._get_announced_cidr.assert_called_once_with("8.8.8.8")

    def test_rdap_failure_returns_none(self):
        self.c._get_announced_cidr = MagicMock(return_value=None)
        assert self.c._extract_parent("IPv4-Addr", "1.2.3.4") is None

    def test_rdap_returns_same_as_value_returns_none(self):
        # RDAP shouldn't return a host address, but defend against it
        self.c._get_announced_cidr = MagicMock(return_value="1.2.3.4")
        assert self.c._extract_parent("IPv4-Addr", "1.2.3.4") is None


class TestExtractParentIPv6:

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()   # use_rdap=False

    def test_public_ipv6_without_rdap_returns_none(self):
        assert self.c._extract_parent("IPv6-Addr", "2001:db8::1") is None

    def test_ipv6_cidr_notation_returns_none(self):
        assert self.c._extract_parent("IPv6-Addr", "2001:db8::/32") is None

    def test_ipv6_loopback_returns_none(self):
        assert self.c._extract_parent("IPv6-Addr", "::1") is None

    def test_ipv6_link_local_returns_none(self):
        assert self.c._extract_parent("IPv6-Addr", "fe80::1") is None

    def test_ipv6_rdap_cidr_used_when_available(self):
        c2 = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c2._get_announced_cidr = MagicMock(return_value="2001:db8::/32")
        p = c2._extract_parent("IPv6-Addr", "2001:db8::1")
        assert p == ("IPv6-Addr", "2001:db8::/32")


class TestKnownCidrAnchors:
    """Trusted CIDR→ASN edges avoid repeated RDAP for peer addresses."""

    @staticmethod
    def _asn_rel(
        cidr: str,
        entity_type: str = "IPv4-Addr",
        description: str = ASN_REL_DESCRIPTION,
        target_type: str = "Autonomous-System",
    ) -> dict:
        return {
            "description": description,
            "from": {
                "id": f"cidr-{cidr}",
                "entity_type": entity_type,
                "observable_value": cidr,
            },
            "to": {"id": "asn-1", "entity_type": target_type},
        }

    def test_loads_only_connector_owned_asn_backed_cidrs_and_uses_longest_prefix(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c.helper.api.stix_core_relationship.list.return_value = [
            self._asn_rel("8.8.0.0/16"),
            self._asn_rel("8.8.8.0/24"),
            self._asn_rel("8.8.8.0/25", description="analyst-created edge"),
            self._asn_rel("8.8.8.0/26", target_type="Organization"),
        ]
        c._get_announced_cidr = MagicMock(return_value="9.9.9.0/24")

        assert c._extract_parent("IPv4-Addr", "8.8.8.8") == (
            "IPv4-Addr", "8.8.8.0/24"
        )
        assert c._extract_parent("IPv4-Addr", "8.8.8.9") == (
            "IPv4-Addr", "8.8.8.0/24"
        )

        c._get_announced_cidr.assert_not_called()
        c.helper.api.stix_core_relationship.list.assert_called_once_with(
            relationship_type="belongs-to",
            fromTypes=["IPv4-Addr", "IPv6-Addr"],
            toTypes=["Autonomous-System"],
            search=ASN_REL_DESCRIPTION,
            getAll=True,
        )

    def test_ipv6_longest_prefix_match_skips_rdap(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c.helper.api.stix_core_relationship.list.return_value = [
            self._asn_rel("2606:4700::/32", "IPv6-Addr"),
            self._asn_rel("2606:4700:4700::/48", "IPv6-Addr"),
        ]
        c._get_announced_cidr = MagicMock(return_value=None)

        assert c._extract_parent("IPv6-Addr", "2606:4700:4700::1111") == (
            "IPv6-Addr", "2606:4700:4700::/48"
        )
        c._get_announced_cidr.assert_not_called()

    def test_untrusted_cidr_is_ignored_and_rdap_handles_miss(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c.helper.api.stix_core_relationship.list.return_value = [
            self._asn_rel("8.8.8.0/24", description="feed relationship")
        ]
        c._get_announced_cidr = MagicMock(return_value="8.8.0.0/16")

        assert c._extract_parent("IPv4-Addr", "8.8.8.8") == (
            "IPv4-Addr", "8.8.0.0/16"
        )
        c._get_announced_cidr.assert_called_once_with("8.8.8.8")

    def test_successful_cidr_asn_link_indexes_chain_for_peer_ip(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c._known_cidrs_loaded = True
        c._get_announced_cidr = MagicMock(return_value="8.8.8.0/24")
        cidr = _obs(entity_id="cidr-001", value="8.8.8.0/24")
        asn = _obs(
            entity_id="as-15169",
            entity_type="Autonomous-System",
            value="AS15169",
        )
        c.helper.api.stix_cyber_observable.list.return_value = [asn]
        c.helper.api.stix_core_relationship.list.return_value = []

        first = c._extract_parent("IPv4-Addr", "8.8.8.8")
        c._cidr_asn_cache["8.8.8.0/24"] = ("15169", "GOOGLE LLC")
        assert c._ensure_cidr_asn_relationship(cidr, "8.8.8.0/24") is True
        second = c._extract_parent("IPv4-Addr", "8.8.8.9")

        assert first == second == ("IPv4-Addr", "8.8.8.0/24")
        c._get_announced_cidr.assert_called_once_with("8.8.8.8")
        c.helper.api.stix_core_relationship.create.assert_called_once_with(
            fromId="cidr-001",
            toId="as-15169",
            relationship_type="belongs-to",
            description=ASN_REL_DESCRIPTION,
            confidence=75,
        )

    def test_private_address_does_not_use_index_or_rdap(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c._known_cidrs_loaded = True
        assert c._register_known_cidr("10.0.0.0/8") is True
        with patch.object(_mod, "IPWhois") as mock_cls:
            assert c._extract_parent("IPv4-Addr", "10.1.2.3") is None
        mock_cls.assert_not_called()

    def test_index_is_bounded(self):
        c = _make_connector()
        with patch.object(_mod, "_CACHE_MAXSIZE", 1):
            assert c._register_known_cidr("8.8.8.0/24") is True
            assert c._register_known_cidr("1.1.1.0/24") is False
        assert len(c._known_cidr_anchors) == 1
        c.helper.log_warning.assert_called_once()


class TestExtractParentDomain:

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()

    def test_subdomain_returns_root(self):
        assert self.c._extract_parent("Domain-Name", "sub.example.com") \
               == ("Domain-Name", "example.com")

    def test_deep_subdomain_returns_root(self):
        assert self.c._extract_parent("Domain-Name", "a.b.c.evil.io") \
               == ("Domain-Name", "evil.io")

    def test_cctld_returns_registered_domain_not_public_suffix(self):
        """B1: cdn.bbc.co.uk → bbc.co.uk, not co.uk."""
        assert self.c._extract_parent("Domain-Name", "cdn.bbc.co.uk") \
               == ("Domain-Name", "bbc.co.uk")

    def test_cctld_com_au_returns_registered_domain(self):
        """B1: multi-label ccTLD (com.au) handled correctly."""
        assert self.c._extract_parent("Domain-Name", "mail.example.com.au") \
               == ("Domain-Name", "example.com.au")

    def test_cctld_root_is_not_parent_of_itself(self):
        """B1: bbc.co.uk is a registrable root domain — no parent (falls to NS)."""
        assert self.c._extract_parent("Domain-Name", "bbc.co.uk") is None

    def test_root_domain_returns_none(self):
        # Root domain is the top of the modelled hierarchy — no further parent
        assert self.c._extract_parent("Domain-Name", "example.com") is None

    def test_single_label_domain_returns_none(self):
        assert self.c._extract_parent("Domain-Name", "localhost") is None


class TestExtractParentUrl:

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()

    def test_url_with_subdomain_returns_root_domain(self):
        p = self.c._extract_parent("Url", "https://api.example.com/v1/data")
        assert p == ("Domain-Name", "example.com")

    def test_url_with_ipv4_host_without_rdap_returns_none(self):
        assert self.c._extract_parent("Url", "http://10.20.30.40/path") is None

    def test_url_root_domain_host_returns_none(self):
        assert self.c._extract_parent("Url", "https://example.com/page") is None

    def test_url_no_host_returns_none(self):
        assert self.c._extract_parent("Url", "not-a-url") is None

    def test_url_ipv6_host_routes_through_ipv6_extraction(self):
        """B10: IPv6 URL hosts now route through IPv6-Addr extraction."""
        assert self.c._extract_parent("Url", "http://[2001:db8::1]/path") is None

    def test_url_with_port_ipv4_still_parses_host(self):
        """B10 regression: IPv4 host:port still parses (urlparse strips port)."""
        assert self.c._extract_parent("Url", "http://10.20.30.40:8080/path") is None


class TestExtractParentX509:

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()

    def test_cert_with_different_issuer_returns_no_synthetic_parent(self):
        entity = {"issuer": "CN=Root CA,O=Corp", "subject": "CN=leaf.corp.com"}
        assert self.c._extract_parent("X509-Certificate", "CN=leaf.corp.com", entity) is None

    def test_self_signed_cert_returns_none(self):
        dn = "CN=SelfSigned,O=Test"
        entity = {"issuer": dn, "subject": dn}
        assert self.c._extract_parent("X509-Certificate", dn, entity) is None

    def test_cert_no_issuer_returns_none(self):
        entity = {"issuer": "", "subject": "CN=leaf"}
        assert self.c._extract_parent("X509-Certificate", "CN=leaf", entity) is None


class TestExtractParentNetworkTraffic:

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()

    def test_ja4_returns_label_only_profile(self):
        entity = {"value": "t13d1516h2_8daaf6152771_e5627efa2ab1"}
        p = self.c._extract_parent("Network-Traffic", "", entity)
        assert p == (LABEL_ONLY, "tls-profile:t13d1516h2")

    def test_ja3_returns_none(self):
        entity = {"value": "0cc9d7dbbdcbaa0aa48e7c5f87c83cf8"}
        assert self.c._extract_parent("Network-Traffic", "", entity) is None

    def test_no_fingerprint_returns_none(self):
        assert self.c._extract_parent("Network-Traffic", "", {}) is None


class TestExtractParentAutonomousSystem:

    def test_rdap_disabled_returns_none(self):
        c = _make_connector()   # use_rdap=False
        assert c._extract_parent("Autonomous-System", "AS15169") is None

    def test_rdap_owner_returns_label_only(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c._get_asn_owner = MagicMock(return_value="GOOGLE LLC")
        p = c._extract_parent("Autonomous-System", "AS15169")
        assert p == (LABEL_ONLY, "asn-owner:GOOGLE LLC")

    def test_rdap_owner_not_found_returns_none(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c._get_asn_owner = MagicMock(return_value=None)
        assert c._extract_parent("Autonomous-System", "AS99999") is None


class TestExtractParentStixFile:
    """StixFile has no structural parent by design."""

    def test_stixfile_always_returns_none(self):
        c = _make_connector()
        assert c._extract_parent("StixFile", "sha256:abc123") is None


# ══════════════════════════════════════════════════════════════════════════════
# ④ _get_announced_cidr — RDAP + caching
# ══════════════════════════════════════════════════════════════════════════════

class TestGetAnnouncedCidr:
    """Patches connector.IPWhois to avoid real network calls."""

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})

    def _rdap_result(self, cidr="8.8.8.0/24", asn="15169", asn_desc="GOOGLE"):
        return {
            "asn":             asn,
            "asn_description": asn_desc,
            "network":         {"cidr": cidr},
            "asn_cidr":        cidr,
        }

    def test_private_ip_returns_none_without_rdap(self):
        with patch.object(_mod, "IPWhois") as mock_cls:
            result = self.c._get_announced_cidr("192.168.1.1")
        assert result is None
        mock_cls.assert_not_called()   # skipped before even reaching IPWhois

    def test_loopback_returns_none(self):
        with patch.object(_mod, "IPWhois") as mock_cls:
            result = self.c._get_announced_cidr("127.0.0.1")
        assert result is None
        mock_cls.assert_not_called()

    def test_public_ip_returns_normalised_cidr(self):
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.return_value = self._rdap_result("8.8.8.0/24")
        with patch.object(_mod, "IPWhois", return_value=mock_instance):
            result = self.c._get_announced_cidr("8.8.8.8")
        assert result == "8.8.8.0/24"

    def test_multiple_cidrs_picks_most_specific(self):
        # RDAP sometimes returns a comma-separated list; take the longest prefix
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.return_value = self._rdap_result(
            cidr="8.0.0.0/8, 8.8.0.0/16, 8.8.8.0/24"
        )
        with patch.object(_mod, "IPWhois", return_value=mock_instance):
            result = self.c._get_announced_cidr("8.8.8.8")
        assert result == "8.8.8.0/24"

    def test_non_containing_cidrs_are_ignored(self):
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.return_value = self._rdap_result(
            cidr="9.9.9.0/24, 8.8.0.0/16"
        )
        with patch.object(_mod, "IPWhois", return_value=mock_instance):
            result = self.c._get_announced_cidr("8.8.8.8")
        assert result == "8.8.0.0/16"

    def test_invalid_cidrs_are_ignored(self):
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.return_value = self._rdap_result(
            cidr="not-a-cidr, 8.8.8.0/24"
        )
        with patch.object(_mod, "IPWhois", return_value=mock_instance):
            result = self.c._get_announced_cidr("8.8.8.8")
        assert result == "8.8.8.0/24"

    def test_asn_cidr_used_when_network_cidr_unusable(self):
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.return_value = {
            "asn": "15169", "asn_description": "GOOGLE",
            "network": {"cidr": "9.9.9.0/24"},
            "asn_cidr": "8.8.8.0/24",
        }
        with patch.object(_mod, "IPWhois", return_value=mock_instance):
            result = self.c._get_announced_cidr("8.8.8.8")
        assert result == "8.8.8.0/24"

    def test_ipv6_cidr_supported(self):
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.return_value = self._rdap_result(
            cidr="2001:4860::/32, 2001:4860:4860::/48"
        )
        with patch.object(_mod, "IPWhois", return_value=mock_instance):
            result = self.c._get_announced_cidr("2001:4860:4860::8888")
        assert result == "2001:4860:4860::/48"

    def test_no_containing_cidr_returns_none(self):
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.return_value = self._rdap_result(
            cidr="9.9.9.0/24"
        )
        with patch.object(_mod, "IPWhois", return_value=mock_instance):
            result = self.c._get_announced_cidr("8.8.8.8")
        assert result is None

    def test_ip_defined_error_returns_none(self):
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.side_effect = _FakeIPDefinedError("special")
        with patch.object(_mod, "IPWhois", return_value=mock_instance):
            result = self.c._get_announced_cidr("8.8.8.8")
        assert result is None

    def test_general_exception_returns_none(self):
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.side_effect = RuntimeError("timeout")
        with patch.object(_mod, "IPWhois", return_value=mock_instance):
            result = self.c._get_announced_cidr("8.8.8.8")
        assert result is None

    def test_result_is_cached_no_second_call(self):
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.return_value = self._rdap_result()
        with patch.object(_mod, "IPWhois", return_value=mock_instance):
            first  = self.c._get_announced_cidr("8.8.8.8")
            second = self.c._get_announced_cidr("8.8.8.8")
        assert first == second == "8.8.8.0/24"
        assert mock_instance.lookup_rdap.call_count == 1  # cached after first call

    def test_asn_description_cached_as_side_effect(self):
        """IP RDAP populates the ASN→owner cache for a later AS observable."""
        mock_instance = MagicMock()
        mock_instance.lookup_rdap.return_value = self._rdap_result(
            asn="15169", asn_desc="GOOGLE LLC"
        )
        with patch.object(_mod, "IPWhois", return_value=mock_instance):
            self.c._get_announced_cidr("8.8.8.8")
        # ASN owner cache should be populated as a side-effect
        assert self.c._asn_desc_cache.get("AS15169") == "GOOGLE LLC"


# ══════════════════════════════════════════════════════════════════════════════
# ⑤ _get_asn_owner — RDAP + cache
# ══════════════════════════════════════════════════════════════════════════════

class TestGetAsnOwner:

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})

    def _urlopen_ctx(self, payload: dict):
        """Context-manager mock for urllib.request.urlopen."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(payload).encode()
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        return patch("urllib.request.urlopen", return_value=mock_resp)

    def test_cache_hit_skips_rdap(self):
        self.c._asn_desc_cache["AS15169"] = "GOOGLE LLC"
        with patch("urllib.request.urlopen") as mock_open:
            name = self.c._get_asn_owner("AS15169")
        assert name == "GOOGLE LLC"
        mock_open.assert_not_called()

    def test_rdap_name_field_returned(self):
        payload = {"name": "ARIN-GOOGLE", "entities": []}
        with self._urlopen_ctx(payload):
            name = self.c._get_asn_owner("15169")
        assert name == "ARIN-GOOGLE"

    def test_rdap_vcard_fn_overrides_name(self):
        payload = {
            "name": "ARIN-GOOGLE",
            "entities": [{
                "roles": ["registrant"],
                "vcardArray": [
                    "vcard",
                    [["fn", {}, "text", "Google LLC"]]
                ]
            }]
        }
        with self._urlopen_ctx(payload):
            name = self.c._get_asn_owner("15169")
        assert name == "Google LLC"

    def test_rdap_failure_returns_none(self):
        with patch("urllib.request.urlopen", side_effect=OSError("network error")):
            name = self.c._get_asn_owner("99999")
        assert name is None

    def test_invalid_asn_digits_returns_none(self):
        name = self.c._get_asn_owner("NOT_AN_ASN")
        assert name is None

    def test_result_is_cached_after_lookup(self):
        payload = {"name": "RIPE-TEST", "entities": []}
        with self._urlopen_ctx(payload):
            first  = self.c._get_asn_owner("64512")
            second = self.c._get_asn_owner("64512")
        assert first == second == "RIPE-TEST"
        # Only one HTTP call even though we called twice
        assert self.c._asn_desc_cache["AS64512"] == "RIPE-TEST"

    def test_http_429_retries_and_succeeds_on_second_attempt(self):
        """B15: HTTP 429 triggers retry; second call returns valid data."""
        import urllib.error as _ue
        payload = {"name": "GOOGLE LLC", "entities": []}

        second_resp = MagicMock()
        second_resp.read.return_value = json.dumps(payload).encode()
        second_resp.__enter__ = lambda s: s
        second_resp.__exit__ = MagicMock(return_value=False)

        call_count = 0
        http_429 = _ue.HTTPError(url="", code=429, msg="Too Many Requests", hdrs=None, fp=None)

        def urlopen_side(req, timeout=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise http_429
            return second_resp

        with patch("urllib.request.urlopen", side_effect=urlopen_side), \
             patch("time.sleep"):   # don't actually sleep in tests
            name = self.c._get_asn_owner("15169")

        assert name == "GOOGLE LLC"
        assert call_count == 2   # retried once after 429

    def test_http_429_max_retries_logs_warning_and_caches_none(self):
        """B15: after max retries exhausted, logs WARNING and caches None."""
        import urllib.error as _ue
        http_429 = _ue.HTTPError(url="", code=429, msg="Too Many Requests", hdrs=None, fp=None)

        with patch("urllib.request.urlopen", side_effect=http_429), \
             patch("time.sleep"):
            name = self.c._get_asn_owner("15169")

        assert name is None
        assert self.c._asn_desc_cache.get("AS15169") is None
        assert self.c.helper.log_warning.called

    def test_non_http_error_does_not_retry(self):
        """B15: generic network error (not HTTP) exits immediately, no sleep."""
        with patch("urllib.request.urlopen", side_effect=OSError("connection refused")), \
             patch("time.sleep") as mock_sleep:
            name = self.c._get_asn_owner("15169")

        assert name is None
        mock_sleep.assert_not_called()   # no backoff for non-HTTP errors


# ══════════════════════════════════════════════════════════════════════════════
# ⑥ process_message — shared setup
# ══════════════════════════════════════════════════════════════════════════════

def _wire(con, child, parent=None):
    """
    Wire up the stix_cyber_observable mocks for one process_message call.

    child  — entity dict returned by observable.read()
    parent — if given, returned by observable.list() (parent already exists)
              if None, list returns [] and create() returns a stub parent
    """
    con.helper.api.stix_cyber_observable.read.return_value = child
    if parent is not None:
        con.helper.api.stix_cyber_observable.list.return_value = [parent]
        con.helper.api.stix_cyber_observable.create.return_value = parent
        # Tests that provide an IP CIDR parent are modelling an ASN/RDAP-derived
        # CIDR. Make that explicit now that random /24 fallback is gone.
        if "/" in (parent.get("value") or "") and not isinstance(
            getattr(con, "_get_announced_cidr", None), MagicMock
        ):
            con.use_rdap = True
            con._get_announced_cidr = MagicMock(return_value=parent["value"])
    else:
        con.helper.api.stix_cyber_observable.list.return_value = []
        # create() returns a minimal UNKNOWN parent anchor
        stub_parent = _obs(
            entity_id="parent-stub",
            value=child.get("value", "0.0.0.0") + "/24",
            score=50,
        )
        con.helper.api.stix_cyber_observable.create.return_value = stub_parent


# ══════════════════════════════════════════════════════════════════════════════
# Skip guard tests
# ══════════════════════════════════════════════════════════════════════════════

class TestProcessMessageGuards:

    def test_no_entity_id_is_skipped(self):
        c = _make_connector()
        result = c.process_message({"entity_type": "IPv4-Addr"})
        assert "skipped" in result

    def test_unsupported_type_is_skipped(self):
        c = _make_connector()
        c.helper.api.stix_cyber_observable.read.return_value = _obs()
        result = c.process_message({"entity_id": "obs-1", "entity_type": "Malware"})
        assert "skipped" in result

    def test_entity_not_found_is_skipped(self):
        c = _make_connector()
        c.helper.api.stix_cyber_observable.read.return_value = None
        result = c.process_message({"entity_id": "missing", "entity_type": "IPv4-Addr"})
        assert "skipped" in result


# ══════════════════════════════════════════════════════════════════════════════
# CIDR linking (KEY: "cidr ioc get linked")
# ══════════════════════════════════════════════════════════════════════════════

class TestCidrLinking:
    """
    Verifies that an IPv4 host observable is structurally linked to its CIDR
    parent: relationship created, cluster label shared on both observables.
    """

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        self.c._get_announced_cidr = MagicMock(
            side_effect=lambda ip: str(ipaddress.ip_network(f"{ip}/24", strict=False))
        )

    # ── Parent creation ──────────────────────────────────────────────────────

    def test_cidr_parent_observable_created_when_absent(self):
        child = _obs(value="10.20.30.40")
        _wire(self.c, child)   # list returns [] → create is called

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        self.c.helper.api.stix_cyber_observable.create.assert_called_once()
        created_args = self.c.helper.api.stix_cyber_observable.create.call_args
        obs_data = created_args.kwargs.get("observableData") or created_args.args[0]
        assert obs_data["value"] == "10.20.30.0/24"
        assert obs_data["type"] == "ipv4-addr"

    def test_existing_cidr_parent_reused_not_duplicated(self):
        child  = _obs(value="10.20.30.40")
        parent = _obs(entity_id="cidr-001", value="10.20.30.0/24", score=50)
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        # create must NOT have been called (parent already existed)
        self.c.helper.api.stix_cyber_observable.create.assert_not_called()

    def test_structural_relationship_does_not_depend_on_label_create(self):
        """Structural parentage is relationship-only; cluster label failures do not matter."""
        c = _make_connector()
        child  = _obs(value="1.2.3.4", score=50)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        _wire(c, child, parent)
        c.helper.api.label.create.return_value = {}

        result = c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert "linked under IPv4-Addr:1.2.3.0/24" in result
        c.helper.api.stix_core_relationship.create.assert_called_once()

    # ── Relationship ─────────────────────────────────────────────────────────

    def test_child_to_parent_relationship_is_created(self):
        child  = _obs(value="1.2.3.4")
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        self.c.helper.api.stix_core_relationship.create.assert_called_once_with(
            fromId="obs-001",
            toId="cidr-001",
            relationship_type="related-to",
            description=pytest.approx("IOC trust-cluster structural parent link (auto-created)", abs=0),
            confidence=75,
        )

    def test_confidence_level_env_var_used_in_relationship(self):
        """B5: CONNECTOR_CONFIDENCE_LEVEL propagates to relationship creation."""
        c = _make_connector({"CONNECTOR_CONFIDENCE_LEVEL": "50"})
        child  = _obs(value="1.2.3.4", score=50)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        _wire(c, child, parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        rel_kwargs = c.helper.api.stix_core_relationship.create.call_args.kwargs
        assert rel_kwargs["confidence"] == 50

    def test_confidence_level_env_var_used_in_audit_note(self):
        """B5: CONNECTOR_CONFIDENCE_LEVEL propagates to note creation."""
        c = _make_connector({"CONNECTOR_CONFIDENCE_LEVEL": "50"})
        child  = _obs(value="1.2.3.4", score=50)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=80)
        _wire(c, child, parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        note_kwargs = c.helper.api.note.create.call_args.kwargs
        assert note_kwargs["confidence"] == 50

    # ── No structural cluster labels ──────────────────────────────────────────

    def test_cluster_label_not_applied_to_child(self):
        child  = _obs(value="1.2.3.4")
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        labels = _labels_created(self.c.helper)
        assert f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24" not in labels

    def test_cluster_label_not_applied_to_parent(self):
        child  = _obs(value="1.2.3.4")
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        add_label_calls = self.c.helper.api.stix_cyber_observable.add_label.call_args_list
        targets = {c.kwargs.get("id") or c.args[0] for c in add_label_calls}
        assert "cidr-001" not in targets

    def test_cidr_ip_itself_returns_no_parent(self):
        # An observable that is already a CIDR should not try to parent itself
        child = _obs(value="10.0.0.0/8")
        _wire(self.c, child)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        self.c.helper.api.stix_core_relationship.create.assert_not_called()

    def test_rdap_announced_cidr_used_as_parent(self):
        c2 = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c2._get_announced_cidr = MagicMock(return_value="8.8.0.0/16")
        child = _obs(value="8.8.8.8")
        _wire(c2, child)

        c2.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        obs_data = c2.helper.api.stix_cyber_observable.create.call_args
        created = obs_data.kwargs.get("observableData") or obs_data.args[0]
        assert created["value"] == "8.8.0.0/16"


class TestAsnDerivedCidrParentRegression:
    """TC4: ASN/RDAP chooses CIDR; OpenCTI reuses/creates that exact parent."""

    def test_existing_opencti_cidr_for_asn_cidr_is_reused(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c._get_announced_cidr = MagicMock(return_value="8.8.0.0/16")
        child = _obs(value="8.8.8.8")
        parent = _obs(entity_id="cidr-001", value="8.8.0.0/16", score=50)
        _wire(c, child, parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_cyber_observable.create.assert_not_called()
        c.helper.api.stix_core_relationship.create.assert_called_once()
        assert c.helper.api.stix_core_relationship.create.call_args.kwargs["toId"] == "cidr-001"

    def test_missing_asn_cidr_parent_is_created_for_exact_asn_cidr(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c._get_announced_cidr = MagicMock(return_value="8.8.0.0/16")
        child = _obs(value="8.8.8.8")
        parent = _obs(entity_id="cidr-001", value="8.8.0.0/16", score=50)
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_cyber_observable.list.return_value = []
        c.helper.api.stix_cyber_observable.create.return_value = parent

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        created = c.helper.api.stix_cyber_observable.create.call_args.kwargs["observableData"]
        assert created["value"] == "8.8.0.0/16"

    def test_no_usable_rdap_cidr_creates_no_random_parent(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c._get_announced_cidr = MagicMock(return_value=None)
        child = _obs(value="8.8.8.8")
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_cyber_observable.list.return_value = []

        result = c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert "no actions" in result
        c.helper.api.stix_cyber_observable.create.assert_not_called()
        c.helper.api.stix_core_relationship.create.assert_not_called()


class TestCidrAsnOwnership:
    """ASN/RDAP metadata is modelled once: CIDR anchor → AS observable."""

    def test_cidr_anchor_gets_belongs_to_asn(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        child = _obs(value="8.8.8.8")
        cidr = _obs(entity_id="cidr-001", value="8.8.8.0/24", score=50)
        asn = _obs(entity_id="as-15169", entity_type="Autonomous-System", value="AS15169")
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_cyber_observable.list.side_effect = lambda **kw: [cidr] if kw.get("types") == ["IPv4-Addr"] else []
        c.helper.api.stix_cyber_observable.create.return_value = asn
        c._get_announced_cidr = MagicMock(return_value="8.8.8.0/24")
        c._cidr_asn_cache["8.8.8.0/24"] = ("15169", "GOOGLE LLC")

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        creates = c.helper.api.stix_core_relationship.create.call_args_list
        assert any(
            call.kwargs.get("fromId") == "cidr-001"
            and call.kwargs.get("toId") == "as-15169"
            and call.kwargs.get("relationship_type") == "belongs-to"
            for call in creates
        )

    def test_existing_asn_and_edge_are_reused(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        child = _obs(value="8.8.8.8")
        cidr = _obs(entity_id="cidr-001", value="8.8.8.0/24", score=50)
        asn = _obs(entity_id="as-15169", entity_type="Autonomous-System", value="AS15169")
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_cyber_observable.list.side_effect = (
            lambda **kw: [cidr] if kw.get("types") == ["IPv4-Addr"] else [asn]
        )
        c.helper.api.stix_core_relationship.list.side_effect = lambda **kw: [
            {"description": "IOC trust-cluster CIDR to ASN ownership link (auto-created)", "toId": "as-15169"}
        ] if kw.get("relationship_type") == "belongs-to" else []
        c._get_announced_cidr = MagicMock(return_value="8.8.8.0/24")
        c._cidr_asn_cache["8.8.8.0/24"] = ("15169", "GOOGLE LLC")

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_cyber_observable.create.assert_not_called()
        assert not any(
            call.kwargs.get("fromId") == "cidr-001"
            and call.kwargs.get("toId") == "as-15169"
            and call.kwargs.get("relationship_type") == "belongs-to"
            for call in c.helper.api.stix_core_relationship.create.call_args_list
        )


# ══════════════════════════════════════════════════════════════════════════════
# Trust propagation (KEY: "trust propagate")
# ══════════════════════════════════════════════════════════════════════════════

class TestTrustPropagation:
    """
    Validates the three-state verdict cascade rules:
      CONFIRMED_MALICIOUS → malicious-cascade DOWN to children
      CONFIRMED_BENIGN    → fp-candidate DOWN to UNKNOWN children
      UNKNOWN             → propagation stops (no cascade)
    """

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()

    # ── Malicious cascade ─────────────────────────────────────────────────────

    def test_malicious_cidr_cascades_label_to_child(self):
        child  = _obs(value="1.2.3.4",     score=50)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=80)
        _wire(self.c, child, parent)

        result = self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        labels = _labels_created(self.c.helper)
        assert LABEL_INHERITED_MALICIOUS_CASCADE in labels
        assert "malicious-cascade" in result

    def test_malicious_cidr_cascade_uses_red_color(self):
        child  = _obs(value="1.2.3.4",     score=50)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=80)
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        malicious_calls = [
            c for c in self.c.helper.api.label.create.call_args_list
            if (c.kwargs.get("value") or "") == LABEL_INHERITED_MALICIOUS_CASCADE
        ]
        assert len(malicious_calls) >= 1
        assert malicious_calls[0].kwargs["color"] == COLOR_MALICIOUS

    def test_cascaded_parent_does_not_re_cascade(self):
        """
        A parent that carries 'malicious-cascade' was inferred, not directly
        assessed — propagating further would contaminate siblings of siblings.
        The parent verdict must be UNKNOWN → propagation stops.
        """
        child  = _obs(value="1.2.3.4",     score=50)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24",
                      score=80, labels=[LABEL_MALICIOUS_CASCADE])
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        labels = _labels_created(self.c.helper)
        assert LABEL_MALICIOUS_CASCADE not in labels

    def test_fp_candidate_conflict_creates_note_not_review_string(self):
        """
        #5: when fp-candidate and malicious-cascade coexist, a dedicated conflict
        Note is created.  The prior inline REVIEW string is removed — the Note
        is the only signal (visible in the feed view, not buried in the audit note).
        """
        c = _make_connector()
        child = _obs(
            value="1.2.3.4", score=30,
            labels=[
                f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24",  # already clustered
                LABEL_FP_CANDIDATE,                      # set by prior ubiquity pass
            ],
        )
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        _wire(c, child, parent)

        result = c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        # malicious-cascade must be added (malicious signal wins)
        assert LABEL_INHERITED_MALICIOUS_CASCADE in _labels_created(c.helper)
        # Dedicated conflict Note created
        conflict_notes = [
            call for call in c.helper.api.note.create.call_args_list
            if "conflict" in (call.kwargs.get("abstract") or "").lower()
        ]
        assert len(conflict_notes) == 1
        # REVIEW string removed from action result (replaced by Note)
        assert "REVIEW" not in result

    def test_child_already_malicious_cascade_not_duplicated(self):
        child  = _obs(value="1.2.3.4",     score=50, labels=[LABEL_MALICIOUS_CASCADE])
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=80)
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        malicious_label_calls = [
            c for c in self.c.helper.api.label.create.call_args_list
            if (c.kwargs.get("value") or "") == LABEL_INHERITED_MALICIOUS_CASCADE
        ]
        assert len(malicious_label_calls) == 0, "label already present — no duplicate"

    # ── FP / benign cascade ───────────────────────────────────────────────────

    def test_fp_candidate_cidr_propagates_to_unknown_child(self):
        child  = _obs(value="1.2.3.4",     score=30)    # UNKNOWN, low score
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24",
                      score=30, labels=[LABEL_FP_CONFIRMED])
        _wire(self.c, child, parent)

        result = self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        labels = _labels_created(self.c.helper)
        assert LABEL_INHERITED_FP_CANDIDATE in labels
        assert "fp-candidate" in result

    def test_fp_candidate_not_propagated_when_child_score_high(self):
        child  = _obs(value="1.2.3.4",     score=60)    # above unknown_score_max=50
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24",
                      score=30, labels=[LABEL_FP_CONFIRMED])
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        labels = _labels_created(self.c.helper)
        assert LABEL_FP_CANDIDATE not in labels

    def test_fp_candidate_not_propagated_when_child_has_malicious_context(self):
        """Child with a malicious indicator must never be labelled fp-candidate."""
        child = _obs(
            value="1.2.3.4", score=30,
            indicators=[{"x_opencti_score": 80}],   # malicious indicator
        )
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24",
                      score=30, labels=[LABEL_FP_CONFIRMED])
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        labels = _labels_created(self.c.helper)
        assert LABEL_FP_CANDIDATE not in labels

    def test_string_indicator_score_does_not_crash(self):
        """
        B8: non-integer x_opencti_score (e.g. \"high\" from OTX/MISP) must not
        raise ValueError and must not block process_message from completing.
        A non-parseable score is treated as 0 (not malicious).
        """
        child = _obs(
            value="1.2.3.4", score=50,
            indicators=[{"x_opencti_score": "critical"}],  # string from external feed
        )
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24",
                      score=30, labels=[LABEL_FP_CONFIRMED])
        _wire(self.c, child, parent)

        # Must not raise; string score is treated as 0 — fp-candidate can cascade
        result = self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        assert "skipped" not in result
        # has_malicious=False (string treated as 0), so fp-candidate cascades
        assert LABEL_INHERITED_FP_CANDIDATE in _labels_created(self.c.helper)

    def test_score_zero_treated_as_zero_not_fifty(self):
        """
        B2: x_opencti_score=0 must read as 0, not 50 (the 'or 50' falsy gotcha).
        A score-0 child is below fp_cascade_score_max (default 50) so it must
        receive the fp-candidate cascade from a CONFIRMED_BENIGN parent.
        """
        c = _make_connector({"TRUST_CLUSTER_FP_CASCADE_SCORE_MAX": "49"})
        # score=0: old code would treat as 50 (> fp_cascade_score_max=49) → no cascade
        # fixed code: 0 <= 49 → cascade fires
        child  = _obs(value="1.2.3.4", score=0)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24",
                      score=30, labels=[LABEL_FP_CONFIRMED])
        _wire(c, child, parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_INHERITED_FP_CANDIDATE in _labels_created(c.helper), (
            "score=0 must cascade fp-candidate; was being read as 50 (falsy gotcha)"
        )

    def test_unknown_parent_stops_propagation(self):
        child  = _obs(value="1.2.3.4",     score=30)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)  # UNKNOWN
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        labels = _labels_created(self.c.helper)
        assert LABEL_MALICIOUS_CASCADE not in labels
        assert LABEL_FP_CANDIDATE      not in labels

    def test_action_string_reports_cascade(self):
        child  = _obs(value="1.2.3.4",     score=50)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=80)
        _wire(self.c, child, parent)

        result = self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert "malicious-cascade" in result
        assert "1.2.3.0/24" in result

    def test_fp_cascade_score_max_configurable(self):
        """
        TRUST_CLUSTER_FP_CASCADE_SCORE_MAX lets operators extend the benign cascade
        threshold above unknown_score_max without changing the ubiquity heuristic.

        Default (50): child with score=60 is NOT cascaded (existing test coverage).
        Raised to 65: the same child MUST receive fp-candidate from a benign parent.
        """
        c = _make_connector({"TRUST_CLUSTER_FP_CASCADE_SCORE_MAX": "65"})
        # score=60 > unknown_score_max=50 but ≤ custom fp_cascade_score_max=65
        child  = _obs(value="1.2.3.4",     score=60)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24",
                      score=30, labels=[LABEL_FP_CONFIRMED])
        _wire(c, child, parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_INHERITED_FP_CANDIDATE in _labels_created(c.helper), (
            "fp-candidate must cascade when child score (≤60 for fp) ≤ "
            "fp_cascade_score_max=65, even though it exceeds unknown_score_max=50"
        )

    def test_fp_candidate_does_not_cascade_to_malicious_score_even_if_below_fp_cascade_max(self):
        """
        B16: fp-candidate must NOT cascade to a child whose score already meets
        malicious_score_min, regardless of how fp_cascade_score_max is configured.

        Scenario: FP_CASCADE_SCORE_MAX=80, MALICIOUS_SCORE_MIN=70.
        Child score=75 is ≤ fp_cascade_score_max=80 but is also ≥ malicious_score_min=70.
        The explicit `score < malicious_score_min` guard must block the cascade.
        """
        c = _make_connector({
            "TRUST_CLUSTER_FP_CASCADE_SCORE_MAX": "80",
            "TRUST_CLUSTER_MALICIOUS_SCORE_MIN":  "70",
        })
        child  = _obs(value="1.2.3.4", score=75)   # malicious-scored, no indicator
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24",
                      score=30, labels=[LABEL_FP_CONFIRMED])
        _wire(c, child, parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_FP_CANDIDATE not in _labels_created(c.helper), (
            "fp-candidate must not cascade to score=75 when malicious_score_min=70"
        )

    def test_fp_candidate_cascades_just_below_malicious_threshold(self):
        """B16: score one below malicious_score_min still receives cascade."""
        c = _make_connector({
            "TRUST_CLUSTER_FP_CASCADE_SCORE_MAX": "80",
            "TRUST_CLUSTER_MALICIOUS_SCORE_MIN":  "70",
        })
        child  = _obs(value="1.2.3.4", score=69)   # one below threshold
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24",
                      score=30, labels=[LABEL_FP_CONFIRMED])
        _wire(c, child, parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_INHERITED_FP_CANDIDATE in _labels_created(c.helper)


# ══════════════════════════════════════════════════════════════════════════════
# Domain-Name linking
# ══════════════════════════════════════════════════════════════════════════════

class TestDomainLinking:

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()

    def test_subdomain_linked_to_root_domain_parent(self):
        child  = _obs(entity_type="Domain-Name", value="cdn.evil.example.com")
        parent = _obs(entity_id="dom-root", entity_type="Domain-Name", value="example.com", score=50)
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        _relationship_made(self.c.helper)
        self.c.helper.api.stix_core_relationship.create.assert_called_once_with(
            fromId="obs-001",
            toId="dom-root",
            relationship_type="related-to",
            description=pytest.approx("IOC trust-cluster structural parent link (auto-created)", abs=0),
            confidence=75,
        )

    def test_root_domain_has_no_parent_no_relationship(self):
        child = _obs(entity_type="Domain-Name", value="rootdomain.com")
        _wire(self.c, child)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        self.c.helper.api.stix_core_relationship.create.assert_not_called()

    def test_malicious_root_domain_cascades_to_subdomain(self):
        child  = _obs(entity_type="Domain-Name", value="cdn.evil.com",   score=50)
        parent = _obs(entity_id="dom-001",       entity_type="Domain-Name",
                      value="evil.com", score=85)
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        assert LABEL_INHERITED_MALICIOUS_CASCADE in _labels_created(self.c.helper)


# ══════════════════════════════════════════════════════════════════════════════
# URL linking
# ══════════════════════════════════════════════════════════════════════════════

class TestUrlLinking:

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()

    def test_url_subdomain_host_linked_to_root_domain(self):
        child  = _obs(entity_type="Url", value="https://sub.example.com/malware.bin")
        parent = _obs(entity_id="dom-001", entity_type="Domain-Name",
                      value="example.com", score=50)
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "Url"})

        self.c.helper.api.stix_core_relationship.create.assert_called_once()

    def test_url_ip_host_linked_to_cidr_parent(self):
        child  = _obs(entity_type="Url", value="http://10.0.1.2/payload")
        parent = _obs(entity_id="cidr-001", entity_type="IPv4-Addr",
                      value="10.0.1.0/24", score=50)
        _wire(self.c, child, parent)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "Url"})

        self.c.helper.api.stix_core_relationship.create.assert_called_once()


# ══════════════════════════════════════════════════════════════════════════════
# X509-Certificate linking
# ══════════════════════════════════════════════════════════════════════════════

class TestX509Linking:

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()

    def test_cert_issuer_dn_does_not_create_parent_link(self):
        child = _obs(
            entity_type="X509-Certificate",
            value="CN=leaf",
            issuer="CN=Root CA,O=Corp",
            subject="CN=leaf",
        )
        _wire(self.c, child)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "X509-Certificate"})

        self.c.helper.api.stix_core_relationship.create.assert_not_called()
        self.c.helper.api.stix_cyber_observable.create.assert_not_called()

    def test_self_signed_cert_no_parent_link(self):
        dn = "CN=SelfSigned,O=Test"
        child = _obs(entity_type="X509-Certificate", value=dn, issuer=dn, subject=dn)
        _wire(self.c, child)

        self.c.process_message({"entity_id": "obs-001", "entity_type": "X509-Certificate"})

        self.c.helper.api.stix_core_relationship.create.assert_not_called()

    def test_x509_issuer_dn_never_creates_duplicate_ca_anchor(self):
        c = _make_connector()
        leaf = _obs(
            entity_type="X509-Certificate", value="CN=leaf",
            issuer="CN=Root CA,O=Corp", subject="CN=leaf",
        )
        c.helper.api.stix_cyber_observable.read.return_value = leaf
        c.helper.api.stix_cyber_observable.list.return_value = []

        c.process_message({"entity_id": "obs-001", "entity_type": "X509-Certificate"})
        c.process_message({"entity_id": "obs-001", "entity_type": "X509-Certificate"})

        c.helper.api.stix_cyber_observable.create.assert_not_called()
        c.helper.api.stix_core_relationship.create.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# Label-only path — ASN owner + TLS profile (KEY: "asn, owner ioc get linked")
# ══════════════════════════════════════════════════════════════════════════════

class TestLabelOnly:
    """
    Autonomous-System (owner) and Network-Traffic (TLS profile) do not create
    parent observables — they cluster via label only.
    """

    # ── Autonomous-System → owner ─────────────────────────────────────────────

    def test_asn_owner_cluster_label_applied(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c._get_asn_owner = MagicMock(return_value="GOOGLE LLC")
        child = _obs(entity_type="Autonomous-System", value="AS15169")
        _wire(c, child)

        result = c.process_message({"entity_id": "obs-001", "entity_type": "Autonomous-System"})

        labels = _labels_created(c.helper)
        assert f"{CLUSTER_LABEL_PREFIX}:asn-owner:GOOGLE LLC" in labels
        assert "labelled" in result

    def test_asn_owner_label_color_is_cluster_blue(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c._get_asn_owner = MagicMock(return_value="FASTLY INC")
        child = _obs(entity_type="Autonomous-System", value="AS54113")
        _wire(c, child)

        c.process_message({"entity_id": "obs-001", "entity_type": "Autonomous-System"})

        owner_label_calls = [
            call for call in c.helper.api.label.create.call_args_list
            if "asn-owner" in (call.kwargs.get("value") or "")
        ]
        assert owner_label_calls[0].kwargs["color"] == COLOR_CLUSTER

    def test_asn_no_parent_observable_created(self):
        """Label-only path must never create a parent observable."""
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c._get_asn_owner = MagicMock(return_value="CLOUDFLARE INC")
        child = _obs(entity_type="Autonomous-System", value="AS13335")
        _wire(c, child)

        c.process_message({"entity_id": "obs-001", "entity_type": "Autonomous-System"})

        c.helper.api.stix_cyber_observable.create.assert_not_called()
        c.helper.api.stix_core_relationship.create.assert_not_called()

    def test_asn_rdap_disabled_no_label(self):
        c = _make_connector()   # RDAP off
        child = _obs(entity_type="Autonomous-System", value="AS15169")
        _wire(c, child)

        c.process_message({"entity_id": "obs-001", "entity_type": "Autonomous-System"})

        labels = _labels_created(c.helper)
        assert not any("asn-owner" in lbl for lbl in labels)

    # ── Network-Traffic → TLS profile ─────────────────────────────────────────

    def test_ja4_profile_cluster_label_applied(self):
        c = _make_connector()
        child = _obs(
            entity_type="Network-Traffic",
            value="t13d1516h2_8daaf6152771_e5627efa2ab1",
        )
        _wire(c, child)

        result = c.process_message({"entity_id": "obs-001", "entity_type": "Network-Traffic"})

        labels = _labels_created(c.helper)
        assert f"{CLUSTER_LABEL_PREFIX}:tls-profile:t13d1516h2" in labels
        assert "labelled" in result

    def test_ja3_no_profile_no_cluster_label(self):
        c = _make_connector()
        child = _obs(
            entity_type="Network-Traffic",
            value="0cc9d7dbbdcbaa0aa48e7c5f87c83cf8",   # JA3 MD5 — no profile
        )
        _wire(c, child)

        c.process_message({"entity_id": "obs-001", "entity_type": "Network-Traffic"})

        labels = _labels_created(c.helper)
        assert not any("tls-profile" in lbl for lbl in labels)

    def test_label_only_already_present_not_duplicated(self):
        already = f"{CLUSTER_LABEL_PREFIX}:tls-profile:t13d1516h2"
        c = _make_connector()
        child = _obs(
            entity_type="Network-Traffic",
            value="t13d1516h2_8daaf6152771_e5627efa2ab1",
            labels=[already],
        )
        _wire(c, child)

        c.process_message({"entity_id": "obs-001", "entity_type": "Network-Traffic"})

        # label.create should NOT have been called for the cluster label
        labels = _labels_created(c.helper)
        assert already not in labels, "existing label must not be re-added"


# ══════════════════════════════════════════════════════════════════════════════
# Ubiquity heuristic
# ══════════════════════════════════════════════════════════════════════════════

class TestUbiquity:
    """
    An observable with sightings ≥ threshold and score ≤ unknown_score_max
    should be labelled 'fp-candidate', regardless of whether it has a parent.
    """

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()

    def test_sightings_above_threshold_adds_fp_candidate(self):
        child = _obs(value="8.8.4.4", score=30)
        _wire(self.c, child)
        # 15 sightings ≥ threshold (10)
        self.c.helper.api.stix_sighting_relationship.list.return_value = [{}] * 15

        result = self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        labels = _labels_created(self.c.helper)
        assert LABEL_FP_CANDIDATE in labels
        assert "fp-candidate" in result
        assert "ubiquity" in result

    def test_sightings_below_threshold_no_fp_candidate(self):
        child = _obs(value="8.8.4.4", score=30)
        _wire(self.c, child)
        self.c.helper.api.stix_sighting_relationship.list.return_value = [{}] * 5  # < 10

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_FP_CANDIDATE not in _labels_created(self.c.helper)

    def test_ubiquity_blocked_by_high_score(self):
        child = _obs(value="8.8.4.4", score=80)   # > unknown_score_max=50
        _wire(self.c, child)
        self.c.helper.api.stix_sighting_relationship.list.return_value = [{}] * 20

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_FP_CANDIDATE not in _labels_created(self.c.helper)

    def test_ubiquity_blocked_when_malicious_context_present(self):
        child = _obs(
            value="8.8.4.4", score=30,
            indicators=[{"x_opencti_score": 90}],
        )
        _wire(self.c, child)
        self.c.helper.api.stix_sighting_relationship.list.return_value = [{}] * 20

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_FP_CANDIDATE not in _labels_created(self.c.helper)

    def test_ubiquity_not_added_when_already_fp_candidate(self):
        child = _obs(value="8.8.4.4", score=30, labels=[LABEL_FP_CANDIDATE])
        _wire(self.c, child)
        self.c.helper.api.stix_sighting_relationship.list.return_value = [{}] * 20

        self.c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        fp_label_adds = [
            c for c in self.c.helper.api.label.create.call_args_list
            if (c.kwargs.get("value") or "") == LABEL_FP_CANDIDATE
        ]
        assert len(fp_label_adds) == 0, "label already present — no duplicate add"

    def test_stixfile_no_parent_ubiquity_still_applied(self):
        """StixFile has no parent path; ubiquity heuristic must still run."""
        child = _obs(entity_type="StixFile", value="sha256:deadbeef", score=20)
        _wire(self.c, child)
        self.c.helper.api.stix_sighting_relationship.list.return_value = [{}] * 15

        result = self.c.process_message({"entity_id": "obs-001", "entity_type": "StixFile"})

        assert LABEL_FP_CANDIDATE in _labels_created(self.c.helper)
        assert "ubiquity" in result


# ══════════════════════════════════════════════════════════════════════════════
# Audit note
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditNote:

    def test_audit_note_created_when_actions_taken(self):
        c = _make_connector()
        child  = _obs(value="1.2.3.4",     score=50)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=80)
        _wire(c, child, parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c.helper.api.note.create.assert_called_once()
        call_kwargs = c.helper.api.note.create.call_args.kwargs
        assert "obs-001" in call_kwargs.get("objectRefs", [])
        assert "Trust Cluster" in (call_kwargs.get("abstract") or "")

    def test_no_audit_note_when_no_actions(self):
        """If nothing changed, no audit note should be written."""
        c = _make_connector()
        # StixFile with no parent, score above ubiquity max, no sightings
        child = _obs(entity_type="StixFile", value="sha256:deadbeef", score=80)
        _wire(c, child)

        c.process_message({"entity_id": "obs-001", "entity_type": "StixFile"})

        c.helper.api.note.create.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# _get_authoritative_ns — DNS NS lookup
# ══════════════════════════════════════════════════════════════════════════════

class TestGetAuthoritativeNs:
    """DNS NS lookup helper — mocks dns.resolver.resolve to avoid real queries."""

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector({"TRUST_CLUSTER_USE_NS_LOOKUP": "true"})

    @staticmethod
    def _ns_answers(hostnames: list[str]):
        """Build minimal mock dns.resolver answer objects with plain-string targets."""
        answers = []
        for h in hostnames:
            rec = MagicMock()
            rec.target = f"{h}."   # plain str so str(rec.target) works correctly
            answers.append(rec)
        return answers

    def test_returns_primary_ns(self):
        with patch.object(_dns_resolver, 'resolve',
                          return_value=self._ns_answers(['ns1.bulletproof.ru'])):
            assert self.c._get_authoritative_ns('evil.com') == 'ns1.bulletproof.ru'

    def test_sorts_picks_first_alphabetically(self):
        """Deterministic: ns1 chosen over ns2 when ns2 is returned first."""
        with patch.object(_dns_resolver, 'resolve',
                          return_value=self._ns_answers(['ns2.provider.com', 'ns1.provider.com'])):
            assert self.c._get_authoritative_ns('evil.com') == 'ns1.provider.com'

    def test_trailing_dot_stripped(self):
        with patch.object(_dns_resolver, 'resolve',
                          return_value=self._ns_answers(['ns1.registrar.com'])):
            result = self.c._get_authoritative_ns('evil.com')
        assert result == 'ns1.registrar.com'
        assert not result.endswith('.')

    def test_circular_ns_returns_none(self):
        """NS under same root domain must not create a cycle."""
        with patch.object(_dns_resolver, 'resolve',
                          return_value=self._ns_answers(['ns1.evil.com'])):
            assert self.c._get_authoritative_ns('evil.com') is None

    def test_circular_ns_returns_none_cctld(self):
        """B1: cycle guard works for ccTLD roots (old [-2:] slice would miss this)."""
        with patch.object(_dns_resolver, 'resolve',
                          return_value=self._ns_answers(['ns1.example.co.uk'])):
            assert self.c._get_authoritative_ns('example.co.uk') is None

    def test_dns_failure_returns_none(self):
        with patch.object(_dns_resolver, 'resolve', side_effect=Exception('NXDOMAIN')):
            assert self.c._get_authoritative_ns('nonexistent.invalid') is None

    def test_result_cached_no_second_query(self):
        with patch.object(_dns_resolver, 'resolve',
                          return_value=self._ns_answers(['ns1.provider.com'])) as mock_resolve:
            first  = self.c._get_authoritative_ns('evil.com')
            second = self.c._get_authoritative_ns('evil.com')
        assert first == second == 'ns1.provider.com'
        assert mock_resolve.call_count == 1

    def test_none_cached_on_failure(self):
        """Failed lookup is cached so the DNS query is not retried per observable."""
        with patch.object(_dns_resolver, 'resolve',
                          side_effect=Exception('timeout')) as mock_resolve:
            self.c._get_authoritative_ns('evil.com')
            self.c._get_authoritative_ns('evil.com')
        assert mock_resolve.call_count == 1
        assert self.c._ns_cache['evil.com'] is None


# ══════════════════════════════════════════════════════════════════════════════
# Domain-Name parent extraction with NS lookup enabled
# ══════════════════════════════════════════════════════════════════════════════

class TestExtractParentDomainNsLookup:

    def test_ns_lookup_default_is_off(self):
        env = {k: v for k, v in _ENV_BASE.items() if k != "TRUST_CLUSTER_USE_NS_LOOKUP"}
        with patch.dict(os.environ, env, clear=True):
            c = IocTrustClusterConnector()
        c.helper = MagicMock()
        c._get_authoritative_ns = MagicMock(return_value='ns1.bulletproof.ru')

        assert c._extract_parent("Domain-Name", "evil.com") is None
        c._get_authoritative_ns.assert_not_called()

    def test_root_domain_returns_ns_parent(self):
        c = _make_connector({"TRUST_CLUSTER_USE_NS_LOOKUP": "true"})
        c._get_authoritative_ns = MagicMock(return_value='ns1.bulletproof.ru')
        assert c._extract_parent("Domain-Name", "evil.com") == ("Domain-Name", "ns1.bulletproof.ru")

    def test_root_domain_ns_fails_returns_none(self):
        c = _make_connector({"TRUST_CLUSTER_USE_NS_LOOKUP": "true"})
        c._get_authoritative_ns = MagicMock(return_value=None)
        assert c._extract_parent("Domain-Name", "evil.com") is None

    def test_root_domain_ns_equals_value_returns_none(self):
        """Degenerate: NS hostname == queried domain itself."""
        c = _make_connector({"TRUST_CLUSTER_USE_NS_LOOKUP": "true"})
        c._get_authoritative_ns = MagicMock(return_value='evil.com')
        assert c._extract_parent("Domain-Name", "evil.com") is None

    def test_subdomain_returns_root_not_ns(self):
        """NS lookup must NOT run for subdomains — only root domains."""
        c = _make_connector({"TRUST_CLUSTER_USE_NS_LOOKUP": "true"})
        c._get_authoritative_ns = MagicMock()
        assert c._extract_parent("Domain-Name", "sub.evil.com") == ("Domain-Name", "evil.com")
        c._get_authoritative_ns.assert_not_called()

    def test_ns_lookup_disabled_returns_none_for_root(self):
        c = _make_connector({"TRUST_CLUSTER_USE_NS_LOOKUP": "false"})
        c._get_authoritative_ns = MagicMock()
        assert c._extract_parent("Domain-Name", "evil.com") is None
        c._get_authoritative_ns.assert_not_called()

    def test_allowlisted_ns_provider_returns_none(self):
        """#2: NS under an allowlisted provider (Cloudflare etc.) must not become a parent."""
        c = _make_connector({
            "TRUST_CLUSTER_USE_NS_LOOKUP": "true",
            "TRUST_CLUSTER_NS_ALLOWLIST":  "cloudflare.com,amazonaws.com",
        })
        c._get_authoritative_ns = MagicMock(return_value="ns1.cloudflare.com")
        assert c._extract_parent("Domain-Name", "example.com") is None

    def test_non_allowlisted_ns_returns_parent(self):
        """#2: NS not in allowlist produces a normal parent as before."""
        c = _make_connector({
            "TRUST_CLUSTER_USE_NS_LOOKUP": "true",
            "TRUST_CLUSTER_NS_ALLOWLIST":  "cloudflare.com,amazonaws.com",
        })
        c._get_authoritative_ns = MagicMock(return_value="ns1.bulletproof.ru")
        assert c._extract_parent("Domain-Name", "evil.com") == ("Domain-Name", "ns1.bulletproof.ru")

    def test_empty_allowlist_does_not_filter_ns(self):
        """#2: empty allowlist preserves original behaviour (all NS allowed)."""
        c = _make_connector({
            "TRUST_CLUSTER_USE_NS_LOOKUP": "true",
            "TRUST_CLUSTER_NS_ALLOWLIST":  "",
        })
        c._get_authoritative_ns = MagicMock(return_value="ns1.cloudflare.com")
        assert c._extract_parent("Domain-Name", "example.com") == ("Domain-Name", "ns1.cloudflare.com")

    def test_allowlist_cctld_ns_provider_blocked(self):
        """#2 + B1: ccTLD NS provider allowlist check uses PSL-aware extraction."""
        c = _make_connector({
            "TRUST_CLUSTER_USE_NS_LOOKUP": "true",
            "TRUST_CLUSTER_NS_ALLOWLIST":  "cloudflare.co.uk",
        })
        # ns1.cloudflare.co.uk is under cloudflare.co.uk (a hypothetical ccTLD provider)
        c._get_authoritative_ns = MagicMock(return_value="ns1.cloudflare.co.uk")
        assert c._extract_parent("Domain-Name", "example.com") is None

    def test_malicious_ns_cascades_to_root_domain(self):
        """End-to-end: root domain linked to malicious NS → gets malicious-cascade."""
        c = _make_connector({"TRUST_CLUSTER_USE_NS_LOOKUP": "true"})
        c._get_authoritative_ns = MagicMock(return_value='ns1.bulletproof.ru')

        child  = _obs(entity_type="Domain-Name", value="evil.com",          score=50)
        parent = _obs(entity_id="ns-001",        entity_type="Domain-Name",
                      value="ns1.bulletproof.ru", score=85)
        _wire(c, child, parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        assert LABEL_INHERITED_MALICIOUS_CASCADE in _labels_created(c.helper)

    def test_benign_ns_propagates_fp_candidate_to_root_domain(self):
        """Root domain under a benign NS inherits fp-candidate."""
        c = _make_connector({"TRUST_CLUSTER_USE_NS_LOOKUP": "true"})
        c._get_authoritative_ns = MagicMock(return_value='ns1.goodprovider.com')

        child  = _obs(entity_type="Domain-Name", value="legit.com",          score=20)
        parent = _obs(entity_id="ns-002",        entity_type="Domain-Name",
                      value="ns1.goodprovider.com", score=20,
                      labels=[LABEL_FP_CONFIRMED])
        _wire(c, child, parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        assert LABEL_INHERITED_FP_CANDIDATE in _labels_created(c.helper)


# ══════════════════════════════════════════════════════════════════════════════
# Already-clustered short-circuit
# ══════════════════════════════════════════════════════════════════════════════

class TestAlreadyClustered:
    """
    Verify the short-circuit path: observables that already carry a
    trust-cluster:* label skip DNS/RDAP re-discovery and structural
    re-linking, but still re-check parent verdict on each trigger.
    """

    def test_skips_extract_parent_when_already_clustered(self):
        """_extract_parent must not be called when cluster label already exists."""
        c = _make_connector()
        child = _obs(
            value="1.2.3.4", score=50,
            labels=[f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24"],
        )
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]
        c._extract_parent = MagicMock(wraps=c._extract_parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c._extract_parent.assert_not_called()

    def test_skips_relationship_and_label_when_already_clustered(self):
        """Already-clustered observable must not re-create relationship or labels."""
        c = _make_connector()
        cluster_lbl = f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24"
        child = _obs(value="1.2.3.4", score=50, labels=[cluster_lbl])
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_core_relationship.create.assert_not_called()
        # Cluster label must not be re-added (already present)
        added = _labels_created(c.helper)
        assert cluster_lbl not in added

    def test_still_cascades_malicious_when_parent_later_scored_high(self):
        """
        Already-clustered child with UNKNOWN parent that later becomes
        CONFIRMED_MALICIOUS must receive malicious-cascade on next trigger.
        """
        c = _make_connector()
        child = _obs(
            value="1.2.3.4", score=50,
            labels=[f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24"],  # previously clustered
        )
        # Parent is now malicious (score changed since first processing)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_INHERITED_MALICIOUS_CASCADE in _labels_created(c.helper)

    def test_no_revocation_when_parent_still_malicious(self):
        """
        #4: parent still CONFIRMED_MALICIOUS — no revocation note, no label changes.
        The revocation check runs (parent is looked up), but finding it still
        malicious means nothing is surfaced to the analyst.
        """
        c = _make_connector()
        child = _obs(
            value="1.2.3.4", score=50,
            labels=[
                f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24",
                LABEL_MALICIOUS_CASCADE,
            ],
        )
        # Parent remains CONFIRMED_MALICIOUS
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        # No revocation note (parent still malicious)
        revocation_notes = [
            call for call in c.helper.api.note.create.call_args_list
            if "revocation" in (call.kwargs.get("abstract") or "").lower()
        ]
        assert len(revocation_notes) == 0
        # No label changes
        assert not _labels_created(c.helper)

    def test_orphaned_child_logs_warning(self):
        """
        B7: already-clustered child whose parent no longer exists must log
        a WARNING so the silent cascade blackhole is visible in production logs.
        """
        c = _make_connector()
        child = _obs(
            value="1.2.3.4", score=50,
            labels=[f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24"],
        )
        c.helper.api.stix_cyber_observable.read.return_value = child
        # Parent lookup returns nothing — parent was deleted
        c.helper.api.stix_cyber_observable.list.return_value = []

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert c.helper.log_warning.called
        warning_text = str(c.helper.log_warning.call_args)
        assert "stale cluster label" in warning_text or "not found" in warning_text

    def test_x509_already_clustered_uses_x509_type_not_domain_name(self):
        """
        Regression for: already-clustered X509 child looked up parent as
        Domain-Name (wrong type), silently missed cascade updates after
        first run.

        The already-clustered label inference must resolve X509-Certificate
        children to X509-Certificate parents, not fall through to Domain-Name.
        An issuer DN ('CN=Root CA,O=Corp') contains no '/' and no label-only
        prefix, so without the explicit X509 branch it became 'Domain-Name'.
        """
        c = _make_connector()
        cluster_lbl = f"{CLUSTER_LABEL_PREFIX}:CN=Root CA,O=Corp"
        child = _obs(
            entity_type="X509-Certificate", value="CN=leaf.corp.com",
            score=50, labels=[cluster_lbl],
            issuer="CN=Root CA,O=Corp", subject="CN=leaf.corp.com",
        )
        # Parent CA is now malicious (score changed since first run)
        ca_parent = _obs(
            entity_id="ca-001", entity_type="X509-Certificate",
            value="CN=Root CA,O=Corp", score=85,
            subject="CN=Root CA,O=Corp",
        )
        # Simulate production: list() only returns results when types=['X509-Certificate']
        def _typed_list(*args, **kwargs):
            types_arg = kwargs.get("types") or []
            return [ca_parent] if "X509-Certificate" in types_arg else []
        c.helper.api.stix_cyber_observable.list.side_effect = _typed_list
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(ca_parent)]

        result = c.process_message({"entity_id": "obs-001", "entity_type": "X509-Certificate"})

        assert LABEL_INHERITED_MALICIOUS_CASCADE in _labels_created(c.helper), (
            "malicious CA must cascade to already-clustered child cert "
            "(previously silently skipped due to wrong parent type lookup)"
        )
        assert "malicious-cascade" in result

    def test_already_clustered_domain_uses_label_not_ns_lookup(self):
        """Domain with existing cluster label must skip NS DNS lookup."""
        c = _make_connector({"TRUST_CLUSTER_USE_NS_LOOKUP": "true"})
        c._get_authoritative_ns = MagicMock()
        child = _obs(
            entity_type="Domain-Name", value="evil.com", score=50,
            labels=[f"{CLUSTER_LABEL_PREFIX}:ns1.bulletproof.ru"],
        )
        parent = _obs(entity_id="ns-001", entity_type="Domain-Name",
                      value="ns1.bulletproof.ru", score=50)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]

        c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        c._get_authoritative_ns.assert_not_called()

    def test_revocation_note_created_when_parent_no_longer_malicious(self):
        """
        #4: child carries malicious-cascade; parent score later reset to UNKNOWN.
        Revocation advisory Note must be created on the next enrichment cycle.
        """
        c = _make_connector()
        child = _obs(
            value="1.2.3.4", score=50,
            labels=[
                f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24",
                LABEL_MALICIOUS_CASCADE,   # was cascaded on a prior cycle
            ],
        )
        # Parent score has since been reset to UNKNOWN (50)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        revocation_notes = [
            call for call in c.helper.api.note.create.call_args_list
            if "cascade revocation —" in (call.kwargs.get("abstract") or "")
        ]
        assert len(revocation_notes) == 1
        assert "obs-001" in revocation_notes[0].kwargs.get("objectRefs", [])

    def test_revocation_note_not_duplicated_across_triggers(self):
        """#4: revocation note created once per session, not on every trigger."""
        c = _make_connector()
        child = _obs(
            value="1.2.3.4", score=50,
            labels=[
                f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24",
                LABEL_MALICIOUS_CASCADE,
            ],
        )
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)  # UNKNOWN
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        revocation_notes = [
            call for call in c.helper.api.note.create.call_args_list
            if "cascade revocation —" in (call.kwargs.get("abstract") or "")
        ]
        assert len(revocation_notes) == 1   # deduplicated by session set

    def test_conflict_note_not_duplicated_across_triggers(self):
        """#5: conflict note created once per session when both labels coexist."""
        c = _make_connector()
        child = _obs(
            value="1.2.3.4", score=30,
            labels=[
                f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24",
                LABEL_FP_CANDIDATE,
            ],
        )
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        _wire(c, child, parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        conflict_notes = [
            call for call in c.helper.api.note.create.call_args_list
            if "conflict" in (call.kwargs.get("abstract") or "").lower()
        ]
        assert len(conflict_notes) == 1   # deduplicated by session set


# ══════════════════════════════════════════════════════════════════════════════
# Relationship-source-of-truth (TC3)
# ══════════════════════════════════════════════════════════════════════════════

class TestRelationshipSourceOfTruth:

    @pytest.mark.parametrize("parents", [
        [
            _obs(entity_id="benign", entity_type="Domain-Name", value="good.example", score=20, labels=[LABEL_FP_CONFIRMED]),
            _obs(entity_id="bad", entity_type="Domain-Name", value="evil.example", score=85),
        ],
        [
            _obs(entity_id="bad", entity_type="Domain-Name", value="evil.example", score=85),
            _obs(entity_id="benign", entity_type="Domain-Name", value="good.example", score=20, labels=[LABEL_FP_CONFIRMED]),
        ],
    ])
    def test_multi_parent_malicious_wins_order_independent(self, parents):
        c = _make_connector()
        child = _obs(entity_type="Domain-Name", value="host.example", score=30)
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(p) for p in parents]

        result = c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        labels = _labels_created(c.helper)
        assert LABEL_INHERITED_MALICIOUS_CASCADE in labels
        assert LABEL_FP_CANDIDATE not in labels
        assert "malicious-cascade" in result

    @pytest.mark.parametrize("parents", [
        [
            _obs(entity_id="unknown", entity_type="Domain-Name", value="maybe.example", score=50),
            _obs(entity_id="benign", entity_type="Domain-Name", value="good.example", score=20, labels=[LABEL_FP_CONFIRMED]),
        ],
        [
            _obs(entity_id="benign", entity_type="Domain-Name", value="good.example", score=20, labels=[LABEL_FP_CONFIRMED]),
            _obs(entity_id="unknown", entity_type="Domain-Name", value="maybe.example", score=50),
        ],
    ])
    def test_multi_parent_unknown_blocks_benign_order_independent(self, parents):
        c = _make_connector()
        child = _obs(entity_type="Domain-Name", value="host.example", score=30)
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(p) for p in parents]

        result = c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        labels = _labels_created(c.helper)
        assert LABEL_MALICIOUS_CASCADE not in labels
        assert LABEL_FP_CANDIDATE not in labels
        assert "inherited" not in result

    def test_multi_parent_all_benign_inherits_fp_candidate(self):
        c = _make_connector()
        child = _obs(entity_type="Domain-Name", value="host.example", score=30)
        parents = [
            _obs(entity_id="b1", entity_type="Domain-Name", value="good1.example", score=20, labels=[LABEL_FP_CONFIRMED]),
            _obs(entity_id="b2", entity_type="Domain-Name", value="good2.example", score=10, labels=[LABEL_FP_CONFIRMED]),
        ]
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(p) for p in parents]

        result = c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        assert LABEL_INHERITED_FP_CANDIDATE in _labels_created(c.helper)
        assert "fp-candidate inherited" in result

    def test_relationship_parent_lookup_requests_all_pages(self):
        c = _make_connector()
        child = _obs(value="1.2.3.4", score=50, labels=[])
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_core_relationship.list.assert_any_call(
            fromId="obs-001", relationship_type="related-to", getAll=True
        )

    def test_related_to_edge_drives_inheritance(self):
        c = _make_connector()
        child = _obs(value="1.2.3.4", score=50, labels=[])
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.side_effect = (
            lambda **kw: [_trust_rel(parent)] if kw.get("relationship_type") == "related-to" else []
        )

        result = c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_INHERITED_MALICIOUS_CASCADE in _labels_created(c.helper)
        assert "malicious-cascade from IPv4-Addr:1.2.3.0/24" in result
        c.helper.api.stix_core_relationship.create.assert_not_called()

    def test_existing_relationship_reads_parent_when_edge_payload_is_partial(self):
        c = _make_connector()
        child = _obs(value="1.2.3.4", score=50, labels=[])
        partial_parent = {
            "id": "cidr-001",
            "entity_type": "IPv4-Addr",
            "observable_value": "1.2.3.0/24",
        }
        full_parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        c.helper.api.stix_cyber_observable.read.side_effect = (
            lambda id: child if id == "obs-001" else full_parent
        )
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(partial_parent)]

        result = c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_cyber_observable.read.assert_any_call(id="cidr-001")
        assert LABEL_INHERITED_MALICIOUS_CASCADE in _labels_created(c.helper)
        assert "malicious-cascade from IPv4-Addr:1.2.3.0/24" in result

    def test_existing_relationship_missing_label_no_duplicate_rel(self):
        c = _make_connector()
        child = _obs(value="1.2.3.4", score=50, labels=[])
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]

        result = c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_core_relationship.create.assert_not_called()
        labels = _labels_created(c.helper)
        assert f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24" not in labels
        assert LABEL_INHERITED_MALICIOUS_CASCADE in labels
        assert "repaired cluster label" not in result

    def test_existing_relationship_skips_parent_extraction(self):
        c = _make_connector({"TRUST_CLUSTER_USE_RDAP": "true"})
        c._get_announced_cidr = MagicMock(return_value="9.9.9.0/24")
        child = _obs(value="1.2.3.4", score=50, labels=[])
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c._get_announced_cidr.assert_not_called()
        assert c._known_cidrs_loaded is False
        c.helper.api.stix_cyber_observable.create.assert_not_called()

    def test_stale_label_existing_parent_recreates_relationship(self):
        c = _make_connector()
        cluster_lbl = f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24"
        child = _obs(value="1.2.3.4", score=50, labels=[cluster_lbl])
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = []

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_core_relationship.create.assert_called_once_with(
            fromId="obs-001", toId="cidr-001",
            relationship_type="related-to",
            description="IOC trust-cluster structural parent link (auto-created)",
            confidence=75,
        )
        child_label_adds = [
            call for call in c.helper.api.stix_cyber_observable.add_label.call_args_list
            if call.kwargs.get("id") == "obs-001"
        ]
        assert not child_label_adds  # child label already present

    def test_stale_label_missing_parent_warns_no_crash(self):
        c = _make_connector()
        child = _obs(
            value="1.2.3.4", score=50,
            labels=[f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24"],
        )
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_core_relationship.list.return_value = []
        c.helper.api.stix_cyber_observable.list.return_value = []

        result = c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert "no actions" in result
        c.helper.api.stix_core_relationship.create.assert_not_called()
        assert c.helper.log_warning.called
        assert "stale cluster label" in str(c.helper.log_warning.call_args)

    def test_stale_x509_issuer_dn_label_does_not_recreate_relationship(self):
        c = _make_connector()
        cluster_lbl = f"{CLUSTER_LABEL_PREFIX}:CN=Root CA,O=Corp"
        child = _obs(
            entity_type="X509-Certificate", value="CN=leaf.corp.com",
            score=50, labels=[cluster_lbl],
            issuer="CN=Root CA,O=Corp", subject="CN=leaf.corp.com",
        )
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_core_relationship.list.return_value = []

        c.process_message({"entity_id": "obs-001", "entity_type": "X509-Certificate"})

        c.helper.api.stix_core_relationship.create.assert_not_called()
        c.helper.api.stix_cyber_observable.create.assert_not_called()


# ══════════════════════════════════════════════════════════════════════════════
# Connector-owned inherited state retraction (580)
# ══════════════════════════════════════════════════════════════════════════════

class TestInheritedStateRetraction:

    def test_unknown_parent_removes_only_namespaced_malicious_state(self):
        c = _make_connector()
        child = _obs(
            value="1.2.3.4", score=50,
            labels=[LABEL_INHERITED_MALICIOUS_CASCADE, LABEL_MALICIOUS_CASCADE],
        )
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]

        result = c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_cyber_observable.remove_label.assert_called_once_with(
            id="obs-001", label_id="label-0"
        )
        assert "removed unsupported inherited malicious state" in result

    def test_unknown_parent_removes_only_namespaced_fp_state(self):
        c = _make_connector()
        child = _obs(
            entity_type="Domain-Name", value="host.example", score=30,
            labels=[LABEL_INHERITED_FP_CANDIDATE, LABEL_FP_CANDIDATE],
        )
        parent = _obs(entity_id="parent", entity_type="Domain-Name", value="example", score=50)
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]

        result = c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        c.helper.api.stix_cyber_observable.remove_label.assert_called_once_with(
            id="obs-001", label_id="label-0"
        )
        assert "removed unsupported inherited fp state" in result

    def test_mixed_parent_removes_fp_and_adds_malicious_state(self):
        c = _make_connector()
        child = _obs(
            entity_type="Domain-Name", value="host.example", score=30,
            labels=[LABEL_INHERITED_FP_CANDIDATE],
        )
        parents = [
            _obs(entity_id="good", entity_type="Domain-Name", value="good.example", score=20, labels=[LABEL_FP_CONFIRMED]),
            _obs(entity_id="bad", entity_type="Domain-Name", value="bad.example", score=85),
        ]
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(p) for p in parents]

        result = c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        assert LABEL_INHERITED_MALICIOUS_CASCADE in _labels_created(c.helper)
        c.helper.api.stix_cyber_observable.remove_label.assert_called_once_with(
            id="obs-001", label_id="label-0"
        )
        assert "removed unsupported inherited fp state" in result

    def test_benign_parent_keeps_supported_inherited_fp_state(self):
        c = _make_connector()
        child = _obs(
            entity_type="Domain-Name", value="host.example", score=30,
            labels=[LABEL_INHERITED_FP_CANDIDATE],
        )
        parent = _obs(entity_id="good", entity_type="Domain-Name", value="good.example", score=20, labels=[LABEL_FP_CONFIRMED])
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]

        c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        c.helper.api.stix_cyber_observable.remove_label.assert_not_called()

    def test_remove_label_failure_logs_warning_and_leaves_prior_state(self):
        c = _make_connector()
        child = _obs(value="1.2.3.4", score=50, labels=[LABEL_INHERITED_MALICIOUS_CASCADE])
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        c.helper.api.stix_cyber_observable.read.return_value = child
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]
        c.helper.api.stix_cyber_observable.remove_label.side_effect = RuntimeError("boom")

        result = c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert "removed unsupported" not in result
        assert c.helper.log_warning.called


# ══════════════════════════════════════════════════════════════════════════════
# Parent-triggered fanout (TC2)
# ══════════════════════════════════════════════════════════════════════════════

class TestParentFanout:

    @staticmethod
    def _rels_for(parent_id: str, *rels):
        def _list(*args, **kwargs):
            if kwargs.get("toId") == parent_id:
                return list(rels)
            return []
        return _list

    def test_parent_malicious_fanout_labels_direct_child(self):
        c = _make_connector()
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        child = _obs(entity_id="child-1", value="1.2.3.4", score=50)
        c.helper.api.stix_cyber_observable.read.return_value = parent
        c.helper.api.stix_core_relationship.list.side_effect = self._rels_for(
            "cidr-001", _child_rel(child)
        )

        result = c.process_message({"entity_id": "cidr-001", "entity_type": "IPv4-Addr"})

        assert LABEL_INHERITED_MALICIOUS_CASCADE in _labels_created(c.helper)
        c.helper.api.stix_cyber_observable.add_label.assert_called_with(
            id="child-1", label_id="label-id-stub"
        )
        assert "malicious-cascade" in result

    def test_parent_benign_fanout_labels_eligible_child(self):
        c = _make_connector()
        parent = _obs(
            entity_id="cidr-001", value="1.2.3.0/24", score=20,
            labels=[LABEL_FP_CONFIRMED],
        )
        child = _obs(entity_id="child-1", value="1.2.3.4", score=50)
        c.helper.api.stix_cyber_observable.read.return_value = parent
        c.helper.api.stix_core_relationship.list.side_effect = self._rels_for(
            "cidr-001", _child_rel(child)
        )

        result = c.process_message({"entity_id": "cidr-001", "entity_type": "IPv4-Addr"})

        assert LABEL_INHERITED_FP_CANDIDATE in _labels_created(c.helper)
        assert "fp-candidate inherited" in result

    def test_parent_unknown_fanout_creates_revocation_note_for_cascaded_child(self):
        c = _make_connector()
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        child = _obs(
            entity_id="child-1", value="1.2.3.4", score=50,
            labels=[LABEL_MALICIOUS_CASCADE],
        )
        c.helper.api.stix_cyber_observable.read.return_value = parent
        c.helper.api.stix_core_relationship.list.side_effect = self._rels_for(
            "cidr-001", _child_rel(child)
        )

        result = c.process_message({"entity_id": "cidr-001", "entity_type": "IPv4-Addr"})

        revocation_notes = [
            call for call in c.helper.api.note.create.call_args_list
            if "cascade revocation" in (call.kwargs.get("abstract") or "")
        ]
        assert len(revocation_notes) == 1
        assert "cascade-revocation" in result

    def test_parent_fanout_second_run_is_noop_when_label_already_present(self):
        c = _make_connector()
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        child = _obs(
            entity_id="child-1", value="1.2.3.4", score=50,
            labels=[LABEL_MALICIOUS_CASCADE],
        )
        c.helper.api.stix_cyber_observable.read.return_value = parent
        c.helper.api.stix_core_relationship.list.side_effect = self._rels_for(
            "cidr-001", _child_rel(child)
        )

        result = c.process_message({"entity_id": "cidr-001", "entity_type": "IPv4-Addr"})

        assert LABEL_MALICIOUS_CASCADE not in _labels_created(c.helper)
        assert "no actions" in result

    def test_parent_fanout_requests_all_pages_and_uses_late_child(self):
        c = _make_connector()
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        child = _obs(entity_id="child-late", value="1.2.3.200", score=50)
        c.helper.api.stix_cyber_observable.read.return_value = parent
        c.helper.api.stix_core_relationship.list.side_effect = self._rels_for(
            "cidr-001",
            *[{"description": "manual analyst link", "from": _obs(entity_id=f"m{i}")} for i in range(100)],
            _child_rel(child),
        )

        c.process_message({"entity_id": "cidr-001", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_core_relationship.list.assert_any_call(
            toId="cidr-001", relationship_type="related-to", getAll=True
        )
        assert LABEL_INHERITED_MALICIOUS_CASCADE in _labels_created(c.helper)
        c.helper.api.stix_cyber_observable.add_label.assert_called_with(
            id="child-late", label_id="label-id-stub"
        )

    def test_parent_fanout_ignores_non_connector_relationships(self):
        c = _make_connector()
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        child = _obs(entity_id="child-1", value="1.2.3.4", score=50)
        c.helper.api.stix_cyber_observable.read.return_value = parent
        c.helper.api.stix_core_relationship.list.side_effect = self._rels_for(
            "cidr-001", {"description": "manual analyst link", "from": child}
        )

        result = c.process_message({"entity_id": "cidr-001", "entity_type": "IPv4-Addr"})

        assert LABEL_MALICIOUS_CASCADE not in _labels_created(c.helper)
        assert "no actions" in result


# ══════════════════════════════════════════════════════════════════════════════
# _get_resolved_ips — DNS A record lookup
# ══════════════════════════════════════════════════════════════════════════════

class TestGetResolvedIps:
    """A record lookup helper — mocks dns.resolver.resolve."""

    @pytest.fixture(autouse=True)
    def con(self):
        self.c = _make_connector()

    @staticmethod
    def _a_answers(ips: list[str]):
        answers = []
        for ip in ips:
            rec = MagicMock()
            rec.address = ip   # plain str so str(rec.address) works
            answers.append(rec)
        return answers

    def test_returns_ip_list(self):
        with patch.object(_dns_resolver, 'resolve',
                          return_value=self._a_answers(['1.2.3.4', '1.2.3.5'])):
            result = self.c._get_resolved_ips('evil.com')
        assert result == ['1.2.3.4', '1.2.3.5']

    def test_dns_failure_returns_empty(self):
        with patch.object(_dns_resolver, 'resolve', side_effect=Exception('NXDOMAIN')):
            assert self.c._get_resolved_ips('nonexistent.invalid') == []

    def test_result_cached_no_second_query(self):
        with patch.object(_dns_resolver, 'resolve',
                          return_value=self._a_answers(['1.2.3.4'])) as mock_resolve:
            first  = self.c._get_resolved_ips('evil.com')
            second = self.c._get_resolved_ips('evil.com')
        assert first == second == ['1.2.3.4']
        assert mock_resolve.call_count == 1

    def test_empty_result_cached(self):
        with patch.object(_dns_resolver, 'resolve',
                          side_effect=Exception('timeout')) as mock_resolve:
            self.c._get_resolved_ips('evil.com')
            self.c._get_resolved_ips('evil.com')
        assert mock_resolve.call_count == 1
        assert self.c._ip_cache['evil.com'] == []


# ══════════════════════════════════════════════════════════════════════════════
# Sinkhole detection
# ══════════════════════════════════════════════════════════════════════════════

SINKHOLE_IP = "198.51.100.1"
OTHER_IP    = "8.8.8.8"


class TestSinkhole:
    """Sinkhole detection — Domain-Name only, label and cascade."""

    def _con(self, sinkhole: str = SINKHOLE_IP) -> IocTrustClusterConnector:
        return _make_connector({"TRUST_CLUSTER_SINKHOLE_IPS": sinkhole})

    # ── label ────────────────────────────────────────────────────────────────

    def test_sinkholed_domain_gets_label(self):
        c = self._con()
        c._get_resolved_ips = MagicMock(return_value=[SINKHOLE_IP])
        child = _obs(entity_type="Domain-Name", value="evil.com", score=50)
        _wire(c, child)

        result = c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        assert LABEL_SINKHOLED in _labels_created(c.helper)
        assert LABEL_SINKHOLE not in _labels_created(c.helper)
        assert "sinkholed" in result
        assert SINKHOLE_IP in result

    def test_sinkholed_label_color_is_purple(self):
        c = self._con()
        c._get_resolved_ips = MagicMock(return_value=[SINKHOLE_IP])
        child = _obs(entity_type="Domain-Name", value="evil.com", score=50)
        _wire(c, child)
        c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        calls = [cl for cl in c.helper.api.label.create.call_args_list
                 if (cl.kwargs.get("value") or "") == LABEL_SINKHOLED]
        assert calls[0].kwargs["color"] == COLOR_SINKHOLED

    def test_non_sinkhole_ip_no_label(self):
        c = self._con()
        c._get_resolved_ips = MagicMock(return_value=[OTHER_IP])
        child = _obs(entity_type="Domain-Name", value="good.com", score=50)
        _wire(c, child)
        c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        assert LABEL_SINKHOLED not in _labels_created(c.helper)

    def test_no_sinkhole_ips_skips_lookup(self):
        """No sinkhole IPs configured — A record query must not be issued."""
        c = _make_connector({"TRUST_CLUSTER_SINKHOLE_IPS": ""})
        c._get_resolved_ips = MagicMock()
        child = _obs(entity_type="Domain-Name", value="evil.com", score=50)
        _wire(c, child)
        c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        c._get_resolved_ips.assert_not_called()

    @pytest.mark.parametrize("label", [LABEL_SINKHOLE, LABEL_SINKHOLED])
    def test_existing_sinkhole_alias_prevents_duplicate(self, label):
        """Either spelling prevents DNS work and creation of the other alias."""
        c = self._con()
        c._get_resolved_ips = MagicMock()
        child = _obs(entity_type="Domain-Name", value="evil.com",
                     score=50, labels=[label])
        _wire(c, child)
        c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        c._get_resolved_ips.assert_not_called()
        assert not ({LABEL_SINKHOLE, LABEL_SINKHOLED} & set(_labels_created(c.helper)))

    def test_ipv4_type_not_checked(self):
        """Sinkhole check is Domain-Name only."""
        c = self._con()
        c._get_resolved_ips = MagicMock()
        child = _obs(entity_type="IPv4-Addr", value="1.2.3.4", score=50)
        _wire(c, child)
        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c._get_resolved_ips.assert_not_called()

    def test_multiple_sinkhole_ips_any_match_triggers(self):
        c = _make_connector(
            {"TRUST_CLUSTER_SINKHOLE_IPS": f"10.0.0.1,{SINKHOLE_IP},10.0.0.2"}
        )
        c._get_resolved_ips = MagicMock(return_value=["8.8.8.8", SINKHOLE_IP])
        child = _obs(entity_type="Domain-Name", value="evil.com", score=50)
        _wire(c, child)

        result = c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        assert LABEL_SINKHOLED in _labels_created(c.helper)
        assert "sinkholed" in result

    # ── cascade ───────────────────────────────────────────────────────────────

    @pytest.mark.parametrize("label", [LABEL_SINKHOLE, LABEL_SINKHOLED])
    def test_sinkhole_parent_cascades_malicious_to_child(self, label):
        """Either spelling drives one-hop cascade despite a low parent score."""
        c = _make_connector({"TRUST_CLUSTER_USE_NS_LOOKUP": "false"})
        child  = _obs(entity_type="Domain-Name", value="cdn.evil.com",  score=50)
        parent = _obs(entity_id="root-001",      entity_type="Domain-Name",
                      value="evil.com", score=20, labels=[label])
        _wire(c, child, parent)

        c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        assert LABEL_INHERITED_MALICIOUS_CASCADE in _labels_created(c.helper)

    def test_sinkholed_parent_cascade_color_is_red(self):
        c = _make_connector({"TRUST_CLUSTER_USE_NS_LOOKUP": "false"})
        child  = _obs(entity_type="Domain-Name", value="cdn.evil.com",  score=50)
        parent = _obs(entity_id="root-001",      entity_type="Domain-Name",
                      value="evil.com", score=20, labels=[LABEL_SINKHOLED])
        _wire(c, child, parent)
        c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})

        calls = [cl for cl in c.helper.api.label.create.call_args_list
                 if (cl.kwargs.get("value") or "") == LABEL_INHERITED_MALICIOUS_CASCADE]
        assert calls[0].kwargs["color"] == COLOR_MALICIOUS


# ══════════════════════════════════════════════════════════════════════════════
# #8 — Sighting source filter
# ══════════════════════════════════════════════════════════════════════════════

class TestSightingSourceFilter:
    """
    Ubiquity heuristic must only count sightings from approved source connectors
    when TRUST_CLUSTER_SIGHTING_SOURCE_FILTER is set.
    """

    def _sightings(self, creator_ids: list[str]) -> list[dict]:
        return [{"createdBy": {"id": cid}} for cid in creator_ids]

    def test_empty_filter_counts_all_sightings(self):
        """Default behaviour: no filter → all sightings count."""
        c = _make_connector({
            "TRUST_CLUSTER_SIGHTING_SOURCE_FILTER": "",
            "TRUST_CLUSTER_FP_SIGHTING_THRESHOLD": "3",
        })
        child = _obs(value="8.8.4.4", score=30)
        _wire(c, child)
        c.helper.api.stix_sighting_relationship.list.return_value = \
            self._sightings(["connector-A", "connector-B", "connector-C"])

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_FP_CANDIDATE in _labels_created(c.helper)

    def test_filter_counts_only_matching_sources(self):
        """With filter set, only sightings from listed connectors count."""
        c = _make_connector({
            "TRUST_CLUSTER_SIGHTING_SOURCE_FILTER": "connector-SIEM",
            "TRUST_CLUSTER_FP_SIGHTING_THRESHOLD": "3",
        })
        child = _obs(value="8.8.4.4", score=30)
        _wire(c, child)
        # 3 matching + 5 OTX noise sightings → threshold met only via SIEM
        c.helper.api.stix_sighting_relationship.list.return_value = \
            self._sightings(["connector-SIEM"] * 3 + ["connector-OTX"] * 5)

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_FP_CANDIDATE in _labels_created(c.helper)

    def test_filter_blocks_fp_when_only_noise_sightings(self):
        """Sightings from non-listed connectors must not trigger fp-candidate."""
        c = _make_connector({
            "TRUST_CLUSTER_SIGHTING_SOURCE_FILTER": "connector-SIEM",
            "TRUST_CLUSTER_FP_SIGHTING_THRESHOLD": "3",
        })
        child = _obs(value="8.8.4.4", score=30)
        _wire(c, child)
        c.helper.api.stix_sighting_relationship.list.return_value = \
            self._sightings(["connector-OTX"] * 10)   # 10 noise sightings

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_FP_CANDIDATE not in _labels_created(c.helper)

    def test_filter_excludes_sightings_with_no_createdby(self):
        """Sightings missing createdBy are not counted when a filter is active."""
        c = _make_connector({
            "TRUST_CLUSTER_SIGHTING_SOURCE_FILTER": "connector-SIEM",
            "TRUST_CLUSTER_FP_SIGHTING_THRESHOLD": "2",
        })
        child = _obs(value="8.8.4.4", score=30)
        _wire(c, child)
        c.helper.api.stix_sighting_relationship.list.return_value = [
            {},                              # no createdBy key
            {"createdBy": None},             # null createdBy
            {"createdBy": {}},               # empty createdBy
            {"createdBy": {"id": "connector-SIEM"}},  # 1 valid → below threshold 2
        ]

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_FP_CANDIDATE not in _labels_created(c.helper)

    def test_filtered_sightings_after_first_page_are_counted(self):
        c = _make_connector({
            "TRUST_CLUSTER_SIGHTING_SOURCE_FILTER": "connector-SIEM",
            "TRUST_CLUSTER_FP_SIGHTING_THRESHOLD": "3",
        })
        child = _obs(value="8.8.4.4", score=30)
        _wire(c, child)
        c.helper.api.stix_sighting_relationship.list.return_value = \
            self._sightings(["connector-OTX"] * 100 + ["connector-SIEM"] * 3)

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        c.helper.api.stix_sighting_relationship.list.assert_called_with(
            toId="obs-001", getAll=True
        )
        assert LABEL_FP_CANDIDATE in _labels_created(c.helper)

    def test_multi_connector_filter_all_sources_count(self):
        """Multiple connectors in the filter: sightings from any of them count."""
        c = _make_connector({
            "TRUST_CLUSTER_SIGHTING_SOURCE_FILTER": "connector-SIEM,connector-EDR",
            "TRUST_CLUSTER_FP_SIGHTING_THRESHOLD": "3",
        })
        child = _obs(value="8.8.4.4", score=30)
        _wire(c, child)
        c.helper.api.stix_sighting_relationship.list.return_value = \
            self._sightings(["connector-SIEM", "connector-EDR", "connector-SIEM"])

        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})

        assert LABEL_FP_CANDIDATE in _labels_created(c.helper)


# ══════════════════════════════════════════════════════════════════════════════
# #10 — URL sinkhole check
# ══════════════════════════════════════════════════════════════════════════════

_URL_SINKHOLE = "198.51.100.1"


class TestSinkholeUrl:
    """Sinkhole detection extends to Url observables via hostname extraction."""

    def _con(self) -> IocTrustClusterConnector:
        return _make_connector({"TRUST_CLUSTER_SINKHOLE_IPS": _URL_SINKHOLE})

    def test_url_with_sinkholed_host_gets_label(self):
        c = self._con()
        c._get_resolved_ips = MagicMock(return_value=[_URL_SINKHOLE])
        child = _obs(entity_type="Url", value="http://evil.com/payload")
        _wire(c, child)

        result = c.process_message({"entity_id": "obs-001", "entity_type": "Url"})

        assert LABEL_SINKHOLED in _labels_created(c.helper)
        assert "sinkholed" in result

    def test_url_hostname_extracted_not_full_value(self):
        """The A lookup uses the URL hostname, not the full URL string."""
        c = self._con()
        c._get_resolved_ips = MagicMock(return_value=[_URL_SINKHOLE])
        child = _obs(entity_type="Url", value="https://sub.evil.com:443/path?q=1")
        _wire(c, child)

        c.process_message({"entity_id": "obs-001", "entity_type": "Url"})

        c._get_resolved_ips.assert_called_once_with("sub.evil.com")

    def test_url_non_sinkhole_host_no_label(self):
        c = self._con()
        c._get_resolved_ips = MagicMock(return_value=["8.8.8.8"])
        child = _obs(entity_type="Url", value="http://safe.com/page")
        _wire(c, child)

        c.process_message({"entity_id": "obs-001", "entity_type": "Url"})

        assert LABEL_SINKHOLED not in _labels_created(c.helper)

    def test_url_no_hostname_skipped(self):
        """Malformed URL with no extractable hostname must not crash."""
        c = self._con()
        c._get_resolved_ips = MagicMock()
        child = _obs(entity_type="Url", value="not-a-url")
        _wire(c, child)

        c.process_message({"entity_id": "obs-001", "entity_type": "Url"})

        c._get_resolved_ips.assert_not_called()

    def test_url_sinkhole_reuses_ip_cache(self):
        """A record resolved earlier (e.g. for the Domain-Name observable)
        is reused from cache — no duplicate DNS query."""
        c = self._con()
        c._ip_cache["evil.com"] = [_URL_SINKHOLE]  # pre-populated
        c._get_resolved_ips = MagicMock(
            side_effect=lambda d: c._ip_cache.get(d, [])
        )
        child = _obs(entity_type="Url", value="http://evil.com/payload")
        _wire(c, child)

        c.process_message({"entity_id": "obs-001", "entity_type": "Url"})

        assert LABEL_SINKHOLED in _labels_created(c.helper)

    def test_already_sinkholed_url_no_duplicate(self):
        c = self._con()
        c._get_resolved_ips = MagicMock()
        child = _obs(entity_type="Url", value="http://evil.com/payload",
                     labels=[LABEL_SINKHOLED])
        _wire(c, child)

        c.process_message({"entity_id": "obs-001", "entity_type": "Url"})

        c._get_resolved_ips.assert_not_called()

    def test_domain_and_url_both_checked_independently(self):
        """Domain-Name and Url types both trigger the sinkhole path."""
        c = self._con()
        c._get_resolved_ips = MagicMock(return_value=[_URL_SINKHOLE])

        for entity_type, value in [
            ("Domain-Name", "evil.com"),
            ("Url", "http://evil.com/payload"),
        ]:
            c.helper.api.label.create.reset_mock()
            child = _obs(entity_type=entity_type, value=value)
            _wire(c, child)
            c.process_message({"entity_id": "obs-001", "entity_type": entity_type})
            assert LABEL_SINKHOLED in _labels_created(c.helper), \
                f"LABEL_SINKHOLED missing for {entity_type}"


# ══════════════════════════════════════════════════════════════════════════════
# #11 — Stats logging
# ══════════════════════════════════════════════════════════════════════════════

class TestStats:
    """Per-interval stats summary log line."""

    def _stats_lines(self, c: IocTrustClusterConnector) -> list[str]:
        return [
            str(call) for call in c.helper.log_info.call_args_list
            if "stats[last" in str(call)
        ]

    def test_stats_emitted_at_interval(self):
        c = _make_connector({"TRUST_CLUSTER_STATS_INTERVAL": "3"})
        child = _obs(value="1.2.3.4", score=80)
        _wire(c, child)
        for _ in range(3):
            c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        assert len(self._stats_lines(c)) == 1
        assert "stats[last 3]" in self._stats_lines(c)[0]

    def test_stats_not_emitted_before_interval(self):
        c = _make_connector({"TRUST_CLUSTER_STATS_INTERVAL": "10"})
        child = _obs(value="1.2.3.4", score=50)
        _wire(c, child)
        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        assert self._stats_lines(c) == []

    def test_stats_disabled_at_zero(self):
        c = _make_connector({"TRUST_CLUSTER_STATS_INTERVAL": "0"})
        child = _obs(value="1.2.3.4", score=50)
        _wire(c, child)
        for _ in range(200):
            c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        assert self._stats_lines(c) == []

    def test_stats_counts_cascade_malicious(self):
        c = _make_connector({"TRUST_CLUSTER_STATS_INTERVAL": "1"})
        child  = _obs(value="1.2.3.4",      score=50)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        _wire(c, child, parent)
        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        assert "cascade_malicious=1" in self._stats_lines(c)[0]

    def test_stats_counts_cascade_fp(self):
        """cascade_fp counts fp-candidate inherited from a CONFIRMED_BENIGN parent."""
        c = _make_connector({"TRUST_CLUSTER_STATS_INTERVAL": "1"})
        child  = _obs(value="1.2.3.4",      score=30)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24",
                      score=30, labels=[LABEL_FP_CONFIRMED])
        _wire(c, child, parent)
        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        assert "cascade_fp=1"  in self._stats_lines(c)[0]
        assert "ubiquity_fp=0" in self._stats_lines(c)[0]

    def test_stats_counts_ubiquity_fp(self):
        """ubiquity_fp counts fp-candidate set by the sightings heuristic."""
        c = _make_connector({
            "TRUST_CLUSTER_STATS_INTERVAL": "1",
            "TRUST_CLUSTER_FP_SIGHTING_THRESHOLD": "2",
        })
        child = _obs(value="8.8.4.4", score=30)
        _wire(c, child)
        c.helper.api.stix_sighting_relationship.list.return_value = [{}, {}]
        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        assert "ubiquity_fp=1" in self._stats_lines(c)[0]
        assert "cascade_fp=0"  in self._stats_lines(c)[0]

    def test_stats_counts_sinkholed(self):
        c = _make_connector({
            "TRUST_CLUSTER_STATS_INTERVAL": "1",
            "TRUST_CLUSTER_SINKHOLE_IPS": "198.51.100.1",
        })
        c._get_resolved_ips = MagicMock(return_value=["198.51.100.1"])
        child = _obs(entity_type="Domain-Name", value="evil.com", score=50)
        _wire(c, child)
        c.process_message({"entity_id": "obs-001", "entity_type": "Domain-Name"})
        assert "sinkholed=1" in self._stats_lines(c)[0]

    def test_stats_counts_no_actions(self):
        """Observable with nothing to do increments no_actions."""
        c = _make_connector({"TRUST_CLUSTER_STATS_INTERVAL": "1"})
        # StixFile with high score → no parent, no ubiquity trigger
        child = _obs(entity_type="StixFile", value="sha256:deadbeef", score=80)
        _wire(c, child)
        c.process_message({"entity_id": "obs-001", "entity_type": "StixFile"})
        assert "no_actions=1" in self._stats_lines(c)[0]

    def test_stats_counts_already_clustered(self):
        c = _make_connector({"TRUST_CLUSTER_STATS_INTERVAL": "1"})
        cluster_lbl = f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24"
        child = _obs(value="1.2.3.4", score=50, labels=[cluster_lbl])
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]
        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        assert "already_clustered=1" in self._stats_lines(c)[0]

    def test_stats_counts_parent_verdict(self):
        """parents_malicious incremented when parent is CONFIRMED_MALICIOUS."""
        c = _make_connector({"TRUST_CLUSTER_STATS_INTERVAL": "1"})
        child  = _obs(value="1.2.3.4",      score=50)
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        _wire(c, child, parent)
        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        assert "parents_malicious=1" in self._stats_lines(c)[0]

    def test_stats_counts_cascade_revoked(self):
        """B18: cascade_revoked incremented when a revocation advisory is issued."""
        c = _make_connector({"TRUST_CLUSTER_STATS_INTERVAL": "1"})
        child = _obs(
            value="1.2.3.4", score=50,
            labels=[
                f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24",
                LABEL_MALICIOUS_CASCADE,
            ],
        )
        # Parent score has been reset to UNKNOWN
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=50)
        _wire(c, child, parent)
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]
        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        assert "cascade_revoked=1" in self._stats_lines(c)[0]

    def test_stats_counts_cascade_conflict(self):
        """B18: cascade_conflict incremented when a conflict note is issued."""
        c = _make_connector({"TRUST_CLUSTER_STATS_INTERVAL": "1"})
        child = _obs(
            value="1.2.3.4", score=30,
            labels=[
                f"{CLUSTER_LABEL_PREFIX}:1.2.3.0/24",
                LABEL_FP_CANDIDATE,
            ],
        )
        parent = _obs(entity_id="cidr-001", value="1.2.3.0/24", score=85)
        _wire(c, child, parent)
        c.process_message({"entity_id": "obs-001", "entity_type": "IPv4-Addr"})
        assert "cascade_conflict=1" in self._stats_lines(c)[0]

    def test_stats_reset_after_interval(self):
        """Counters reset to zero after each interval window."""
        c = _make_connector({"TRUST_CLUSTER_STATS_INTERVAL": "2"})
        # First two: high-score child (no cascade) — both no_actions
        child = _obs(entity_type="StixFile", value="sha256:aabb", score=80)
        _wire(c, child)
        c.process_message({"entity_id": "obs-001", "entity_type": "StixFile"})
        c.process_message({"entity_id": "obs-001", "entity_type": "StixFile"})
        # Second two: same
        c.process_message({"entity_id": "obs-001", "entity_type": "StixFile"})
        c.process_message({"entity_id": "obs-001", "entity_type": "StixFile"})
        lines = self._stats_lines(c)
        assert len(lines) == 2
        assert "no_actions=2" in lines[0]
        assert "no_actions=2" in lines[1]   # reset → same count in second window


# ══════════════════════════════════════════════════════════════════════════════
# B9 — Bounded session caches
# ══════════════════════════════════════════════════════════════════════════════

class TestCacheBound:
    """B9: session caches are cleared and a single entry written on overflow."""

    def test_cache_cleared_on_overflow(self):
        import connector as _mod
        c = _make_connector()
        maxsize = _mod._CACHE_MAXSIZE
        # Fill to exactly maxsize
        for i in range(maxsize):
            c._ns_cache[f"d{i}.com"] = f"ns{i}.x.com"
        assert len(c._ns_cache) == maxsize
        # One more write should clear and leave only the new entry
        c._cache_set(c._ns_cache, "new.com", "ns.new.com")
        assert len(c._ns_cache) == 1
        assert c._ns_cache["new.com"] == "ns.new.com"

    def test_cache_below_maxsize_not_cleared(self):
        import connector as _mod
        c = _make_connector()
        c._ns_cache["a.com"] = "ns1.a.com"
        c._cache_set(c._ns_cache, "b.com", "ns1.b.com")
        assert len(c._ns_cache) == 2
        assert "a.com" in c._ns_cache

    def test_cache_set_stores_none_values(self):
        """Negative cache entries (None) must also be bounded."""
        c = _make_connector()
        c._cache_set(c._cidr_cache, "1.2.3.4", None)
        assert c._cidr_cache["1.2.3.4"] is None
