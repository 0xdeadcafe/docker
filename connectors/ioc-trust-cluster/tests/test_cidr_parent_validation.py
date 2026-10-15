"""Legacy hints and graph markers cannot substitute for IP containment."""
from unittest.mock import MagicMock
from urllib.parse import urlparse

import pytest

from .test_connector import _make_connector, _obs, _trust_rel, _wire


@pytest.mark.parametrize("kind,value,parent_type,parent_value", [
    ("IPv4-Addr", "18.214.199.100", "IPv4-Addr", "18.32.0.0/11"),
    ("IPv4-Addr", "35.138.131.221", "IPv4-Addr", "35.129.0.0/16"),
    ("IPv4-Addr", "18.32.0.0/11", "IPv4-Addr", "18.32.0.0/24"),
    ("IPv6-Addr", "2606:4700::1111", "IPv6-Addr", "2001:4860::/32"),
    ("IPv4-Addr", "8.8.8.8", "IPv6-Addr", "2001:4860::/32"),
    ("Url", "https://[2606:4700::1111]/", "IPv6-Addr", "2001:4860::/32"),
    ("Url", "https://18.214.199.100/path", "IPv4-Addr", "18.32.0.0/11"),
    ("IPv4-Addr", "8.8.8.8", "IPv4-Addr", "malformed/24"),
])
@pytest.mark.parametrize("source", ["existing_edge", "legacy_label", "discovery", "resolved_endpoint"])
def test_invalid_parent_never_creates_or_reuses_graph_context(kind, value, parent_type, parent_value, source):
    c = _make_connector()
    child = _obs(entity_type=kind, value=value)
    parent = _obs(entity_id="parent", entity_type=parent_type, value=parent_value)
    _wire(c, child, parent)
    c._ensure_cidr_asn_relationship = MagicMock()
    c._extract_parent = MagicMock(return_value=(parent_type, parent_value))
    if source == "existing_edge":
        c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]
    elif source == "legacy_label":
        child["objectLabel"] = [{"id": "hint", "value": "trust-cluster:" + parent_value}]
    elif source == "resolved_endpoint":
        # Valid discovery resolves to an unrelated returned endpoint.
        host = urlparse(value).hostname if kind == "Url" else value
        c._extract_parent.return_value = ("IPv6-Addr", "2606:4700::/32") if ":" in host else ("IPv4-Addr", "0.0.0.0/0")
    assert c.process_message({"entity_id": child["id"], "entity_type": kind}) == "no actions"
    c.helper.api.stix_core_relationship.create.assert_not_called()
    c.helper.api.stix_cyber_observable.create.assert_not_called()
    c.helper.api.stix_cyber_observable.add_label.assert_not_called()
    c.helper.api.stix_cyber_observable.remove_label.assert_not_called()
    c._ensure_cidr_asn_relationship.assert_not_called()
    assert "invalid CIDR parent" in str(c.helper.log_warning.call_args)
    if source == "existing_edge":
        c._extract_parent.assert_not_called()  # No automatic graph repair.


@pytest.mark.parametrize("kind,value,parent_type,parent_value", [
    ("IPv4-Addr", "18.214.199.100", "IPv4-Addr", "18.0.0.0/8"),
    ("IPv4-Addr", "8.8.0.0/16", "IPv4-Addr", "8.0.0.0/8"),
    ("IPv6-Addr", "2606:4700::1111", "IPv6-Addr", "2606:4700::/32"),
    ("Url", "https://[2606:4700::1111]/", "IPv6-Addr", "2606:4700::/32"),
    ("Domain-Name", "a.example.com", "Domain-Name", "example.com"),
])
def test_valid_parent_paths_remain_supported(kind, value, parent_type, parent_value):
    assert _make_connector()._valid_cidr_parent(kind, value, (parent_type, parent_value))


def test_missing_resolved_endpoint_identity_fails_closed():
    c = _make_connector()
    child = _obs(value="8.8.8.8")
    _wire(c, child, {"id": "unknown", "value": "", "entity_type": ""})
    c._extract_parent = MagicMock(return_value=("IPv4-Addr", "8.8.0.0/16"))
    assert c.process_message({"entity_id": child["id"], "entity_type": "IPv4-Addr"}) == "no actions"
    c.helper.api.stix_core_relationship.create.assert_not_called()


def test_invalid_legacy_edge_does_not_disable_independent_direct_heuristic():
    c = _make_connector()
    child = _obs(value="18.214.199.100", score=0)
    parent = _obs(entity_id="parent", value="18.32.0.0/11")
    _wire(c, child, parent)
    c.helper.api.stix_core_relationship.list.return_value = [_trust_rel(parent)]
    c.helper.api.stix_sighting_relationship.list.return_value = [{}] * 10
    result = c.process_message({"entity_id": child["id"], "entity_type": "IPv4-Addr"})
    assert "fp-candidate via ubiquity" in result
    c.helper.api.stix_core_relationship.create.assert_not_called()
