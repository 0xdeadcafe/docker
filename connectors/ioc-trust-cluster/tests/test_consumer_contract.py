"""Optional cross-repository gate: actual producer edges consumed by ShellShock."""
import copy
import importlib.util
import os
from pathlib import Path

import pytest

from .test_connector import _make_connector, _obs, _wire


def test_producer_edges_and_parent_tag_rereads_preserve_direct_cache_evidence():
    script = os.environ.get("OPENCTI_CONSUMER_SCRIPT")
    if not script:
        pytest.skip("set OPENCTI_CONSUMER_SCRIPT for the cross-repository release gate")
    path = Path(script)
    assert path.is_file(), path
    spec = importlib.util.spec_from_file_location("consumer_contract", path)
    consumer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(consumer)
    child = _obs(value="8.8.8.8", score=0, labels=["whitelist"])
    network = _obs(entity_id="network", value="8.8.0.0/16", score=0, labels=["context-only"])
    asn = _obs(entity_id="asn", entity_type="Autonomous-System", value="AS15169", score=0)
    objects = {o["id"]: o for o in [child, network, asn]}
    for obj in objects.values():
        obj["observable_value"] = obj["value"]
    producer = _make_connector()
    _wire(producer, child, network)
    producer._cidr_asn_cache[network["value"]] = ("15169", "GOOGLE")
    producer._find_or_create_asn = lambda *args: asn
    edges = []

    def create_edge(**kwargs):
        edge = {"id": str(len(edges)), **kwargs,
                "from": objects[kwargs["fromId"]], "to": objects[kwargs["toId"]]}
        edges.append(edge)
        return edge

    producer.helper.api.stix_core_relationship.create.side_effect = create_edge
    producer.process_message({"entity_id": child["id"], "entity_type": "IPv4-Addr"})
    assert [edge["relationship_type"] for edge in edges] == ["related-to", "belongs-to"]
    producer.helper.api.stix_cyber_observable.add_label.assert_not_called()

    class Client:
        def lookup_pages(self, ioc, limit):
            return [{"data": {"stixCyberObservables": {"edges": [{"node": child}]}}}]

        def relationships(self, obj_id, first, after=None):
            return {"data": {"stixCyberObservable": {"stixCoreRelationships": {
                "edges": [{"node": edge} for edge in edges if edge["fromId"] == obj_id],
                "pageInfo": {"hasNextPage": False, "endCursor": None}}}}}

    ioc = {"value": child["value"], "type": "ip", "subtype": "IPv4-Addr"}
    client = Client()
    direct = consumer.lookup_ioc(client, ioc, 10, None)
    for tags in [["malicious", "owner-context"], [], ["replacement-tag"]]:
        asn["objectLabel"] = [{"value": tag} for tag in tags]
        result = copy.deepcopy(direct)
        consumer.build_trust_parents(client, ioc, result, 10, None, 3, 10, 168)
        for key in ["verdict", "labels", "score", "verdict_evidence", "verdict_cache_status", "object_cache_status"]:
            assert result[key] == direct[key]
        assert [p["value"] for p in result["belong_to_parents"]] == ["8.8.0.0/16", "AS15169"]
        assert result["belong_to_parents"][1]["tags"] == sorted(tags)
        assert result["belong_to_graph"]["complete"]
    producer.helper.api.stix_cyber_observable.remove_label.assert_not_called()
