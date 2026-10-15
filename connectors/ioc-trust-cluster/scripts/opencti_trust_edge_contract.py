#!/usr/bin/env python3
"""Opt-in MUTATING smoke for an approved disposable OpenCTI stack only.

Requires OPENCTI_URL, OPENCTI_TOKEN, TRUST_CONTRACT_DISPOSABLE=1 and all
INTERNAL_ENRICHMENT connectors' automatic triggers disabled. Never a unit test.
TRUST_CONTRACT_KEEP=1 retains randomized fixtures for inspection.
"""
from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "connectors/ioc-trust-cluster/src"))


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"missing required env var: {name}")
    return value


def label_values(entity: dict) -> set[str]:
    return {label["value"] for label in entity.get("objectLabel") or []}


def snapshot(api, obj_id: str) -> tuple:
    entity = api.stix_cyber_observable.read(id=obj_id)
    return entity.get("x_opencti_score"), sorted(label_values(entity))


def wait_for_label(api, obj_id: str, value: str, present: bool) -> None:
    for _ in range(20):
        if (value in label_values(api.stix_cyber_observable.read(id=obj_id))) == present:
            return
        time.sleep(0.25)
    raise AssertionError(f"fixture label did not become present={present}")


def require_isolated_stack(api) -> None:
    if os.environ.get("TRUST_CONTRACT_DISPOSABLE") != "1":
        raise SystemExit("requires explicit TRUST_CONTRACT_DISPOSABLE=1 for an approved disposable stack")
    data = api.query("query { connectorsForWorker { id name active auto connector_type } }")
    connectors = (data.get("data") or {}).get("connectorsForWorker")
    if connectors is None:
        raise SystemExit("cannot verify automatic enrichment suppression")
    automatic = [c["name"] for c in connectors
                 if c.get("connector_type") == "INTERNAL_ENRICHMENT" and c.get("auto") is not False]
    if automatic:
        raise SystemExit("disable all automatic internal enrichment before smoke: " + ", ".join(automatic))


def main() -> None:
    url, token = require_env("OPENCTI_URL"), require_env("OPENCTI_TOKEN")
    from connector import IocTrustClusterConnector, TRUST_REL_TYPE, TRUST_REL_DESCRIPTION
    from pycti import OpenCTIApiClient

    api = OpenCTIApiClient(url, token)
    require_isolated_stack(api)  # Before connector registration or any observable writes.
    os.environ.setdefault("CONNECTOR_ID", "6bb7c2ca-956b-4d80-8d59-44e05f99fe7a")
    os.environ["CONNECTOR_AUTO"] = "false"
    os.environ["TRUST_CLUSTER_USE_RDAP"] = "false"
    os.environ["TRUST_CLUSTER_USE_NS_LOOKUP"] = "false"
    os.environ["TRUST_CLUSTER_SINKHOLE_IPS"] = ""
    os.environ["TRUST_CLUSTER_STATS_INTERVAL"] = "0"
    suffix = uuid.uuid4().hex[:12]
    obs_ids, rel_ids, label_ids = [], [], []
    connector = None
    try:
        connector = IocTrustClusterConnector()
        connector._create_audit_note = lambda *args: None  # Do not leave Note fixtures.
        connector._get_sightings_count = lambda *args: 0
        for parent_score, tag in [(85, "malicious"), (0, "fp-confirmed")]:
            objects = []
            for role, score in [("child", 0), ("parent", parent_score)]:
                obj = api.stix_cyber_observable.create(observableData={
                    "type": "domain-name", "value": f"{role}-{parent_score}-{suffix}.example.com",
                    "x_opencti_score": score,
                    "x_opencti_description": "IOC trust-cluster disposable contract fixture",
                })
                obs_ids.append(obj["id"])
                objects.append(obj)
            child, parent = objects
            # Confine discovery to disposable objects, never the real example.com anchor.
            connector._extract_parent = lambda *args: ("Domain-Name", parent["observable_value"])
            direct_before = snapshot(api, child["id"])
            result = connector.process_message({"entity_id": child["id"], "entity_type": "Domain-Name"})
            assert "linked under" in result
            relationships = api.stix_core_relationship.list(
                fromId=child["id"], relationship_type=TRUST_REL_TYPE, first=1, getAll=True)
            owned = [r for r in relationships if r.get("description") == TRUST_REL_DESCRIPTION]
            rel_ids.extend(r["id"] for r in owned)
            assert len(owned) == 1
            assert (owned[0].get("toId") or (owned[0].get("to") or {}).get("id")) == parent["id"]
            label = api.label.create(value=f"contract:{suffix}:{tag}", color="#1565c0")
            label_ids.append(label["id"])
            for present in [True, False]:
                operation = api.stix_cyber_observable.add_label if present else api.stix_cyber_observable.remove_label
                operation(id=parent["id"], label_id=label["id"])
                wait_for_label(api, parent["id"], label["value"], present)
                connector.process_message({"entity_id": child["id"], "entity_type": "Domain-Name"})
                assert snapshot(api, child["id"]) == direct_before
            # Exercise actual direct parent assessment without copying it to the child.
            direct_tag = api.label.create(value=tag, color="#1565c0")
            api.stix_cyber_observable.add_label(id=parent["id"], label_id=direct_tag["id"])
            wait_for_label(api, parent["id"], tag, True)
            connector.process_message({"entity_id": child["id"], "entity_type": "Domain-Name"})
            connector.process_message({"entity_id": parent["id"], "entity_type": "Domain-Name"})
            assert snapshot(api, child["id"]) == direct_before
            again = api.stix_core_relationship.list(
                fromId=child["id"], relationship_type=TRUST_REL_TYPE, first=1, getAll=True)
            assert {r["id"] for r in again} == {r["id"] for r in relationships}
        print("ok: directed edges/idempotency; parent tag changes never change child labels/score")
    finally:
        if connector is not None:
            connector.helper.stop()
        if os.environ.get("TRUST_CONTRACT_KEEP") == "1":
            print("kept disposable fixtures: " + ", ".join(obs_ids))
        else:
            for resource, ids in [(api.stix_core_relationship, rel_ids),
                                  (api.stix_cyber_observable, obs_ids), (api.label, label_ids)]:
                for obj_id in reversed(ids):
                    try:
                        resource.delete(id=obj_id)
                    except Exception as exc:
                        print(f"fixture cleanup failed for {obj_id}: {type(exc).__name__}", file=sys.stderr)


if __name__ == "__main__":
    main()
