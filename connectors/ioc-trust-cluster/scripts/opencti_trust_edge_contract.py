#!/usr/bin/env python3
"""Opt-in OpenCTI contract smoke test for IOC trust edges.

Requires a running OpenCTI (for example this repo's compose stack) and:
  OPENCTI_URL=http://localhost:8080
  OPENCTI_TOKEN=<admin/api token>

Optional:
  CONNECTOR_ID=<uuid>              (defaults to a fixed smoke-test UUID)
  TRUST_CONTRACT_KEEP=1            keep created observables/relationships

Run from repo root:
  python3 connectors/ioc-trust-cluster/scripts/opencti_trust_edge_contract.py
"""

from __future__ import annotations

import os
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "connectors" / "ioc-trust-cluster" / "src"
sys.path.insert(0, str(SRC))


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"missing required env var: {name}")
    return value


def label_values(entity: dict) -> set[str]:
    return {lbl.get("value", "") for lbl in (entity.get("objectLabel") or [])}


def endpoint_id(rel: dict, side: str) -> str | None:
    return rel.get(f"{side}Id") or (rel.get(side) or {}).get("id")


def wait_for_label(api, observable_id: str, value: str, present: bool = True) -> dict:
    for _ in range(20):
        entity = api.stix_cyber_observable.read(id=observable_id)
        if (value in label_values(entity)) is present:
            return entity
        time.sleep(0.25)
    raise AssertionError(f"label {value!r} did not become present={present}")


def create_domain(api, value: str, score: int) -> dict:
    return api.stix_cyber_observable.create(
        observableData={
            "type": "domain-name",
            "value": value,
            "x_opencti_score": score,
            "x_opencti_description": "IOC trust-cluster contract smoke test fixture",
        },
        update=True,
    )


def main() -> None:
    url = require_env("OPENCTI_URL")
    token = require_env("OPENCTI_TOKEN")

    from connector import (  # noqa: WPS433 - opt-in script, fail only when run
        CLUSTER_LABEL_PREFIX,
        COLOR_CLUSTER,
        COLOR_FP,
        LABEL_FP_CONFIRMED,
        LABEL_INHERITED_FP_CANDIDATE,
        LABEL_INHERITED_MALICIOUS_CASCADE,
        TRUST_REL_DESCRIPTION,
        TRUST_REL_TYPE,
        IocTrustClusterConnector,
    )
    from pycti import OpenCTIApiClient  # noqa: WPS433

    os.environ.setdefault("CONNECTOR_ID", "6bb7c2ca-956b-4d80-8d59-44e05f99fe7a")
    os.environ.setdefault("TRUST_CLUSTER_USE_RDAP", "false")
    os.environ.setdefault("TRUST_CLUSTER_USE_NS_LOOKUP", "false")
    os.environ.setdefault("TRUST_CLUSTER_STATS_INTERVAL", "0")

    api = OpenCTIApiClient(url, token)
    suffix = uuid.uuid4().hex[:12]
    child_value = f"trust-contract-child-{suffix}.example.com"
    parent_value = f"trust-contract-parent-{suffix}.example.com"
    benign_child_value = f"trust-contract-benign-child-{suffix}.example.com"
    benign_parent_value = f"trust-contract-benign-parent-{suffix}.example.com"
    contract_label = f"{CLUSTER_LABEL_PREFIX}:contract:{suffix}"

    rel_ids: list[str] = []
    obs_ids: list[str] = []
    contract_label_id: str | None = None
    connector = None
    keep = os.environ.get("TRUST_CONTRACT_KEEP", "").lower() in {"1", "true", "yes"}

    try:
        child = create_domain(api, child_value, 50)
        parent = create_domain(api, parent_value, 85)
        benign_child = create_domain(api, benign_child_value, 50)
        benign_parent = create_domain(api, benign_parent_value, 20)
        obs_ids.extend([
            child["id"], parent["id"], benign_child["id"], benign_parent["id"]
        ])

        fp_label = api.label.create(value=LABEL_FP_CONFIRMED, color=COLOR_FP)
        assert api.stix_cyber_observable.add_label(
            id=benign_parent["id"], label_id=fp_label["id"]
        )
        benign_parent = wait_for_label(
            api, benign_parent["id"], LABEL_FP_CONFIRMED
        )

        rel = api.stix_core_relationship.create(
            fromId=child["id"],
            toId=parent["id"],
            relationship_type=TRUST_REL_TYPE,
            description=TRUST_REL_DESCRIPTION,
            confidence=75,
        )
        extra_rel = api.stix_core_relationship.create(
            fromId=child["id"],
            toId=benign_parent["id"],
            relationship_type=TRUST_REL_TYPE,
            description=TRUST_REL_DESCRIPTION,
            confidence=75,
        )
        benign_rel = api.stix_core_relationship.create(
            fromId=benign_child["id"],
            toId=benign_parent["id"],
            relationship_type=TRUST_REL_TYPE,
            description=TRUST_REL_DESCRIPTION,
            confidence=75,
        )
        rel_ids.extend([rel["id"], extra_rel["id"], benign_rel["id"]])

        rels = api.stix_core_relationship.list(
            fromId=child["id"],
            relationship_type=TRUST_REL_TYPE,
            first=1,
            getAll=True,
        )
        assert len(rels) >= 2, "pycti getAll pagination did not return both relationships"
        listed = next(r for r in rels if r["id"] == rel["id"])
        assert TRUST_REL_DESCRIPTION in (listed.get("description") or "")
        assert endpoint_id(listed, "from") == child["id"]
        assert endpoint_id(listed, "to") == parent["id"]
        assert (listed.get("to") or {}).get("observable_value") == parent_value

        label = api.label.create(value=contract_label, color=COLOR_CLUSTER)
        contract_label_id = label["id"]
        assert api.stix_cyber_observable.add_label(id=child["id"], label_id=label["id"])
        wait_for_label(api, child["id"], contract_label)
        assert api.stix_cyber_observable.remove_label(id=child["id"], label_id=label["id"])
        wait_for_label(api, child["id"], contract_label, present=False)

        connector = IocTrustClusterConnector()
        # The contract is for trust edges/labels; avoid leaving audit Note fixtures.
        connector._create_audit_note = lambda *args, **kwargs: None

        benign_result = connector.process_message(
            {"entity_id": benign_child["id"], "entity_type": "Domain-Name"}
        )
        benign_labels = label_values(wait_for_label(
            api, benign_child["id"], LABEL_INHERITED_FP_CANDIDATE
        ))
        assert LABEL_INHERITED_FP_CANDIDATE in benign_labels, benign_result
        assert "fp-candidate inherited" in benign_result

        malicious_result = connector.process_message(
            {"entity_id": child["id"], "entity_type": "Domain-Name"}
        )
        malicious_labels = label_values(wait_for_label(
            api, child["id"], LABEL_INHERITED_MALICIOUS_CASCADE
        ))
        assert f"{CLUSTER_LABEL_PREFIX}:{parent_value}" not in malicious_labels
        assert LABEL_INHERITED_MALICIOUS_CASCADE in malicious_labels
        assert LABEL_INHERITED_FP_CANDIDATE not in malicious_labels
        assert "malicious-cascade" in malicious_result

        print("ok: OpenCTI trust-edge and trust-state contracts passed")
    finally:
        if connector is not None:
            connector.helper.stop()
        if keep:
            print(f"kept fixtures: {', '.join(obs_ids)}")
            return
        for rel_id in reversed(rel_ids):
            try:
                api.stix_core_relationship.delete(id=rel_id)
            except Exception:
                pass
        for obs_id in reversed(obs_ids):
            try:
                api.stix_cyber_observable.delete(id=obs_id)
            except Exception:
                pass
        if contract_label_id:
            try:
                api.label.delete(id=contract_label_id)
            except Exception:
                pass


if __name__ == "__main__":
    main()
