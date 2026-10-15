"""Safety guards run before any optional disposable fixture mutation."""
import importlib.util
from pathlib import Path
from unittest.mock import MagicMock

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/opencti_trust_edge_contract.py"
spec = importlib.util.spec_from_file_location("contract_smoke", SCRIPT)
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def test_disposable_acknowledgement_is_mandatory(monkeypatch):
    monkeypatch.delenv("TRUST_CONTRACT_DISPOSABLE", raising=False)
    api = MagicMock()
    with pytest.raises(SystemExit, match="approved disposable stack"):
        smoke.require_isolated_stack(api)
    api.query.assert_not_called()


@pytest.mark.parametrize("connectors", [None, [
    {"name": "paid provider", "connector_type": "INTERNAL_ENRICHMENT", "auto": True}
], [{"name": "unknown suppression", "connector_type": "INTERNAL_ENRICHMENT"}]])
def test_unverified_or_automatic_enrichment_blocks_smoke(monkeypatch, connectors):
    monkeypatch.setenv("TRUST_CONTRACT_DISPOSABLE", "1")
    api = MagicMock()
    api.query.return_value = {"data": {"connectorsForWorker": connectors}}
    with pytest.raises(SystemExit):
        smoke.require_isolated_stack(api)
    api.stix_cyber_observable.create.assert_not_called()


def test_suppressed_automatic_connectors_allow_explicit_disposable_smoke(monkeypatch):
    monkeypatch.setenv("TRUST_CONTRACT_DISPOSABLE", "1")
    api = MagicMock()
    api.query.return_value = {"data": {"connectorsForWorker": [
        {"name": "provider", "connector_type": "INTERNAL_ENRICHMENT", "auto": False}
    ]}}
    smoke.require_isolated_stack(api)
    api.stix_cyber_observable.create.assert_not_called()
