"""Run: python3 tests/check_threatfox.py (requires Docker Compose and pulled image).

Synthetic CSV-format fixtures run inside the unmodified image without networking,
real credentials, connector registration or OpenCTI writes.
"""
import csv
import io
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import MagicMock


def check_native():
    import stix2
    from src.__main__ import FeedRow, ThreatFox
    from src.models.configs.config_loader import ConfigLoader

    config = ConfigLoader()
    assert config.threatfox.interval == 1
    assert config.threatfox.ioc_to_import == "all_types"
    assert config.threatfox.import_offline and config.threatfox.create_indicators
    assert config.threatfox.default_x_opencti_score == 50
    connector = object.__new__(ThreatFox)  # Never run __init__: it registers/writes.
    connector.helper = MagicMock()
    connector.identity = {"standard_id": stix2.Identity(name="Fixture", identity_class="organization").id}
    connector.create_indicators = config.threatfox.create_indicators
    connector.default_x_opencti_score = config.threatfox.default_x_opencti_score
    connector.threatfox_interval = config.threatfox.interval
    for name in ("ip", "domain", "url", "hash"):
        setattr(connector, "x_opencti_score_" + name, getattr(config.threatfox, "x_opencti_score_" + name))
    assert connector.get_interval() == 86400

    fixtures = {"ip:port": "192.0.2.1:443", "domain": "example.invalid",
                "url": "https://example.invalid/payload", "md5_hash": "01" * 16,
                "sha1_hash": "01" * 20, "sha256_hash": "01" * 32}
    for kind, value in fixtures.items():
        text = io.StringIO()
        csv.writer(text).writerow([
            "2026-10-15 12:00:00", "1", value, kind, "payload_delivery",
            "win.fixture", "None", "Fixture", "2026-10-15 13:00:00",
            "100", "false", "https://example.invalid/reference", "fixture", "0", "fixture",
        ])
        row = FeedRow(next(csv.reader(io.StringIO(text.getvalue()), skipinitialspace=True)))
        assert row.first_seen < row.last_seen
        objects = list(connector.process_row(row))
        indicator = next(o for o in objects if o.type == "indicator")
        observable = next(o for o in objects if o.type not in {"indicator", "malware", "relationship"})
        assert indicator.confidence == 100 and indicator.x_opencti_score == 50
        assert observable.x_opencti_score == 50
        assert indicator.external_references[0].source_name == "ThreatFox source reference"
        assert indicator.created_by_ref == connector.identity["standard_id"]
        assert indicator.object_marking_refs and "payload_delivery" in indicator.labels
        assert any(o.type == "relationship" and o.relationship_type == "based-on"
                   and o.source_ref == indicator.id and o.target_ref == observable.id for o in objects)
        if kind == "sha256_hash":
            assert observable.hashes["SHA-256"] == value
            assert indicator.pattern == f"[file:hashes.'SHA-256' = '{value}']"
        if kind in {"url", "domain"}:
            assert not any(o.type in {"ipv4-addr", "ipv6-addr"} for o in objects)
        stix2.Bundle(objects=objects, allow_custom=True).serialize()
    assert not connector.helper.api.mock_calls
    connector.helper.send_stix2_bundle.assert_not_called()
    print("Stock settings + six IOC fixtures passed: SHA-256, source, confidence/score, markings, based-on and no inferred host IPs")


def check_compose():
    root = Path(__file__).resolve().parents[1]
    # Keep expanded credentials in memory only; never print/save resolved Compose.
    result = subprocess.run(["docker", "compose", "-p", "xtm", "-f", "docker-compose.yml",
                             "config", "--format", "json"], cwd=root, capture_output=True, check=True)
    config = json.loads(result.stdout)
    service = config["services"]["connector-threatfox"]
    assert service["image"] == "opencti/connector-threatfox:7.260910.0" and "build" not in service
    env = service["environment"]
    assert env["THREATFOX_CSV_URL"] == "https://threatfox.abuse.ch/export/csv/recent/"
    assert env["CONNECTOR_TYPE"] == "EXTERNAL_IMPORT"
    for name in ("connector-ipqs", "connector-virustotal"):
        other = config["services"][name]["environment"]
        assert other["CONNECTOR_AUTO"] == other["CONNECTOR_AUTO_UPDATE"] == "false"
    command = ["docker", "run", "--rm", "--network", "none", "-i", "--entrypoint", "python"]
    for key, value in env.items():
        command.extend(["-e", key + "=" + ("offline-fixture" if key == "OPENCTI_TOKEN" else value)])
    command.extend([service["image"], "-", "--inside"])
    subprocess.run(command, input=Path(__file__).read_bytes(), check=True)


if __name__ == "__main__":
    check_native() if "--inside" in sys.argv else check_compose()
