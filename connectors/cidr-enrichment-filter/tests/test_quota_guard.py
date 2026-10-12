import importlib.util
import os
import unittest
from pathlib import Path
from unittest.mock import patch


spec = importlib.util.spec_from_file_location(
    "quota_guard_under_test", Path(__file__).parents[1] / "quota_guard.py"
)
quota = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quota)


class FakeCounter:
    def __init__(self):
        self.events = []
        self.current = None

    def labels(self, **labels):
        self.current = labels
        return self

    def inc(self):
        self.events.append(self.current)


class FakeGauge:
    def __init__(self):
        self.provider = None
        self.functions = {}

    def labels(self, **labels):
        self.provider = labels["provider"]
        return self

    def set_function(self, function):
        self.functions[self.provider] = function

    @property
    def values(self):
        return {provider: function() for provider, function in self.functions.items()}


class Helper:
    def __init__(self):
        self.warnings = []
        self.infos = []

    def log_warning(self, message):
        self.warnings.append(message)

    def log_info(self, message):
        self.infos.append(message)


def outcomes(counter, provider):
    return [event["outcome"] for event in counter.events if event["provider"] == provider]


class QuotaCircuitTests(unittest.TestCase):
    def setUp(self):
        self.now = [100.0]
        self.clock = lambda: self.now[0]
        self.counter = FakeCounter()
        self.gauge = FakeGauge()
        self.helper = Helper()

    def guard(self, provider="ipqs"):
        return quota.QuotaCircuit(
            provider, self.helper, self.clock, self.counter, self.gauge
        )

    def test_quota_failure_opens_and_blocks_without_another_call(self):
        guard = self.guard()
        calls = []

        def exhausted():
            calls.append("provider")
            raise quota.QuotaExceeded("insufficient credits")

        with self.assertRaisesRegex(quota.CircuitOpenError, "circuit opened"):
            guard.run("Url", exhausted)
        with self.assertRaisesRegex(quota.CircuitOpenError, "retry in"):
            guard.run("Url", lambda: calls.append("must not run"))

        self.assertEqual(calls, ["provider"])
        self.assertEqual(
            outcomes(self.counter, "ipqs"),
            [
                "requested", "executed", "failed", "quota_blocked",
                "requested", "skipped", "quota_blocked",
            ],
        )

    def test_expiry_and_manual_reset_resume_calls(self):
        with patch.dict(os.environ, {"IPQS_QUOTA_COOLDOWN_SECONDS": "10"}):
            guard = self.guard()
        with self.assertRaises(quota.CircuitOpenError):
            guard.run("Domain-Name", lambda: (_ for _ in ()).throw(quota.QuotaExceeded("quota")))

        self.now[0] += 11
        self.assertEqual(guard.run("Domain-Name", lambda: "ok"), "ok")
        guard.open_until = self.now[0] + 10
        guard.reset()
        self.assertEqual(guard.run("Domain-Name", lambda: "ok"), "ok")

    def test_provider_circuits_are_independent(self):
        ipqs = self.guard("ipqs")
        vt = self.guard("virustotal")
        with self.assertRaises(quota.CircuitOpenError):
            ipqs.run("IPv4-Addr", lambda: (_ for _ in ()).throw(quota.QuotaExceeded("quota")))

        self.assertEqual(vt.run("IPv4-Addr", lambda: "ok"), "ok")
        self.assertEqual(ipqs.remaining(), 3600)
        self.assertEqual(vt.remaining(), 0)

    def test_recent_duplicate_is_skipped_then_expires(self):
        with patch.dict(os.environ, {"IPQS_RECENT_ENRICHMENT_SECONDS": "10"}):
            guard = self.guard()
        calls = []
        operation = lambda: calls.append("provider") or "ok"

        self.assertEqual(guard.run("Url", operation, "observable-1"), "ok")
        self.assertIn("already requested", guard.run("Url", operation, "observable-1"))
        self.assertEqual(calls, ["provider"])
        self.now[0] += 11
        self.assertEqual(guard.run("Url", operation, "observable-1"), "ok")
        self.assertEqual(calls, ["provider", "provider"])

    def test_url_readiness_recovers_on_scrape_after_cooldown(self):
        with patch.dict(os.environ, {"CONNECTOR_SCOPE": "IPv4-Addr,Domain-Name"}):
            self.guard("virustotal")
        with patch.dict(
            os.environ,
            {"CONNECTOR_SCOPE": "IPv4-Addr,Domain-Name,Url", "IPQS_QUOTA_COOLDOWN_SECONDS": "10"},
        ):
            ipqs = self.guard("ipqs")

        self.assertEqual(self.gauge.values, {"virustotal": 0, "ipqs": 1})
        with self.assertRaises(quota.CircuitOpenError):
            ipqs.run("Url", lambda: (_ for _ in ()).throw(quota.QuotaExceeded("quota")))
        self.assertEqual(self.gauge.values, {"virustotal": 0, "ipqs": 0})

        self.now[0] += 11
        self.assertEqual(self.gauge.values, {"virustotal": 0, "ipqs": 1})

    def test_retry_after_header_is_used_but_bounded(self):
        response = type("Response", (), {"headers": {"Retry-After": "999999"}})()
        with patch.dict(os.environ, {"ENRICHMENT_QUOTA_MAX_COOLDOWN_SECONDS": "20"}):
            guard = self.guard("virustotal")
        with self.assertRaises(quota.CircuitOpenError):
            guard.run(
                "Domain-Name",
                lambda: (_ for _ in ()).throw(
                    quota.QuotaExceeded("rate limit", quota.retry_after_seconds(response))
                ),
            )
        self.assertEqual(guard.remaining(), 20)


if __name__ == "__main__":
    unittest.main()
