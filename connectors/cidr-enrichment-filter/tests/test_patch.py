import importlib.util
import unittest
from pathlib import Path
from types import SimpleNamespace


spec = importlib.util.spec_from_file_location(
    "cidr_enrichment_patch", Path(__file__).parents[1] / "patch.py"
)
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)
quota_spec = importlib.util.spec_from_file_location(
    "quota_guard", Path(__file__).parents[1] / "quota_guard.py"
)
quota = importlib.util.module_from_spec(quota_spec)
quota_spec.loader.exec_module(quota)


class Helper:
    def __init__(self):
        self.errors = []
        self.infos = []

    def log_error(self, message):
        self.errors.append(message)

    def log_info(self, message):
        self.infos.append(message)


class PatchTests(unittest.TestCase):
    def test_provider_failure_raises_with_message(self):
        source = '''class Client:
    def query(self, data):
        if not to_bool(data.get("success")):
            self.helper.log_error(f"Error: {data.get('message')}")
            return None
        return data
'''
        namespace = {
            "to_bool": lambda value: value is True,
            "is_quota_error": quota.is_quota_error,
            "QuotaExceeded": quota.QuotaExceeded,
        }
        exec(
            patch.apply_replacements(
                source, [patch.IPQS_CLIENT_REPLACEMENTS[-1]], "ipqs"
            ),
            namespace,
        )
        client = namespace["Client"]()
        client.helper = Helper()

        with self.assertRaisesRegex(quota.QuotaExceeded, "credits unavailable"):
            client.query(
                {"success": False, "message": "You have insufficient credits"}
            )
        self.assertEqual(client.helper.errors, [])

    def test_auth_failure_raises(self):
        source = '''class Client:
    def query(self, error):
        url = "https://ipqs.invalid/api"
        try:
            raise error
        except HTTPError as error:
            self.helper.log_error(f"IPQS HTTP error for {url}: {error}")
            return None
'''
        namespace = {
            "HTTPError": type("HTTPError", (Exception,), {}),
            "QuotaExceeded": quota.QuotaExceeded,
            "retry_after_seconds": quota.retry_after_seconds,
        }
        exec(
            patch.apply_replacements(
                source, [patch.IPQS_CLIENT_REPLACEMENTS[0]], "ipqs"
            ),
            namespace,
        )
        client = namespace["Client"]()
        client.helper = Helper()

        with self.assertRaisesRegex(RuntimeError, "401 Unauthorized"):
            client.query(namespace["HTTPError"]("401 Unauthorized"))

    def test_virustotal_429_raises_quota_without_retry(self):
        source = '''class Client:
    def query(self, error):
        try:
            raise error
        except requests.exceptions.HTTPError as errh:
            self.helper.log_error(f"[VirusTotal] Http error: {errh}")
            self.helper.metric.inc("client_error_count")
'''
        http_error = type("HTTPError", (Exception,), {})
        namespace = {
            "requests": SimpleNamespace(exceptions=SimpleNamespace(HTTPError=http_error)),
            "QuotaExceeded": quota.QuotaExceeded,
            "retry_after_seconds": quota.retry_after_seconds,
        }
        old, new, _ = patch.PATCHES["virustotal"][0][1][2]
        exec(
            patch.apply_replacements(source, [(old, new)], "virustotal"),
            namespace,
        )
        error = http_error("429 Too Many Requests")
        error.response = SimpleNamespace(status_code=429, headers={"Retry-After": "60"})
        client = namespace["Client"]()
        client.helper = Helper()

        with self.assertRaises(quota.QuotaExceeded) as raised:
            client.query(error)
        self.assertEqual(raised.exception.retry_after, 60)
        self.assertEqual(client.helper.errors, [])

    def test_virustotal_retry_policy_excludes_429(self):
        old, new = patch.PATCHES["virustotal"][0][1][1]
        self.assertNotIn("429", patch.apply_replacements(old, [(old, new)], "virustotal"))

    def test_all_patches_are_idempotent_and_validate_cardinality(self):
        for name, groups in patch.PATCHES.items():
            for _, replacements in groups:
                source = "\n".join(
                    replacement[0] * (replacement[2] if len(replacement) == 3 else 1)
                    for replacement in replacements
                )
                patched = patch.apply_replacements(source, replacements, name)
                self.assertEqual(
                    patch.apply_replacements(patched, replacements, name), patched
                )

        replacement = patch.PATCHES["virustotal"][0][1][2]
        with self.assertRaisesRegex(RuntimeError, "expected 2, found 1"):
            patch.apply_replacements(replacement[0], [replacement], "virustotal")
        with self.assertRaisesRegex(RuntimeError, "expected 2, found 3"):
            patch.apply_replacements(replacement[0] * 3, [replacement], "virustotal")

    def test_cidr_guards_cover_direct_and_indicator_values(self):
        cases = [
            (
                '''class Connector:
    def process(self, opencti_entity):
        # Extract TLP
        return "queried"
''',
                patch.PATCHES["abuseipdb"][0][1][0],
            ),
            (
                '''class Connector:
    def process(self, observable):
        match observable["entity_type"]:
            case _:
                return "queried"
''',
                patch.PATCHES["ipqs"][0][1][3],
            ),
            (
                '''class Connector:
    def process(self, opencti_entity):
        entity_type = opencti_entity["entity_type"]
        is_indicator = entity_type == "Indicator"
        if is_indicator:
            return "indicator"
        return "queried"
''',
                patch.PATCHES["virustotal"][1][1][3],
            ),
        ]
        for source, replacement in cases:
            namespace = {}
            exec(patch.apply_replacements(source, [replacement]), namespace)
            connector = namespace["Connector"]()
            connector.helper = Helper()
            self.assertTrue(
                connector.process(
                    {"entity_type": "IPv4-Addr", "observable_value": "192.0.2.0/24"}
                ).startswith("skipped:")
            )
            self.assertEqual(
                connector.process(
                    {"entity_type": "IPv4-Addr", "observable_value": "192.0.2.1"}
                ),
                "queried",
            )

        source = '''class Connector:
    def process(self, observables):
        results = []
        if True:
            for obs_type, observable_value in observables:
                # Build a synthetic entity that looks like an observable so
                results.append(f"queried:{observable_value}")
        return results
'''
        namespace = {}
        exec(
            patch.apply_replacements(
                source, [patch.PATCHES["virustotal"][1][1][4]]
            ),
            namespace,
        )
        connector = namespace["Connector"]()
        connector.helper = Helper()
        self.assertEqual(
            connector.process(
                [("IPv4-Addr", "192.0.2.0/24"), ("Domain-Name", "example.com")]
            ),
            [
                "skipped: CIDR IPv4 observable is not supported by VirusTotal",
                "queried:example.com",
            ],
        )

    def test_successful_no_hit_stays_clean(self):
        source = '''class Client:
    def query(self, data):
        if not to_bool(data.get("success")):
            self.helper.log_error(f"Error: {data.get('message')}")
            return None
        return data
'''
        namespace = {"to_bool": lambda value: value is True}
        exec(
            patch.apply_replacements(
                source, [patch.IPQS_CLIENT_REPLACEMENTS[-1]], "ipqs"
            ),
            namespace,
        )
        client = namespace["Client"]()
        client.helper = Helper()
        response = {"success": True, "fraud_score": 0, "message": "No risk found"}

        self.assertEqual(client.query(response), response)
        self.assertEqual(client.helper.errors, [])


if __name__ == "__main__":
    unittest.main()
