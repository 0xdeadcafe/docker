import importlib.util
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "cidr_enrichment_patch", Path(__file__).parents[1] / "patch.py"
)
patch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patch)


class Helper:
    def __init__(self):
        self.errors = []

    def log_error(self, message):
        self.errors.append(message)


class PatchTests(unittest.TestCase):
    def test_provider_failure_raises_with_message(self):
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

        with self.assertRaisesRegex(RuntimeError, "insufficient credits"):
            client.query(
                {"success": False, "message": "You have insufficient credits"}
            )
        self.assertIn("insufficient credits", client.helper.errors[0])

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
        namespace = {"HTTPError": type("HTTPError", (Exception,), {})}
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
