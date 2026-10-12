import os
from pathlib import Path

IPQS_CLIENT_REPLACEMENTS = [
    (
        '''            self.helper.log_error(f"IPQS HTTP error for {url}: {error}")
            return None
''',
        '''            if getattr(getattr(error, "response", None), "status_code", None) == 429:
                raise QuotaExceeded(
                    "IPQS quota or rate limit reached",
                    retry_after_seconds(error.response),
                ) from error
            message = f"IPQS HTTP error for {url}: {error}"
            self.helper.log_error(message)
            raise RuntimeError(message) from error
''',
    ),
    (
        '''            self.helper.log_error(
                f"IPQS returned a non-JSON response for {url}: {error}"
            )
            return None
''',
        '''            message = f"IPQS returned a non-JSON response for {url}: {error}"
            self.helper.log_error(message)
            raise RuntimeError(message) from error
''',
    ),
    (
        '''            self.helper.log_error(
                f"Error connecting to IPQS ({type(error).__name__}): {error}"
            )
            return None
''',
        '''            message = f"Error connecting to IPQS ({type(error).__name__}): {error}"
            self.helper.log_error(message)
            raise RuntimeError(message) from error
''',
    ),
    (
        '''        if not to_bool(data.get("success")):
            self.helper.log_error(f"Error: {data.get('message')}")
            return None
''',
        '''        if not to_bool(data.get("success")):
            provider_message = data.get("message")
            if is_quota_error(provider_message):
                raise QuotaExceeded("IPQS quota exhausted or credits unavailable")
            message = f"IPQS provider rejected enrichment: {provider_message}"
            self.helper.log_error(message)
            raise RuntimeError(message)
''',
    ),
]

PATCHES = {
    "abuseipdb": [(
        "/opt/opencti-connector-abuseipdb/src/connector/abuseipdb.py",
        [(
            "        # Extract TLP\n",
            '''        if "/" in (opencti_entity.get("observable_value") or ""):
            self.helper.log_info(
                f"[AbuseIPDB] skipping CIDR observable: {opencti_entity.get('observable_value')}"
            )
            return "skipped: CIDR IPv4 observable is not supported by AbuseIPDB"

        # Extract TLP
''',
        )],
    )],
    "ipqs": [
        (
            "/opt/opencti-connector-ipqs/ipqs/ipqs.py",
            [
                (
                    "from .client import IPQSClient\n",
                    "from .client import IPQSClient\nfrom .quota_guard import QuotaCircuit\n",
                ),
                (
                    "        self.client = IPQSClient(self.helper, self.base_url, self.api_key)\n",
                    '''        self.client = IPQSClient(self.helper, self.base_url, self.api_key)
        self.quota_guard = QuotaCircuit("ipqs", self.helper)
''',
                ),
                (
                    "    def _process_message(self, data: Dict):\n        observable = data[\"enrichment_entity\"]\n",
                    '''    def _process_message(self, data: Dict):
        observable = data.get("enrichment_entity") or {}
        return self.quota_guard.run(
            observable.get("entity_type", "Unknown"),
            lambda: self._process_message_unmetered(data),
            observable.get("id") or observable.get("standard_id"),
        )

    def _process_message_unmetered(self, data: Dict):
        observable = data["enrichment_entity"]
''',
                ),
                (
                    '        match observable["entity_type"]:\n',
                    '''        if observable["entity_type"] == "IPv4-Addr" and "/" in (observable.get("observable_value") or ""):
            self.helper.log_info(
                f"[IPQS] skipping CIDR observable: {observable.get('observable_value')}"
            )
            return "skipped: CIDR IPv4 observable is not supported by IPQS"

        match observable["entity_type"]:
''',
                ),
            ],
        ),
        (
            "/opt/opencti-connector-ipqs/ipqs/client.py",
            [
                (
                    "from .constants import (\n",
                    "from .quota_guard import QuotaExceeded, is_quota_error, retry_after_seconds\n\nfrom .constants import (\n",
                ),
                *IPQS_CLIENT_REPLACEMENTS,
            ],
        ),
    ],
    "virustotal": [
        (
            "/opt/opencti-connector-virustotal/src/virustotal/client.py",
            [
                (
                    "from urllib3 import Retry\n",
                    "from urllib3 import Retry\n\nfrom .quota_guard import QuotaExceeded, retry_after_seconds\n",
                ),
                (
                    "            status_forcelist=[429, 500, 502, 503, 504],\n",
                    "            status_forcelist=[500, 502, 503, 504],\n",
                ),
                (
                    '''        except requests.exceptions.HTTPError as errh:
            self.helper.log_error(f"[VirusTotal] Http error: {errh}")
            self.helper.metric.inc("client_error_count")
''',
                    '''        except requests.exceptions.HTTPError as errh:
            if getattr(errh.response, "status_code", None) == 429:
                raise QuotaExceeded(
                    "VirusTotal quota or rate limit reached",
                    retry_after_seconds(errh.response),
                ) from errh
            self.helper.log_error(f"[VirusTotal] Http error: {errh}")
            self.helper.metric.inc("client_error_count")
''',
                    2,
                ),
            ],
        ),
        (
            "/opt/opencti-connector-virustotal/src/virustotal/virustotal.py",
            [
                (
                    "from virustotal.client import VirusTotalClient\n",
                    "from virustotal.client import VirusTotalClient\nfrom virustotal.quota_guard import QuotaCircuit\n",
                ),
                (
                    "        self.client = VirusTotalClient(self.helper, self._API_URL, token)\n",
                    '''        self.client = VirusTotalClient(self.helper, self._API_URL, token)
        self.quota_guard = QuotaCircuit("virustotal", self.helper)
''',
                ),
                (
                    '''    def _process_message(self, data: Dict) -> str:
        self.helper.metric.inc("run_count")
''',
                    '''    def _process_message(self, data: Dict) -> str:
        entity = data.get("enrichment_entity") or {}
        return self.quota_guard.run(
            entity.get("entity_type", "Unknown"),
            lambda: self._process_message_unmetered(data),
            entity.get("id") or entity.get("standard_id"),
        )

    def _process_message_unmetered(self, data: Dict) -> str:
        self.helper.metric.inc("run_count")
''',
                ),
                (
                    "        if is_indicator:\n",
                    '''        if entity_type == "IPv4-Addr" and "/" in (opencti_entity.get("observable_value") or ""):
            self.helper.log_info(
                f"[VirusTotal] skipping CIDR observable: {opencti_entity.get('observable_value')}"
            )
            return "skipped: CIDR IPv4 observable is not supported by VirusTotal"

        if is_indicator:
''',
                ),
                (
                    '''            for obs_type, observable_value in observables:
                # Build a synthetic entity that looks like an observable so
''',
                    '''            for obs_type, observable_value in observables:
                if obs_type == "IPv4-Addr" and "/" in (observable_value or ""):
                    self.helper.log_info(
                        f"[VirusTotal] skipping CIDR observable from indicator: {observable_value}"
                    )
                    results.append("skipped: CIDR IPv4 observable is not supported by VirusTotal")
                    continue
                # Build a synthetic entity that looks like an observable so
''',
                ),
            ],
        ),
    ],
}


def apply_replacements(source, replacements, name="connector"):
    for replacement in replacements:
        old, new, *counts = replacement
        expected = counts[0] if counts else 1
        old_count = source.count(old)
        new_count = source.count(new)
        if new_count == expected:
            if old_count != expected * new.count(old):
                raise RuntimeError(f"partially patched target for {name}: {old!r}")
            continue
        if old_count != expected:
            raise RuntimeError(
                f"patch target count for {name}: expected {expected}, found {old_count}: {old!r}"
            )
        source = source.replace(old, new, expected)
    return source


def main():
    name = os.environ["CIDR_FILTER_CONNECTOR"]
    if name in ("ipqs", "virustotal"):
        package = {
            "ipqs": "/opt/opencti-connector-ipqs/ipqs",
            "virustotal": "/opt/opencti-connector-virustotal/src/virustotal",
        }[name]
        quota_source = Path("/tmp/quota_guard.py").read_text()
        compile(quota_source, "quota_guard.py", "exec")
        Path(package, "quota_guard.py").write_text(quota_source)
    for path, replacements in PATCHES[name]:
        p = Path(path)
        patched = apply_replacements(p.read_text(), replacements, name)
        compile(patched, str(p), "exec")
        p.write_text(patched)


if __name__ == "__main__":
    main()
