import os
from pathlib import Path

IPQS_CLIENT_REPLACEMENTS = [
    (
        '''            self.helper.log_error(f"IPQS HTTP error for {url}: {error}")
            return None
''',
        '''            message = f"IPQS HTTP error for {url}: {error}"
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
            message = f"IPQS provider rejected enrichment: {data.get('message')}"
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
            [(
                '        match observable["entity_type"]:\n',
                '''        if observable["entity_type"] == "IPv4-Addr" and "/" in (observable.get("observable_value") or ""):
            self.helper.log_info(
                f"[IPQS] skipping CIDR observable: {observable.get('observable_value')}"
            )
            return "skipped: CIDR IPv4 observable is not supported by IPQS"

        match observable["entity_type"]:
''',
            )],
        ),
        (
            "/opt/opencti-connector-ipqs/ipqs/client.py",
            IPQS_CLIENT_REPLACEMENTS,
        ),
    ],
    "virustotal": [(
        "/opt/opencti-connector-virustotal/src/virustotal/virustotal.py",
        [(
            "        if is_indicator:\n",
            '''        if entity_type == "IPv4-Addr" and "/" in (opencti_entity.get("observable_value") or ""):
            self.helper.log_info(
                f"[VirusTotal] skipping CIDR observable: {opencti_entity.get('observable_value')}"
            )
            return "skipped: CIDR IPv4 observable is not supported by VirusTotal"

        if is_indicator:
''',
        ), (
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
        )],
    )],
}


def apply_replacements(source, replacements, name="connector"):
    for old, new in replacements:
        if new not in source:
            assert old in source, f"patch target not found for {name}: {old!r}"
            source = source.replace(old, new, 1)
    return source


def main():
    name = os.environ["CIDR_FILTER_CONNECTOR"]
    for path, replacements in PATCHES[name]:
        p = Path(path)
        p.write_text(apply_replacements(p.read_text(), replacements, name))


if __name__ == "__main__":
    main()
