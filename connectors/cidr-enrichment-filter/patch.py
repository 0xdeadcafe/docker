import os
from pathlib import Path

PATCHES = {
    "abuseipdb": (
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
    ),
    "ipqs": (
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
    "virustotal": (
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
    ),
}

name = os.environ["CIDR_FILTER_CONNECTOR"]
path, replacements = PATCHES[name]
p = Path(path)
s = p.read_text()
for old, new in replacements:
    if new not in s:
        assert old in s, f"patch target not found for {name}: {old!r}"
        s = s.replace(old, new, 1)
p.write_text(s)
