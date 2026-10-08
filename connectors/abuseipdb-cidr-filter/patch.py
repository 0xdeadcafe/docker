from pathlib import Path
p = Path('/opt/opencti-connector-abuseipdb/src/connector/abuseipdb.py')
s = p.read_text()
needle = '        # Extract TLP\n'
guard = '''        if "/" in (opencti_entity.get("observable_value") or ""):
            self.helper.log_info(
                f"[AbuseIPDB] skipping CIDR observable: {opencti_entity.get('observable_value')}"
            )
            return "skipped: CIDR IPv4 observable is not supported by AbuseIPDB"

'''
if guard not in s:
    assert needle in s
    s = s.replace(needle, guard + needle, 1)
p.write_text(s)
