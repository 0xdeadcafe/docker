from pathlib import Path
p = Path('/opt/opencti-connector-ipqs/ipqs/ipqs.py')
s = p.read_text()
needle = '        match observable["entity_type"]:\n'
guard = '''        if observable["entity_type"] == "IPv4-Addr" and "/" in (observable.get("observable_value") or ""):
            self.helper.log_info(
                f"[IPQS] skipping CIDR observable: {observable.get('observable_value')}"
            )
            return "skipped: CIDR IPv4 observable is not supported by IPQS"

'''
if guard not in s:
    assert needle in s
    s = s.replace(needle, guard + needle, 1)
p.write_text(s)
