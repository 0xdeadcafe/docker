from pathlib import Path
p = Path('/opt/opencti-connector-virustotal/src/virustotal/virustotal.py')
s = p.read_text()
needle = '        if is_indicator:\n'
guard = '''        if entity_type == "IPv4-Addr" and "/" in (opencti_entity.get("observable_value") or ""):\n            self.helper.log_info(
                f"[VirusTotal] skipping CIDR observable: {opencti_entity.get('observable_value')}"
            )
            return "skipped: CIDR IPv4 observable is not supported by VirusTotal"

'''
if guard not in s:
    assert needle in s
    s = s.replace(needle, guard + needle, 1)
needle = '            for obs_type, observable_value in observables:\n                # Build a synthetic entity that looks like an observable so\n'
guard = '''            for obs_type, observable_value in observables:
                if obs_type == "IPv4-Addr" and "/" in (observable_value or ""):
                    self.helper.log_info(
                        f"[VirusTotal] skipping CIDR observable from indicator: {observable_value}"
                    )
                    results.append("skipped: CIDR IPv4 observable is not supported by VirusTotal")
                    continue
                # Build a synthetic entity that looks like an observable so
'''
if guard not in s:
    assert needle in s
    s = s.replace(needle, guard, 1)
p.write_text(s)
