# Decision: OTX pulse grouping stays semantic

OTX/AlienVault pulses already import rich context into OpenCTI: reports, indicators, observables, malware, intrusion sets, vulnerabilities, attack patterns, sectors/countries, and semantic relationships such as `based-on`, `indicates`, `uses`, and `targets`.

Do **not** create peer `related-to` edges between every IOC in a pulse. A full IOC mesh is noisy and grows as `N²` per pulse.

If peer IOC links are ever needed, they must be capped to a small scored top-N set and justified by a concrete query/use case. Default grouping remains the pulse/report and existing semantic relationships.
