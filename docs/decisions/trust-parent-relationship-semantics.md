# Trust parent relationship semantics

Structural IOC parentage uses connector-owned `related-to` edges:

```text
child --related-to [IOC trust-cluster structural parent link (auto-created)]--> parent
```

OpenCTI rejects `belongs-to` for the current SCO parentage pairs (`Domain-Name→Domain-Name`, `Url→Domain-Name`, `Url→IPv4-Addr`, `IPv4-Addr→IPv4-Addr`), so `related-to` is canonical for those trust-parent edges.

`belongs-to` is used only where OpenCTI allows ownership semantics, currently CIDR → `Autonomous-System`.

Legacy structural `trust-cluster:<parent>` labels are not source of truth; relationships are.

## Retrieval contract (open-cti-r2f)

Keep tags and assessments on the objects they describe. The producer discovers and maintains edges; the consumer retrieves attributed context. Neither copies parent tags into a child's direct labels or replaces a child's direct score/verdict/cache evidence with a parent assessment.

The ShellShock consumer `skel/.pi/skills/opencti-ioc/scripts/opencti_ioc.py` has three expansion callers: ordinary lookup, enrich-on-miss results, and resume. Its `build_payload`/`render_summary` must continue reporting the requested IOC's direct evidence. Local references to inherited tags outside the producer are documentation and tests; no additional local production consumer of inherited verdict labels was found. External integrations cannot be exhaustively audited from these repositories and must be reviewed before data cleanup.

- `belong_to_parents` and `belong_to_graph` contain only outgoing structural `related-to` edges with the exact marker above, or outgoing `belong-to` / `belongs-to` / `part-of` ownership edges. Ownership edges may be feed-authored; the marker is a convention, not authentication. Relationship IDs, direction, description and paths stay attached to parent tags.
- `trust_parent_verdicts` / `trust_graph` retain URL-host and DNS-derived advisory context. Generic/incoming relationships are related context, not authoritative parents. Neither contributes to `strongest_trust_parent_verdict`, which summarizes only approved graph parents and never overrides the IOC verdict.
- Keep existing output fields. Preserve arbitrary parent labels as context even when they have no verdict meaning. Report unavailable metadata and bounded/failed traversal explicitly; absence of a parent is not evidence of benignness.
- Never invent `/24` or `/48` parents. Networks come from actual OpenCTI edges maintained from RDAP. The client performs no RDAP requests. Respect depth/fanout, private-IP guards, cycles and finite query limits.
- Remove only parent-driven inheritance, fanout, retraction and cascade-only machinery. Retain direct sighting-based `fp-candidate`, optional direct sinkhole detection, opt-in NS discovery and JA4/ASN display grouping. Shared score/label helpers may still serve these independent behaviors.
- Preserve existing connector IDs, relationship markers, graph discovery semantics and UNKNOWN anchors at score `0`. Historical inherited labels remain read-only compatibility state until separately reviewed.

Deploy and verify the consumer before deploying the simplified producer. Inventory inherited-label associations before any cleanup; exact names or an adjacent graph edge alone do not prove assignment ownership. Skip ambiguous/manual associations. Cleanup requires a refreshed dry run, rollback manifest and explicit operator approval; do not delete label definitions, direct tags/scores, relationships or historical Notes.
