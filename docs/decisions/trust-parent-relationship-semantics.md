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

## Release evidence — 2026-10-15

- Consumer: ShellShock `5cd7e849`, `53de26c3`, `b70ae0d4`, pushed on `eval/ioc-comparison-oct15`. Delivered through the existing `/home/x0r/ShellShock/skel` → `/home/analyst` workbench bind mount; the previously stopped workbench remains stopped. Read-only verification executed the identical host-mounted Python source (SHA-256 `80ed7d2c749659a446afb71c92899066e8cf33ddc4e5e8e04e22112148b835d5`), not a claim that a stopped process was exercised.
- Producer: `81c81ec` / `8b4012b`, recreated alone at **14:32:22Z**, after consumer checks. Deployed image `sha256:568dc78e4696b5fc27fc697bf9aba84eeaecb0f836f6ea6bceaf12ed27eef6df`; source SHA-256 `f2e7c6e45f1b8d2e766d363b50644c0ab40abc5b347fe5a3136b98dfe19b4224` matches the checkout. Removed propagation methods are absent in-container. Same connector ID `3f8c9982-8cc2-486b-8969-1fb58a88117b`, one running writer, registered/active, 274 existing ASN-backed anchors loaded; listen/push queues had zero ready/unacknowledged messages before and after.
- Scoped rollback: old producer image `sha256:c79f7899f574afefedee26996de762685c35541272ac15ce7229ed17950ed4c0` retained as `ioc-trust-cluster:pre-r2f`; commands in the connector README. No platform, worker or other connector recreation; unrelated worktree changes preserved.
- Release gates: **238 producer tests** (including cross-repository gate), **221 consumer tests**, one existing opt-in consumer test skipped; ShellShock repository-policy lint, compile and whitespace checks passed. Actual producer-generated non-/24 CIDR→ASN fixtures show tag additions/removals on reread without changing direct verdict/cache evidence.
- Six existing live examples compared expansion off/on before and after replacement: direct verdict, score, tags, source evidence and object/verdict cache status unchanged. Verified actual `185.73.125.8` → `185.73.125.0/25` → ASN, existing parent `IPQS:VERDICT="CLEAN"` tag attribution, explicit depth limit and unavailable-parent uncertainty. Evidence: `/tmp/r2f-rollout-verification.json`, `/tmp/r2f-{before,after}-{basic,parents}.json`, chain/tagged comparison files and raw directories. No validation enrichment dispatch, paid provider tests, parent tag edits or new live fixtures. No forced processing event was used to manufacture runtime proof; deployed source plus hermetic tests cover the removed writer paths.
- Final inherited-label inventory **14:34:29Z**, after the old writer stopped: **0 associations, 0 candidates, 0 applied**, both definitions preserved. All object types/index generations; target lookup used exact names **and** current label IDs, exact totals, no timed-out/failed shards. Verified no-op, not cleanup approval. Evidence `/tmp/r2f-inherited-inventory-final-{raw,summary}.json`; raw SHA-256 `e857b069ba5bf4a99a4c5df0be0d1f131eb49f01ed12daabf00846689638f6f3`. No rollback mutation was needed; no definitions, labels, scores, edges or Notes were deleted.
- Separate follow-up `open-cti-dft`: sampling found pre-existing IP→CIDR edges whose network does not contain the IP. Marker presence does not prove graph data quality. These historical edges remain untouched; inventory/repair approval is outside this series.
