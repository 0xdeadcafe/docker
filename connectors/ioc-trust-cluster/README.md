# IOC Trust Cluster

Build structural IOC relationships; retrieve parent context instead of copying it.

## Contract

- IP → RDAP CIDR and domain/URL → discovered parent use child-to-parent `related-to` with description exactly `IOC trust-cluster structural parent link (auto-created)`.
- CIDR → `Autonomous-System` uses `belongs-to` with the existing ownership marker. OpenCTI rejects `belongs-to` for the SCO parentage pairs above.
- Synthetic UNKNOWN network/domain anchors start at score `0`. No guessed `/24` or `/48`, new client-side RDAP, or synthetic X509 issuer-DN objects.
- Existing relationships are reused without parent verdict classification or descendant enumeration. Parent updates do not copy tags, change child scores, retract labels, or create cascade/conflict/revocation Notes.
- Independent features remain: sighting-based generic `fp-candidate`, optional direct `sinkholed` detection (`sinkhole` feed alias preserved), opt-in NS discovery, label-only JA4/ASN-owner groups and graph-change audit Notes.
- Historical `trust-cluster:malicious-cascade` / `trust-cluster:fp-candidate` associations stay untouched. Generic/manual tags, scores, relationships and historical Notes are never migration targets here.

See [relationship semantics](../../docs/decisions/trust-parent-relationship-semantics.md). The connector ID and relationship markers are unchanged. The retired `TRUST_CLUSTER_FP_CASCADE_SCORE_MAX` setting has no effect. Malicious/unknown score thresholds still guard independent direct heuristics.

## Retrieval

ShellShock's `opencti-ioc` retains `verdict`, `requested_ioc_verdict`, `ioc_verdicts`, direct labels and exact verdict-cache evidence regardless of parent expansion:

```sh
opencti-ioc.sh --ioc "$IOC" --json --raw-dir /tmp/parent-read \
  --include-trust-parents --trust-parent-depth 3 --trust-parent-fanout 10 \
  > /tmp/parent-read.json 2>/tmp/parent-read.err
```

Do **not** add `--enrich-on-miss` for verification. `belong_to_parents` carries raw parent tags, IDs, relationship ID/direction/description, depth/path, freshness and provenance. `strongest_trust_parent_verdict` summarizes only approved outgoing graph parents, never the requested IOC. Generic/incoming links are `related_context`; URL-host/DNS-derived context stays in `trust_parent_verdicts` / `trust_graph`, not established ownership. Check `belong_to_graph.complete`, `incomplete_reasons` and uncertainty before interpreting absent parents. SCO confidence is unavailable and remains null.

## CIDR discovery

1. Load connector-marked CIDR→ASN `belongs-to` edges into a bounded session prefix index.
2. Reuse the most-specific indexed CIDR containing an IP without another RDAP request.
3. Otherwise ask IPWhois/RDAP for the most-specific valid `network.cidr` / `asn_cidr` containing the IP.
4. Find/create the CIDR, link it to its ASN when available and cache the chain.
5. Without an actual allocation, return no parent. Never manufacture a prefix.

NS discovery remains opt-in (`TRUST_CLUSTER_USE_NS_LOOKUP=true` or `TRUST_CLUSTER_USE_NS=true`) to avoid cross-tenant provider clusters.

## Release checks

```sh
OPENCTI_CONSUMER_SCRIPT=/home/x0r/ShellShock/skel/.pi/skills/opencti-ioc/scripts/opencti_ioc.py \
  python3 -m pytest -q connectors/ioc-trust-cluster/tests
python3 -m pytest -q /home/x0r/ShellShock/skel/.pi/skills/opencti-ioc/tests
```

The cross-repository test consumes actual producer-created IP→non-/24 CIDR→ASN edges and rereads added/removed parent tags while direct evidence stays invariant. All tests are hermetic; no paid enrichment.

The optional **mutating** `scripts/opencti_trust_edge_contract.py` is only for an explicitly approved disposable stack. Set `OPENCTI_URL`, `OPENCTI_TOKEN` and `TRUST_CONTRACT_DISPOSABLE=1`; first disable **all** automatic internal-enrichment triggers (including this connector). The script verifies suppression before creating fixtures; this prevents observable creation from spending provider quota. Do not run it against production as a routine check. It confines discovery to randomized fixtures, checks directed edges/idempotency and unchanged child tags/scores under malicious/benign parent changes, then cleans its fixture objects/edges. `TRUST_CONTRACT_KEEP=1` retains fixtures and still reports assertion failures. No live mutating smoke was used for this release.

## Consumer-first rollout and rollback

Implementation references: producer `81c81ec`; consumer `5cd7e849` (direct verdict isolation), `53de26c3` (bounded directed graph context). Include subsequent contract/docs fixes when selecting release heads.

1. Record consumer commit, bind mounts, producer image/connector ID/settings, current connector work and queue depth. Save read-only baseline JSON for a real IP→CIDR→ASN chain, a tagged parent and a missing-parent example. Do not print tokens.
2. Deliver the consumer first. This checkout's workbench binds `/home/x0r/ShellShock/skel` to `/home/analyst`; verify the actual deployment's mount/version instead of assuming every workbench updates automatically. Preserve a stopped workbench's state. Run the deployed CLI or identical bind-mounted source against the existing API, expansion off/on, saving JSON before comparison. Confirm direct verdict/labels/cache evidence agree and inspect graph provenance/limits. No observable creation, `askEnrichment`, paid requests or tag changes.
3. Only after that passes, preserve the old producer image and recreate **only** this service:

   ```sh
   docker image tag "$(docker inspect -f '{{.Image}}' xtm-connector-ioc-trust-cluster-1)" ioc-trust-cluster:pre-r2f
   docker compose -p xtm -f docker-compose.yml build connector-ioc-trust-cluster
   docker compose -p xtm -f docker-compose.yml up -d --no-deps --no-build connector-ioc-trust-cluster
   ```

   Do not recreate the platform or include unrelated platform/work-ID work. Confirm registration/unchanged connector identity, one writer instance, its source hash/image and work/queue health. Read-only verification cannot prove a newly dispatched processing event; source/tests plus runtime version prove the removed writer paths without manufacturing live work.
4. Repeat read-only comparisons, refresh the exact inherited-label association inventory, and record evidence/versions in `open-cti-r2f.7` / `.8`. Zero candidates means a verified no-op, not permission to delete definitions. Nonzero/ambiguous assignments require a new ownership review, rollback export and explicit approval after showing the dry run.

Rollback only affected components: restore consumer files from pre-change `1acc6a9c` (or the recorded deployment baseline) and rerun read-only verification; restore the saved producer image with a temporary compose override `services.connector-ioc-trust-cluster.image: ioc-trust-cluster:pre-r2f` and `up -d --no-deps --no-build --pull never connector-ioc-trust-cluster`. Keep the override outside the repository. Rolling back the producer re-enables inheritance; leave all legacy data unchanged and do not run cleanup. Never roll back unrelated dirty files or erase evidence.

## CIDR edge audit (read-only)

The producer now checks same-family containment for IP/IPv6 and literal-IP URL parents, including existing edges, legacy hints, discovery and returned endpoints. A CIDR child must be wholly inside its parent, not merely share its first address. Invalid links are warned about and left unchanged for review; no automatic rediscovery, removal or repair. Independent direct heuristics remain active.

```sh
# Live read-only capture, using the existing pycti dependency and API credentials:
python3 connectors/ioc-trust-cluster/scripts/audit_cidr_parent_edges.py \
  --raw-file /tmp/cidr-edge-raw-NEW.json > /tmp/cidr-edge-review.json
# Replay an existing capture without network access:
python3 connectors/ioc-trust-cluster/scripts/audit_cidr_parent_edges.py \
  --snapshot /tmp/cidr-edge-raw-NEW.json > /tmp/cidr-edge-review-replay.json
```

The scan covers all IP→IP relationship types, hydrates current endpoints via OpenCTI rather than trusting cached search-index names, and checks whole-network containment. Raw pages are saved before assessment, never overwritten. Paging is capped at 100 pages × 100 rows by default; partial/failed scans or unassessable endpoints exit `2`. A complete scan exits `0` even with findings: inspect `invalid_count`, not just exit status. There is no apply mode, RDAP lookup, paid enrichment or ownership inference from a marker. See [the dft audit and approval-gated repair proposal](../../docs/decisions/cidr-parent-edge-audit-20261015.md).

## Legacy migrations (separate approvals)

`cleanup_structural_labels.py` removes a different obsolete structural-label class and explicitly protects both inherited-state labels; do not relax those safeguards. `migrate_unknown_anchor_scores.py` is a separate score-50 anchor migration with its own dry-run/apply/verify guards. Neither is run by this rollout.

Read-only inventory at **2026-10-15T14:25:32Z** found **0 inherited-label associations**, across all object types/index generations; both label definitions remain. Exact counts, no shard failures/timeouts. Evidence: `/tmp/r2f-inherited-inventory-{raw,summary}.json`; raw SHA-256 `e60c9128dd56f3e851666151f874cbe6502617bb7f528ca667f8ef75f921dfb7`. No cleanup tool was built for an empty inventory. This pre-rollout result must be refreshed after the old writer stops.
