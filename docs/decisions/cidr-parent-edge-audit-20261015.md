# CIDR parent edge audit — open-cti-dft

## Findings (read-only, 2026-10-15)

At **15:10:54Z**, a complete bounded native-API scan returned **1,030 IP→IP edges** (11 pages, stable exact counts, distinct IDs), all `related-to` with CIDR targets. Current hydrated endpoints—not cached Elasticsearch connection names—show **993 contained, 37 invalid**. These comprise **36 host children and one CIDR child**, referencing **20 parent networks**. There were no malformed/unavailable endpoints. This is a paginated observation, not a transactional database snapshot; refresh before any repair.

All 37 have the exact structural marker and confidence 75, but **all lack `createdBy` attribution**. They were created **2026-09-10T19:27:57Z through 2026-09-13T18:17:10Z**. A marker and generated anchor description are consistent with the connector, not proof of assignment ownership. All affected parent tags are currently empty. Full relationship exports additionally show no edge labels, markings or external references; native reference checks found **0 Notes, 0 Reports and 0 other core relationships** referring to these edges. Existing child Notes and other evidence are not removal targets.

Original examples confirmed against current endpoint objects:

| Child | Incorrect parent | Current containing RIR allocation |
|---|---|---|
| `18.214.199.100` | `18.32.0.0/11` | `18.128.0.0/9` |
| `35.138.131.221` | `35.129.0.0/16` | `35.136.0.0/13` |

The third important shape is `18.32.0.0/11` → `18.32.0.0/24`: the first address is inside the target, but the **whole child network is not**.

## Cause and current RDAP evidence

The earliest recorded connector (`68e3c93`, September 16) selected the longest prefix across **all** comma-separated RDAP CIDRs without checking whether it contained the queried IP. Replaying that algorithm on current public RDAP responses reproduces **all 36 incorrect host parents** exactly. Containment filtering was added in `5952e3a` (October 7); legacy edges/hints remained reusable afterward.

All invalid edges predate the earliest recorded source revision, so this is a strongly reproduced mechanism, **not verified historical writer attribution**. The CIDR→narrower-CIDR edge is not reproduced by recorded source, which already skips CIDR discovery; its precise origin remains unknown.

A bounded, read-only free RDAP check received **37/37 HTTP 200 responses** through ARIN bootstrap redirects to the authoritative RIRs; each response provides an allocation containing the complete child. These are **current registration/allocation ranges**, not proof of historical ownership, BGP announcements or a unique correct structural parent. The audit did not call paid enrichment, create replacement anchors or alter a tag, score, edge or Note.

## Consumer impact and prevention

Thirty-six existing host IOCs were retrieved with expansion off/on. Direct verdict, score, labels, source evidence and object/verdict cache status were identical; no enrichment work was dispatched. However, the consumer accepted **37 invalid authoritative parent records** (including the extra CIDR hop). All 36 strongest-parent summaries are currently `unknown`; this does **not** make the false parentage safe—future parent tags could be attributed incorrectly.

The consumer source had pre-existing uncommitted IOC/workflow changes (fingerprint `1ca1d456643c6c4ab01e33ff46d5f895a1ba66c830ad6d1d92a4f5b4dbe20e1a`). Those files were not modified or committed here. **`open-cti-czx`** tracks rejecting invalid authoritative paths with explicit uncertainty while preserving raw related evidence and direct/cache invariance.

The producer now checks same-family **full-network containment** on existing parent selection, legacy hints, discovery and returned lookup endpoints. Invalid contexts produce a warning, cannot repair/create a relationship or attach ASN metadata, and do not trigger automatic replacement. Existing stored edges and independent direct heuristics remain untouched. Missing resolved endpoint identity also fails closed. **291 producer tests pass**, including the cross-repository test against the current consumer source; regression coverage includes IPv4, IPv6, narrowing, literal-IP URLs, malformed endpoints, missing identity and direct ubiquity.

## Review manifest and bounded repair proposal — NOT APPROVED

- **37 mathematically invalid edges** are review items, not authenticated connector-owned deletion candidates. The report has `mutation_authorized=false`, `apply_limit=0`. No apply tool was built or run.
- Recommended first batch: **at most two edges**, `193e497d-b8b0-4db7-9d6e-332b766dfae6` and `239b8e1c-5ef8-434f-a0b4-df1e24f04ca5`, corresponding to the original examples above. Operator must explicitly authorize disposition despite missing author attribution. The remaining 35 require a separately bounded approved batch.
- Proposal: remove only the reviewed invalid relationship IDs through normal OpenCTI APIs. Do **not** delete any of the 20 parent observables, ASN edges, direct labels/scores, definitions or historical Notes. Do not fabricate replacement networks or automatically create the suggested RDAP allocations. Correct replacement discovery is a separate decision; the CIDR-child edge needs no invented replacement.
- Before apply: coordinate a short graph-writer maintenance window; record zero queued/in-flight work, stop only IOC Trust Cluster, refresh the complete audit/RDAP evidence, export each full relationship and current endpoints/references again, and re-read each exact ID immediately before mutation. Skip any metadata/endpoint/reference change, ambiguity or instance mismatch. A stale manifest never authorizes deletion.
- **Rollback export exists for all 37**. Restore semantic relationships using the exported standard STIX ID, original endpoint IDs, relationship type, description, confidence, dates and other supported metadata via OpenCTI. Internal UUIDs and platform creation timestamps may change; references must be reassociated if any appear. Do not claim byte-identical restoration. Validate this restore in an **explicitly approved disposable scope with automatic enrichment suppressed** before approving production removal; no live rollback mutation has been tested or needed so far.
- After an approved batch: reread direct evidence and graph/reference state, verify unrelated data unchanged, account for applied/skipped/errors, then restart the same guarded writer image. Preserve raw evidence and old edges' exports. No paid provider validation.

**Decision pending:** operator approval of the pilot and rollback validation scope. No destructive action is authorized by this audit. Responsible operator: `nick@vectra.ai` (bead owner).

## Evidence

Saved privately outside git at `/home/x0r/.local/state/open-cti/dft-20261015/`, with working originals under `/tmp/dft-*`:

| Evidence | SHA-256 |
|---|---|
| `dft-edges-raw.json` | `4989201c90920b85ff9903fddcc9daa3269851fd53800261675fc32a703669fe` |
| `dft-rdap-raw.jsonl` | `f5f8b70d7cfb3040ef105eb9add0cd594095f48edb532d0beadaa52441b09e85` |
| `dft-full-edge-export.jsonl` | `80625824ebb4b02bf1b1b35e442e4303d4ebb42a0c98d43fdcf676779b26a186` |
| `dft-consumer-impact.json` | `84ce68438f66d55c4458c65fb8d0b92637d0941c68dfb1bce6453591d37002c4` |

`dft-review-manifest.json`, RDAP summaries, reference responses and source-history snapshots accompany these exports. Reproduce future live/offline inventories with `connectors/ioc-trust-cluster/scripts/audit_cidr_parent_edges.py`; it has no mutation mode and reports incomplete scans explicitly.
