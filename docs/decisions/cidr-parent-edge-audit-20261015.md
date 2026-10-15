# CIDR parent edge audit — open-cti-dft

**Current state (2026-10-15): approved two-edge pilot completed at 17:18Z; 35 invalid edges remain outside approval.** See the pilot result below; earlier sections retain the pre-repair evidence.

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

## Consumer guard delivered — open-cti-czx

ShellShock fix **`69bcad4c`** is pushed on `eval/ioc-comparison-oct15` (tested delivered head `0137e934`). The shared traversal now validates same-family whole-child containment using actual IP endpoint values, including literal-IP URLs. Invalid, malformed or missing IP endpoint metadata produces `cidr_not_contained`, `cidr_family_mismatch` or `cidr_endpoint_invalid`; rejected links retain attributed tags/path/provenance in bounded `related_context` with `rejection_reason`, make completeness explicitly false and are not traversed. Independent valid paths remain eligible; private-IP and existing traversal limits remain intact. No RDAP calls, new dependencies or stored-edge changes.

Read-only verification of **36 live affected hosts**, using **94 saved native queries shared between baseline/fixed traversals**, reduced invalid authoritative records **37 → 0**, retained 36 directly observed rejected links, and preserved all direct verdict/source/cache/work evidence. The extra CIDR-child hop is no longer read through its rejected ancestor; the pure guard also rejected **all 37** inventoried cases. All strongest-parent summaries remain `unknown`, with explicit incomplete context rather than benign inference. The exact delivered source replayed all 36 saved results identically without network access.

Clean delivery-worktree gates: **287 consumer tests passed**, one existing opt-in skip; **291 producer/cross-repository tests passed**; repository-policy lint, compile and whitespace checks passed. Concurrent self-reference/quoted-IOC changes were preserved rather than committed as part of the guard. Live-verified, delivered and host-mounted consumer SHA-256: `fd54fc94d71149667051d60de51e34cf614fe819f70cd60ee372d6fadbc77e52`. The workbench remained **exited**; no stopped service was started for validation. Git pull/rebase and push succeeded, with both delivery and shared branch clean/up to date at verification.

Evidence: `/home/x0r/.local/state/open-cti/czx-20261015/` (`czx-live-verification.json`, 94 raw response files, `czx-live-summary.json`, `czx-release-replay.json`, delivery proof and gates). **This closes consumer prevention only. The 37 stored edges are still unrepaired and their disposition remains approval-gated under open-cti-dft.**

## Guard deployment and verification

Signed commit **`b7bebdb`** was deployed at **15:28:00Z**, recreating **only** IOC Trust Cluster. Image `sha256:02311d249b5ef7896b65396d11d4c56046b0591bb8124264d0f38f40aa2f36bf`; source SHA-256 `6b2c855842842149134a3ff0922d021a9f705c445ea96e1d04817aa6f06e1347` matches the checkout. Same connector identity, 274 existing ASN-backed anchors loaded, one running writer, zero ready/unacknowledged messages before/after. The deployed pure guard rejected **37/37** recorded invalid cases without invoking the connector constructor, processing messages or any mutation API.

A fresh live audit through `http://opencti:8080` verified **identical decoded JSON values for all 1,030 relationship/endpoint records** to the initial native snapshot, with the same 37 invalid edges left in place. This proves preservation of those graph/direct-evidence records, not a global transaction or all unrelated state. A normal queued IPv6 work item was observed during restart, including the retained graph audit-Note behavior; no work was dispatched by this audit. No invalid edge was repaired or removed.

Rollback: prior image `sha256:568dc78e4696b5fc27fc697bf9aba84eeaecb0f836f6ea6bceaf12ed27eef6df` retained as **`ioc-trust-cluster:pre-dft`**. If needed, use an external temporary compose override setting only `services.connector-ioc-trust-cluster.image` to that tag, then `docker compose -p xtm -f docker-compose.yml -f /tmp/dft-rollback.yml up -d --no-deps --no-build --pull never connector-ioc-trust-cluster`. This rolls back code only; no data rollback is currently necessary. Unrelated OpenCTI and ShellShock worktree diffs remained byte-identical to their pre-task snapshots.

## Original review manifest and bounded repair proposal (pre-approval record)

- **37 mathematically invalid edges** are review items, not authenticated connector-owned deletion candidates. The report has `mutation_authorized=false`, `apply_limit=0`. No apply tool was built or run.
- Recommended first batch: **at most two edges**, `193e497d-b8b0-4db7-9d6e-332b766dfae6` and `239b8e1c-5ef8-434f-a0b4-df1e24f04ca5`, corresponding to the original examples above. Operator must explicitly authorize disposition despite missing author attribution. The remaining 35 require a separately bounded approved batch.
- Proposal: remove only the reviewed invalid relationship IDs through normal OpenCTI APIs. Do **not** delete any of the 20 parent observables, ASN edges, direct labels/scores, definitions or historical Notes. Do not fabricate replacement networks or automatically create the suggested RDAP allocations. Correct replacement discovery is a separate decision; the CIDR-child edge needs no invented replacement.
- Before apply: coordinate a short graph-writer maintenance window; record zero queued/in-flight work, stop only IOC Trust Cluster, refresh the complete audit/RDAP evidence, export each full relationship and current endpoints/references again, and re-read each exact ID immediately before mutation. Skip any metadata/endpoint/reference change, ambiguity or instance mismatch. A stale manifest never authorizes deletion.
- **Rollback export exists for all 37**. Restore semantic relationships using the exported standard STIX ID, original endpoint IDs, relationship type, description, confidence, dates and other supported metadata via OpenCTI. Internal UUIDs and platform creation timestamps may change; references must be reassociated if any appear. Do not claim byte-identical restoration. Validate this restore in an **explicitly approved disposable scope with automatic enrichment suppressed** before approving production removal; no live rollback mutation has been tested or needed so far.
- After an approved batch: reread direct evidence and graph/reference state, verify unrelated data unchanged, account for applied/skipped/errors, then restart the same guarded writer image. Preserve raw evidence and old edges' exports. No paid provider validation.

**Decision at proposal time (superseded by the pilot result below):** operator approval of the pilot and rollback validation scope. No destructive action is authorized by this audit. Responsible operator: `nick@vectra.ai` (bead owner).

## Approved two-edge pilot — completed 2026-10-15

The operator's **“yes repair”** approved the previously proposed **two-ID pilot**, including isolated rollback validation, despite unproven historical writer attribution. It did not authorize the other 35. Fresh native inventory still showed 1,030 edges / 37 invalid; fresh free RDAP returned 2/2 HTTP 200 containing allocations. The exact two full native SDK relationship records, four current endpoints (including Note content), and zero dependent Notes/Reports/core relationships were exported before mutation. Platform identity: `2abd4223-fead-4829-9566-957ad965cf02`, version `7.260910.0`.

| Removed relationship ID | Pair | API deletion UTC |
|---|---|---|
| `193e497d-b8b0-4db7-9d6e-332b766dfae6` | `18.214.199.100` → `18.32.0.0/11` | `17:18:12.977Z` |
| `239b8e1c-5ef8-434f-a0b4-df1e24f04ca5` | `35.138.131.221` → `35.129.0.0/16` | `17:18:13.227Z` |

**Production apply: 2 applied, 0 skipped, 0 errors. No replacement observables or edges were created.** No parent observable, ASN ownership edge, label, definition, score or historical Note was targeted for deletion or alteration.

### Restore validation and safety boundaries

Before either live deletion, a **native draft workspace, never published**, held a nonce-marked disposable `related-to` relationship between two existing endpoint objects. No SCO fixture was created. Automatic update enrichment was false on every internal enrichment connector; none of the configured automatic scopes matched `related-to` / core relationships, and the graph writer was stopped. Native create → read → delete → restore → read preserved the standard STIX ID, direction/endpoints, relationship type, description, confidence, language, revocation and semantic timestamps. The **internal UUID changed**, as anticipated. This proves the exported semantic restore in isolated draft scope, **not byte-identical database restoration or a live production restore**.

Preparation caught incompatible host pycti/FastAPI dependencies and the SDK's identity-only create response. The pinned deployed SDK was used in a `--rm` utility process, without registering a connector or saving credentials; full reads were added before comparing restored records. An initial isolated rehearsal aborted before any live edge deletion and its draft was discarded. Both rehearsal workspaces are now absent. **17 archived offline pilot/export checks pass**, including stale/changed metadata, out-of-scope IDs and the identity-only SDK response.

### Post-apply proof

- Immediate and post-writer-resume complete inventories agree: **1,028 edges = 993 contained + 35 invalid** (34 host children, one CIDR child). Every other IP relationship/endpoint record is identical to the pre-apply snapshot as decoded JSON, apart from the two explicitly removed records.
- All four endpoint snapshots, including labels, scores, markings, reports, references and full bounded Note content, are identical before/after. Historical evidence is retained.
- Both IOCs were checked read-only: the removed IDs are absent from parent/related context, and direct verdict/source/cache evidence remains equal using the **same pinned consumer source** (`fd54fc94`) as the earlier baseline. Concurrent consumer source-freshness changes were not mistaken for data changes; saved native responses were reused locally rather than re-querying to adjust filtering.
- Only IOC Trust Cluster was paused/resumed. Same container/image `02311d24`, same connector identity; it resumed at **17:18:15Z**, loaded the same **274 ASN-backed anchors**, and ready/unacknowledged counts are **0/0** before/after. The workbench stayed stopped. No paid enrichment or replacement discovery was invoked.

### Evidence and rollback

Private artifact root: **`/home/x0r/.local/state/open-cti/dft-pilot-20261015/`** (directories 0700, files 0600). The successful batch is `apply-pilot-verified/`; all preparatory attempts are retained separately.

- `apply-pilot-verified/rollback-export.json` — SHA-256 `259dd62aa9c64f7a42463b44af1dba3d67f7b792e33bca71d326fbb34d88e00e`.
- `apply-pilot-verified/restore-proof.json` — SHA-256 `bde99a141cad1068c192bec868da26407d81e72439d66812bdcd4cc28fc3b74d`.
- `dft-pilot-after-resume-raw.json` — SHA-256 `707b891b00997bba1bf6b51ebf4915e0b7dec2c527ed8b999b66f568570a5b7c`.
- `dft-pilot-verification.json`, native API journals, fresh RDAP, four endpoint snapshots, consumer proof, queue/runtime logs, `dft-pilot-repair.py`, SDK runner and runnable `test_dft_pilot.py` accompany these exports.

No data rollback was required. If explicitly rolling this batch back, pause the same writer and verify the exported platform identity, original endpoint IDs, unchanged metadata and current references first. Using the healthy deployed SDK, load the archived `dft-pilot-repair.py` and call its tested **`restore(api, record)`** for **only** the two `rollback-export.json` relationship records. The helper re-reads and checks exported semantic fields; it refuses nonempty author/label/marking/reference/organization/workflow metadata rather than dropping it. Record new internal IDs, reassociate any newly introduced references, and reverify direct evidence before resuming. Do **not** restore known-bad edges just to retest this proof.

**Remaining decision:** `remaining-35-review.json` contains the exact refreshed IDs/pairs for a proposed separate batch of at most 35, with `mutation_authorized=false` and `apply_limit=0`. It requires new explicit approval and refreshed full exports, endpoint/reference/RDAP checks before any action. `open-cti-dft` stays blocked on that disposition; this pilot does not authorize further cleanup.

## Evidence

Saved privately outside git at `/home/x0r/.local/state/open-cti/dft-20261015/`, with working originals under `/tmp/dft-*`:

| Evidence | SHA-256 |
|---|---|
| `dft-edges-raw.json` | `4989201c90920b85ff9903fddcc9daa3269851fd53800261675fc32a703669fe` |
| `dft-rdap-raw.jsonl` | `f5f8b70d7cfb3040ef105eb9add0cd594095f48edb532d0beadaa52441b09e85` |
| `dft-full-edge-export.jsonl` | `80625824ebb4b02bf1b1b35e442e4303d4ebb42a0c98d43fdcf676779b26a186` |
| `dft-consumer-impact.json` | `84ce68438f66d55c4458c65fb8d0b92637d0941c68dfb1bce6453591d37002c4` |

`dft-review-manifest.json`, RDAP summaries, reference responses and source-history snapshots accompany these exports. The final source-bound review is `dft-postdeployment-manifest.json`; final raw snapshot SHA-256 `e1aef4a6d08244928176630ce43dba0c07acdeec2ad9a3a103a290a9f7292485`. `dft-deployment-verification.json`, runtime guard proof, queue snapshots and rollout logs record the deployment. Reproduce future live/offline inventories with `connectors/ioc-trust-cluster/scripts/audit_cidr_parent_edges.py`; it has no mutation mode and reports incomplete scans explicitly.
