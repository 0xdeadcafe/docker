# Vectra commonness review pilot

Status: **source-local pilot accepted; herd writes remain dormant**
Date: 2026-10-12
Live sources: one opaque source

## Decision

The bounded source-local pilot is acceptable for development use. Keep both
`VECTRA_COMMONNESS_WRITE` and `VECTRA_COMMONNESS_REVIEW_WRITE` false by default.
The cross-source reducer may be run in shadow mode. Do not enable herd writes
until a second real source supplies fresh evidence; synthetic multi-source
fixtures stay test-only.

Commonness remains a low-hunting-discrimination observation, not a benign
verdict. No routing or suppression policy is enabled.

## Bounded y5g write

One explicitly authorized y5g cycle ran with creation capped at one. It executed
10 bounded Metadata queries: four returned rows, six were true zero, one request
retried, and none failed or returned partial data. Metadata runtime was 98.642
seconds and wall time was 110.325 seconds.

The cycle reused 25 existing Observables, created one Observable, and upserted 26
native source Notes with 26 neutral label associations. It observed zero threat
conflicts and changed no scores or Indicators. The one-off environment override
expired with the container; the configured default remains write-off.

## Two-run reducer result

Two complete shadow scans produced identical state:

| Metric | Run 1 | Run 2 |
|---|---:|---:|
| Eligible Observables | 26 | 26 |
| Native source Notes / valid votes | 26 / 26 | 26 / 26 |
| Source-local candidates | 26 | 26 |
| Herd candidates | 0 | 0 |
| Stale / malformed / duplicate | 0 / 0 / 0 | 0 / 0 / 0 |
| Threat conflicts | 0 | 0 |
| Projected reducer writes | 0 | 0 |
| Actual reducer mutations | 0 | 0 |
| OpenCTI pages | 2 | 2 |
| Runtime | 0.854 s | 0.902 s |

Candidate churn and projected stale removals were zero. The one-source invariant
held: no herd label or aggregate herd Note was present or projected.

## Analyst review

All 26 candidates had approved signal evidence in two disjoint windows. The
sample contained 25 domains and one shared-auth IPv4 Observable; 25 were
recognized as shared service/update/certificate/authentication infrastructure.
One domain remains a manual follow-up rather than being guessed benign.

- **Confirmed low-discrimination precision:** 25/26, or **96.2%** conservative
  lower bound when the deferred item is counted as unconfirmed.
- **Reducer coverage:** 26/26 persisted source-evidence Observables, or 100%.
- **Threat contradiction rate:** 0/26.
- **Graph growth:** one Observable, 26 source Notes, and 26 neutral label
  associations from y5g; zero reducer-owned growth.
- **Enrichment savings:** 0 / not applicable. VirusTotal and IPQS remain
  analyst-triggered.

No endpoint values or source identities are stored in this report.

## Safety validation

Local tests cover one-source, two-source, duplicate-source, stale, malformed,
orphan, paginated, threat-conflict, deterministic upsert, partial-scan,
cleanup, rollback, and privacy behavior. Synthetic source fixtures are never
written to OpenCTI. The live pilot created no `fp-confirmed`, changed no score,
created no Indicator, and suppressed no detection.

## Disable and rollback

- Stop source writes with `VECTRA_COMMONNESS_WRITE=false`.
- Stop reducer writes with `VECTRA_COMMONNESS_REVIEW_WRITE=false`.
- With the reducer write gate explicitly enabled for one rollback command,
  `review.py purge` removes only `vectra-metadata:herd-common` associations and
  `vectra-commonness-review:*` Notes.
- `delete_source_evidence.py <opaque-id> dry-run` previews source cleanup; its
  apply mode removes only that source's y5g Notes and eligible owned labels.
  Observables, scores, Indicators, and analyst/threat state remain.

Any enrichment-routing proposal requires a separate measured task and a new,
reversible opt-in flag.
