# Vectra commonness review contract

Status: accepted for `open-cti-x39.3`
Evidence version: `schema_version=1`, `query_version=x39.1-commonness-v1`

## Scope and ownership

`open-cti-y5g` remains the only owner of per-source Notes and these labels:

- `vectra-metadata:common-domain`
- `vectra-metadata:common-ip`
- `vectra-metadata:shared-auth-ip`
- `vectra-metadata:commonness-conflict`

The review reducer does not query Vectra Metadata and does not rewrite that
state. It may own only:

- `vectra-metadata:herd-common`
- one deterministic `vectra-commonness-review:<digest>` Note per herd-qualified Observable

Commonness means low hunting discrimination, not benignness. Scores,
Indicators, analyst/threat/sinkhole labels, detections, and source Notes remain
authoritative and untouched.

## Accepted source evidence

A source Note counts only when all of the following hold:

- its abstract is `vectra-commonness:<opaque-source-id>:<digest>`;
- its JSON content has the accepted schema and query versions;
- its `source_id` is an opaque 1–64 character alphanumeric, hyphen, or
  underscore value and matches the abstract;
- it references exactly one `Domain-Name` or `IPv4-Addr` Observable and its
  declared type matches that object;
- it has at least one qualifying signal valid for that object type;
- `updated_at` is no more than five minutes in the future (clock-skew allowance)
  and is no older than two days by default.

The maximum age is an operational freshness window, not a telemetry lookback.
It is configurable with `VECTRA_COMMONNESS_REVIEW_MAX_AGE_DAYS` when connector
scheduling changes.

Malformed, orphaned, future-dated, stale, unsupported-version, and partial-read
evidence does not vote. It is counted in aggregate metrics and is never treated
as negative evidence.

## Reduction

For each Observable, a source contributes at most one vote, regardless of its
number of Notes, signals, windows, or events. When duplicate valid Notes exist,
the newest Note supplies that source's vote.

- one fresh distinct source: `source-local`;
- two or more fresh distinct sources: `herd-common`.

The herd threshold is fixed at **2**. IP and domain evidence never roll up into
one another. Signal counts do not increase source count.

Source-local explanations come from the existing y5g evidence and shadow review
plan. A persisted aggregate review Note is needed only for herd-qualified
Observables. It contains only classification, distinct-source count, signal
classes, freshness, and whether authoritative threat context coexists.
It contains no source IDs, endpoint values, tenant names, users, internal hosts,
events, URLs, credentials, or secrets.

## Mutation and lifecycle

Shadow mode is the default. Apply mode additionally requires
`VECTRA_COMMONNESS_REVIEW_WRITE=true`.

A complete successful scan may upsert the reducer Note, add/remove only
`vectra-metadata:herd-common`, and delete stale reducer Notes. Failed, partial,
or capped scans remove nothing and perform no writes. Source-local labels and
source Notes remain y5g-owned and are removed through y5g lifecycle or its
source-deletion tool.

Only one authorized live source currently exists. It must produce zero live
herd-common candidates. Multi-source behavior is tested with local fixtures;
no synthetic source evidence is written to OpenCTI.

Paid VirusTotal/IPQS enrichment is already analyst-triggered. Routing changes
and claimed enrichment savings are therefore out of scope and remain disabled;
a future measured need requires a separate task and reversible flag.
