# Vectra endpoint-commonness validation

Status: **accepted for implementation in `open-cti-y5g`**
Query version: `x39.1-commonness-v1`
Replay anchor: `2026-10-12T18:02:00Z`
Source: one authorized tenant, recorded as opaque ID `tenant-01`

## Decision

Build endpoint-behavior noise intelligence, not a false-positive classifier.
OpenCTI remains the observable store. Vectra Metadata has two jobs:

1. Measure how common existing OpenCTI domain/IP observables are.
2. Discover strongly recurring common endpoints and create or reuse their OpenCTI observables.

A common observable is usually a poor discriminator for IOC hunting. It is not
necessarily benign: shared services, scanners, compromised SaaS/CDN endpoints,
sinkholes, and malicious infrastructure can all be common. Commonness must
coexist with, and never override, threat evidence.

## Privacy and output contract

The replay exports only:

- opaque tenant ID;
- normalized public `Domain-Name` or `IPv4-Addr` value while querying/upserting;
- signal and query version;
- aggregate host/user breadth and event count, preferably bucketed;
- first/last seen, fixed window ID, and recurrence;
- query outcome (`ok`, `partial`, `error`, or true zero) and runtime.

It must never export raw users, internal hosts/IPs, individual events, customer
names, credentials, tokens, or tenant URLs. Reports committed to this repository
contain aggregate counts only and no endpoint values.

## Replay manifest

### Inputs and normalization

- Existing-observable lookup: page OpenCTI `Domain-Name` and `IPv4-Addr`
  observables. The validation sample was the 100 most recently created values of
  each type; 100 domains and 52 valid public host IPv4 values remained after
  validation. Production processing may continue through bounded pages across
  cycles.
- Discovery: Vectra Metadata only. Vectra detections are not an input.
- Domains: lowercase, remove one trailing dot and HTTP port, require a valid
  dotted DNS name, and reject local/reserved suffixes.
- IPv4: canonical public host addresses only; reject private, reserved, loopback,
  link-local, multicast, and CIDR values.
- Targeted batch size: **50**. The hard contract is at most 100, but 50 is the
  validated value for this Metadata service.

### Fixed windows

The 30-day replay used three disjoint half-open windows:

| Window | Start | End |
|---|---|---|
| `w1` | 2026-09-12 18:02Z | 2026-09-22 18:02Z |
| `w2` | 2026-09-22 18:02Z | 2026-10-02 18:02Z |
| `w3` | 2026-10-02 18:02Z | 2026-10-12 18:02Z |

Every query must constrain both `dt` and the table's event-time field. Current
telemetry began on 2026-09-28, so recurrence is demonstrated in `w2` and `w3`;
`w1` is a retention gap, not evidence of absence.

### Query map

| Signal | Table | Candidate expression | Breadth | Use |
|---|---|---|---|---|
| DNS | `network.dns._all` | normalized `query` | distinct `id.orig_h` | targeted lookup/corroboration |
| TLS SNI | `network.ssl._all` | normalized `server_name` | distinct `id.orig_h` | targeted lookup/corroboration |
| HTTP Host | `network.http._all` | normalized `host` | distinct `id.orig_h` | lookup and discovery |
| M365 shared auth | `m365.signins._all` | `ip_address` | distinct `user_principal_name` | lookup and discovery |
| destination session | `network.isession._all` | `id.resp_h` | distinct `id.orig_h` | targeted lookup only |

M365 includes only `status.error_code = 0`. Network signals require outbound
traffic. HTTP discovery additionally requires at least one 2xx/3xx response.

### Targeted SQL shape

Substitute the table-specific expressions from the query map. Candidate values
must be validated before interpolation.

```sql
SELECT
  <normalized_candidate> AS candidate,
  CASE
    WHEN <event_time> < from_iso8601_timestamp('2026-09-22T18:02:00Z') THEN 'w1'
    WHEN <event_time> < from_iso8601_timestamp('2026-10-02T18:02:00Z') THEN 'w2'
    ELSE 'w3'
  END AS window_id,
  count(DISTINCT <breadth_subject>) AS breadth,
  count(*) AS event_count,
  min(<event_time>) AS first_seen,
  max(<event_time>) AS last_seen
FROM <table>
WHERE dt >= from_iso8601_timestamp('2026-09-12T18:02:00Z')
  AND dt <  from_iso8601_timestamp('2026-10-12T18:02:00Z')
  AND <event_time> >= from_iso8601_timestamp('2026-09-12T18:02:00Z')
  AND <event_time> <  from_iso8601_timestamp('2026-10-12T18:02:00Z')
  AND <normalized_candidate> IN (<at-most-50-values>)
  <signal-safety-filters>
GROUP BY <normalized_candidate>, 2
ORDER BY candidate, window_id
LIMIT 500;
```

### Discovery SQL shape

Discovery is approved only for HTTP Host and successful M365 source IP because
those query shapes returned complete, target-confirmable results. Use breadth
`10` for HTTP and `3` for M365 in each window, ordered by breadth and capped at
500 aggregate rows. A candidate qualifies only after appearing in at least two
disjoint windows.

```sql
SELECT
  <normalized_candidate> AS candidate,
  <fixed-window-case> AS window_id,
  count(DISTINCT <breadth_subject>) AS breadth,
  count(*) AS event_count,
  min(<event_time>) AS first_seen,
  max(<event_time>) AS last_seen
FROM <table>
WHERE <fixed-dt-and-event-time-range>
  <signal-safety-filters>
GROUP BY <normalized_candidate>, 2
HAVING count(DISTINCT <breadth_subject>) >= <10-http-or-3-m365>
  <http-success-guard>
ORDER BY breadth DESC, event_count DESC
LIMIT 500;
```

A successful zero from broad DNS, SNI, or iSession aggregation is not a true
zero when a bounded exact query returns matches. Record it as
`unsupported_query_shape`, not absence. Do not fall back to unbounded retries.

## Aggregate replay results

All 20 primary queries completed; three rate-limited calls succeeded after one
retry. Primary query runtime was 208.262 seconds. No raw telemetry was saved.

### Existing OpenCTI observable lookup

OpenCTI contained 90,491 domains and 3,678 IPv4 observables. The bounded
validation sample produced:

| Signal | Valid candidates | Matched | Match rate | Recurring in 2 windows |
|---|---:|---:|---:|---:|
| DNS | 100 domains | 5 | 5.0% | 3 |
| TLS SNI | 100 domains | 7 | 7.0% | 5 |
| HTTP Host | 100 domains | 0 | 0.0% | 0 |
| M365 shared auth | 52 IPv4 | 0 | 0.0% | 0 |
| destination session | 52 IPv4 | 14 | 26.9% | 11 |

Zero HTTP/M365 matches describe this deterministic OpenCTI sample only; their
working discovery queries below prove tenant coverage.

### Metadata-led discovery

| Signal | Unique candidates | Recurring in 2 windows | Query result |
|---|---:|---:|---|
| HTTP Host, breadth >=10 | 139 | 101 | proceed |
| M365 success source IP, breadth >=3 | 203 | 69 | proceed |
| DNS | 0 | 0 | defer: broad query silently returned zero |
| TLS SNI | 0 | 0 | defer: broad query silently returned zero |
| destination session IP | 0 | 0 | defer: broad query silently returned zero |

The broad-zero results are query-shape failures: bounded OpenCTI candidate
queries matched DNS, SNI, and iSession data in the same windows.

Targeted confirmation of the 101 recurring HTTP-discovered domains found:

| Confirmation signal | Matched | Recurring in 2 windows |
|---|---:|---:|
| HTTP Host | 101 (100%) | 101 |
| DNS | 79 (78.2%) | 77 |
| TLS SNI | 25 (24.8%) | 22 |

The 170 recurring discovery candidates mapped to 24 existing OpenCTI
observables and 146 missing observables. A cap of 100 new observables per run
keeps graph growth bounded; subsequent cycles can converge idempotently.

### Conflict review

All 170 recurring discovery candidates were compared with exact OpenCTI
observables. Twenty-four existed. There were zero current conflicts from score
>=70, malicious/threat/sinkhole labels, linked Indicators, or inherited
parent-only malicious state. The 21 matched lookup candidates also had zero
current conflicts.

This observed conflict rate is `0/170`, not a safety guarantee. Future conflicts
must remain visible and authoritative while commonness evidence stays attached.

### Tenant inventory

One authorized tenant credential set was available. No tenant name, URL, or
secret was recorded. No synthetic second tenant was created; multi-tenant
comparison remains optional.

## Signal decision matrix

| Signal | Existing lookup | Discovery/create | Qualification | Label |
|---|---|---|---|---|
| HTTP Host domain | proceed | **proceed** | >=10 hosts in each of >=2 windows; successful HTTP response | `vectra-metadata:common-domain` |
| DNS domain | proceed | defer | targeted exact breadth >=10 in >=2 windows; discovery candidate may be corroborated | `vectra-metadata:common-domain` |
| TLS SNI domain | proceed | defer | targeted exact breadth >=10 in >=2 windows; discovery candidate may be corroborated | `vectra-metadata:common-domain` |
| M365 source IPv4 | proceed | **proceed** | >=3 successful-sign-in users in each of >=2 windows | `vectra-metadata:shared-auth-ip` |
| destination IPv4 | proceed | defer | targeted exact breadth >=10 hosts in >=2 windows | `vectra-metadata:common-ip` |
| JA3/JA3S, X509, URL, email, hash, port | defer | reject for this version | no validated exact discovery identity/overlap | none |

Implementation rules for `open-cti-y5g`:

- Upsert one deterministic aggregate evidence record per tenant and observable.
- Reuse existing observables; create only recurring HTTP/M365 discoveries.
- Create at most 100 missing observables per run; never create Indicators.
- Keep labels neutral; remove old `vectra-metadata-benign`/automatic
  `fp-candidate` behavior from this path.
- Re-evaluate over a 30-day lookback. Remove connector-owned commonness labels
  when fewer than two populated windows qualify; retain the observable and
  threat context.
- Never lower scores, set `fp-confirmed`, suppress detections, or overwrite
  malicious labels/Indicators.
- Record `vectra-metadata:commonness-conflict` when commonness and threat evidence
  coexist.
- An optional enrichment-cost policy may skip non-authoritative paid reputation
  calls only for fresh qualifying evidence. It must be separately enabled,
  reversible, and must never block threat-feed ingestion.

## OpenCTI evidence contract smoke test

A live API smoke test created a temporary Observable and called `noteAdd` twice
with the same supplied STIX ID and `update: true`. OpenCTI returned the same
internal Note ID, updated the content in place, and retained one object
reference. The temporary Note and Observable were deleted immediately. This
selects a deterministic Note as the native aggregate evidence record; no
Sighting is needed.

## Shadow rollout result

A live production-shaped connector cycle completed in explicit shadow mode on
2026-10-12. It executed 10 bounded queries: 4 returned rows, 6 were true zero,
one call retried, and there were no errors or partial results. The cycle saw 107
valid paged OpenCTI candidates and 309 discovery candidates, produced 149
qualified plans (25 existing and 124 missing), rejected 163 plans, observed zero
current threat conflicts, and projected 249 object/evidence operations if writes
were later enabled. Query runtime was 96.749 seconds and wall time was 100.851
seconds. Created, updated, and stale-removed counts were all zero. Logs contained
aggregate counts only; targeted API filter values were suppressed.

The legacy dry-run found 202 legacy-labeled, connector-created Observables and
202 legacy label associations, but no matching generated legacy Notes. Per the
ownership rule, apply mode would therefore remove zero labels, change zero
scores, and delete zero Observables; all 202 unsupported associations are
retained for manual review rather than guessed ownership.

## Final disposition

**Proceed** to `open-cti-y5g` with HTTP-domain and M365 shared-auth discovery,
plus targeted lookup for existing domains/IPs. Defer broad DNS, SNI, and
destination-IP discovery until a bounded query shape proves reliable. One tenant
is sufficient for implementation; additional tenants may later add stronger
cross-tenant commonness confidence.
