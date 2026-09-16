# open-cti Connector TODO

Priority key: **P0** crash/corrupt · **P1** reliability or feature-blocker · **P2** correct but not urgent · **P3** polish/housekeeping · **DEFERRED** questioned or wrong file

---

## Working order — all items, both connectors

Sorted by priority. "Batch" column calls out items that should land in the same PR.

| ID | Connector | Pri | Batch | One line |
|---|---|---|---|---|
| V1 | vectra | **P0** | V1+V2 | ~~Tests never collect — no `sys.path` bootstrap~~ ✅ |
| V2 | vectra | **P0** | V1+V2 | ~~Class-body pycti import crashes collection even with V1 fixed~~ ✅ |
| B1 | trust | **P0** | — | ~~PSL missing — ccTLD domains get wrong parent (`bbc.co.uk` → `co.uk`)~~ ✅ |
| B3 | trust | **P0** | — | ~~X509 parent search always misses → duplicate CA anchors every run~~ ✅ |
| B8 | trust | **P0** | — | ~~Non-integer indicator score crashes `process_message`~~ ✅ |
| B4 | trust | **P1** | B4+V3 | ~~`_add_label` swallows failures, marks labels done regardless~~ ✅ |
| V3 | vectra | **P1** | B4+V3 | ~~Same `_add_label` bug in vectra connector~~ ✅ |
| V4 | vectra | **P1** | after V3 | ~~Note fires on label failure; no dedup → accumulates per cycle~~ ✅ |
| V5 | vectra | **P1** | after V3 | ~~`vectra-metadata-benign` permanently missing if second label add fails~~ ✅ |
| V6 | vectra | **P1** | — | ~~Poll `raise_for_status()` leaks `HTTPError` past `VectraMetadataError` → kills whole cycle~~ ✅ |
| B7 | trust | **P1** | — | ~~Deleted parent silently orphans child cascade forever~~ ✅ |
| B2 | trust | **P1** | — | ~~`_entity_score` — score=0 reads as 50 (falsy gotcha)~~ ✅ |
| #2 | trust | **P1** | after B1 | ~~NS Allowlist — must ship before NS lookup is enabled in any deployment~~ ✅ |
| #1 | trust | **P1** | after B1+B3 | ~~Parent Reputation Aggregator — cascade never fires without it~~ ✅ |
| V8 | vectra | **P1¹** | — | ~~`_rows_from_native` misses `results:[...]` list — silent empty result~~ ✅ |
| #4 | trust | **P2** | — | ~~malicious-cascade revocation note path~~ ✅ |
| #5 | trust | **P2** | — | ~~fp-candidate + malicious-cascade conflict note (partial impl exists)~~ ✅ |
| B5 | trust | **P2** | — | ~~`confidence=75` hardcoded, ignores `CONNECTOR_CONFIDENCE_LEVEL`~~ ✅ |
| B15 | trust | **P2** | — | ~~ASN RDAP calls have no 429 backoff; owner permanently missed on rate-limit~~ ✅ |
| V7 | vectra | **P2** | — | ~~Cycle exceptions logged without traceback~~ ✅ |
| B13 | trust | **P3** | B13+V10 | ~~Dockerfile runs as root~~ ✅ |
| V10 | vectra | **P3** | B13+V10 | ~~Dockerfile runs as root~~ ✅ |
| B14 | trust | **P3** | B14+V9 | ~~`requirements.txt` has no upper-bound pins~~ ✅ |
| V9  | vectra | **P3** | B14+V9 | ~~`requirements.txt` has no upper-bound pins~~ ✅ |
| B6  | trust | **P3** | — | ~~`resp.read()` in `_get_asn_owner` has no size cap~~ ✅ |
| B9  | trust | **P3** | — | ~~Session caches unbounded and never TTL-refreshed~~ ✅ |
| B10 | trust | **P3** | — | ~~IPv6 literal URL hosts: `.split(":")[0]` corrupts address; parent extraction silently drops~~ ✅ |
| B11 | trust | **P3** | — | ~~`OBSERVABLE_PARENT_TYPES` / `LABEL_ONLY_PARENT_TYPES` are dead constants~~ ✅ |
| V11 | vectra | **P3** | — | ~~OAuth2 token cache discarded on every cycle~~ ✅ |
| V12 | vectra | **P3** | — | ~~`_add_discovery_note` failure logged at DEBUG, should be WARNING~~ ✅ |
| V13 | vectra | **P3** | — | ~~`if ok_fp and needs_fp:` — `needs_fp` is always True there; misleading dead condition~~ ✅ |
| V14 | vectra | **P3** | — | ~~`_breadth_bucket` returns `"10-19"` for any n < 10; wrong label if threshold lowered~~ ✅ |
| V15 | vectra | **P3** | — | ~~`_find_observable` failure at DEBUG; falls through to create, risking duplicates~~ ✅ |
| V16 | vectra | **P3** | — | ~~`_build_client` exceptions not caught in `run()` — unexpected error crashes loop~~ ✅ |
| V17 | vectra | **P2** | — | ~~No threshold lower-bound: `host_threshold=0` marks everything fp-candidate~~ ✅ |
| V18 | vectra | **P3** | — | `malicious_guard` uses `or 50` falsy-zero pattern (same as B2; correct here but inconsistent) |
| B16 | trust | **P2** | — | ~~`fp_cascade_score_max` not validated — fp-candidate can reach malicious-scored observables~~ ✅ |
| B17 | trust | **P3** | — | ~~Note creation failures silently swallowed at DEBUG (same root as B4)~~ ✅ |
| B18 | trust | **P3** | — | ~~Stats have no counter for revocation or conflict events~~ ✅ |
| B19 | trust | **P3** | — | ~~`_find_observable` `extra_filters` parameter dead after B3~~ ✅ |
| #3 | trust | DEFERRED | — | Parent promotion note — superseded by #1 |
| #6 | trust | DEFERRED | — | Dynamic sinkhole IPs — simplify the design first |
| #7 | trust | DEFERRED | — | vectra CIDR marking — wrong file, belongs in vectra backlog |
| #9 | trust | DEFERRED | — | JA4/ASN verdict path — YAGNI until demand exists |

> ¹ **V8 risk note:** `_rows_from_cantina` has `('results',)` in `_ROW_PATHS`, meaning
> the `results: [...]` shape has been observed in Cantina responses. If native mode
> returns the same shape, V8 silently drops every query result — upgrade to P0 if
> native mode is in active use.

**Dependency chain — do not reorder:**
- **B1 → #2, #1** — PSL fix before NS Allowlist or Parent Aggregator
- **B3 → #1** — X509 dedup before Parent Aggregator
- **V3 → V4 → V5** — fix `_add_label` return value first; V4 and V5 builds on that bool

**Batch notes:**
- **B4 + V3** — identical bug in two connectors; fix in one PR touching both files
- **B13 + V10** — identical Dockerfile change; one PR, two connectors
- **B14 + V9** — identical `requirements.txt` change; one PR, two connectors

---

# ioc-trust-cluster

---

## P0 — Fix immediately (data corruption or crash)

No new features until these are resolved.

---

### B1 · Naive eTLD extraction produces wrong parent for ccTLD+SLD domains

`_extract_parent("Domain-Name")` takes the last two labels unconditionally:

```python
parts = value.rstrip(".").split(".")
if len(parts) > 2:
    return ("Domain-Name", ".".join(parts[-2:]))
```

For `cdn.bbc.co.uk` this returns `co.uk` — a TLD registry, not a registrant.
Every `.co.uk` domain clusters under the same parent, enabling cross-tenant
malicious-cascade. Same problem applies to `com.au`, `co.jp`, `org.uk`, etc.

The NS cycle guard in `_get_authoritative_ns` has the same flaw: it checks
`ns.split(".")[-2:] == domain`, which fails to detect the cycle for
`domain="example.co.uk"` and `ns="ns1.example.co.uk"` (`co.uk != example.co.uk`).

**Dependency:** Fix before #2 (NS Allowlist uses same two-label extraction)
and before #1 (Parent Aggregator needs correct domain parents).

**Fix:** Add `tldextract` (or `publicsuffix2`) to `requirements.txt` and
replace the slice with a PSL-aware registrable-domain extraction.

**Acceptance criteria:**
- [ ] `cdn.bbc.co.uk` → parent `bbc.co.uk`
- [ ] `mail.example.com.au` → parent `example.com.au`
- [ ] `sub.evil.com` → parent `evil.com` (no regression on simple TLDs)
- [ ] NS cycle guard updated and tested with multi-part TLD domain + self-referential NS

---

### B3 · X509 parent search always returns empty — duplicate CA anchors every run

`_find_or_create_parent("X509-Certificate", issuer_dn)` searches via
`_find_observable`, which always includes `{"key": "value", "values": [issuer_dn]}`
as a base filter. OpenCTI X509-Certificate observables have no `value` field;
their identity is a fingerprint hash. The `AND` filter always returns zero
results, so `create` is called on every enrichment run of every child cert.
Each run produces a new duplicate CA anchor observable.

**Fix:** Remove the `value` base filter for X509; search by `subject` alone:

```python
if obs_type == "X509-Certificate":
    results = self.helper.api.stix_cyber_observable.list(
        types=["X509-Certificate"],
        filters={"mode": "and",
                 "filters": [{"key": "subject", "values": [value]}],
                 "filterGroups": []},
        first=1,
    )
    existing = results[0] if results else None
```

**Acceptance criteria:**
- [ ] Second enrichment run of a cert issued by the same CA finds the existing
      anchor and does not call `create`
- [ ] Test: call `process_message` twice for the same leaf cert; `create` called
      exactly once across both runs

---

### B8 · `_has_malicious_context` crashes on non-integer indicator score

```python
int(ind.get("x_opencti_score") or 0)   # raises ValueError if value is "high"
```

External feeds (OTX, MISP) sometimes import scores as strings (`"high"`,
`"critical"`). One such indicator causes `process_message` to throw and the
observable is not processed at all. Already flagged by the `ponytail:` comment
in source.

**Fix:**

```python
try:
    s = int(ind.get("x_opencti_score") or 0)
except (TypeError, ValueError):
    s = 0
```

**Acceptance criteria:**
- [ ] Observable with an indicator carrying `x_opencti_score: "critical"` does
      not raise; connector continues normally
- [ ] Test: indicator with string score does not propagate exception

---

## P1 — Fix before next feature ship

---

### B4 · `_add_label` swallows failures and marks labels as applied regardless

**Batch with V3** — same bug in vectra connector; fix in one PR.

```python
def _add_label(self, obs_id, label_value, color):
    try:
        result = self.helper.api.label.create(...)
        self.helper.api.stix_cyber_observable.add_label(..., label_id=result["id"])
    except Exception as e:
        self.helper.log_debug(...)     # ← DEBUG, not WARNING

# caller — unconditional:
self._add_label(entity_id, cluster_lbl, COLOR_CLUSTER)
labels.add(cluster_lbl)       # ← runs even if _add_label failed
actions.append("clustered…")  # ← audit note claims success
```

If `label.create` returns a dict without `"id"` (transient 5xx),
`result["id"]` raises `KeyError`, caught silently at DEBUG. The connector
reports success in the audit note, but no label landed in OpenCTI. Next
trigger: no cluster label found, `already_clustered=False`, full pipeline
re-runs and may create duplicate relationships.

Same silent-failure pattern in `_ensure_relationship`.

**Fix:** Make `_add_label` return `bool`; log at `WARNING` on failure; make
callers conditional on the return value.

**Acceptance criteria:**
- [ ] `_add_label` returns `False` when `label.create` returns `{}` (missing `id`)
- [ ] Failure logged at `WARNING`
- [ ] `labels.add` and `actions.append` not reached on failure
- [ ] Test: mock `label.create` returning `{}`; verify `actions` is empty

---

### B7 · Already-clustered child with deleted parent is silently orphaned

When `already_clustered=True` and the parent was deleted, `_find_observable`
returns `None`. Code falls through silently. On every subsequent trigger: same
result. The child keeps its stale cluster label, cascade stays permanently
skipped — with zero indication anything is wrong.

**Fix:** Log at `WARNING` when `already_clustered=True` and parent lookup
returns `None`. Optionally add `TRUST_CLUSTER_ORPHAN_RECLUSTER=true` to clear
the stale label and re-run discovery.

**Acceptance criteria:**
- [ ] `WARNING` logged when already-clustered child's parent is not found
- [ ] Test: already-clustered child, `_find_observable` mocked to return `None`;
      warning is emitted, no crash, result is `"no actions"`

---

### B2 · `_entity_score` — explicit score=0 reads as 50 (falsy gotcha)

```python
return int(entity.get("x_opencti_score") or 50)
# 0 or 50 == 50
```

An observable scored `0` is treated as `50`. A score-0 child can miss a benign
cascade when `fp_cascade_score_max < 50`.

**Fix:**

```python
raw = entity.get("x_opencti_score")
return int(raw) if raw is not None else 50
```

**Acceptance criteria:**
- [ ] `x_opencti_score: 0` → scored as `0`, not `50`
- [ ] `x_opencti_score: null` / absent → scored as `50`
- [ ] Add test: score=0 entity below `fp_cascade_score_max` receives cascade

---

### #2 · NS Provider Allowlist — must ship before NS lookup is live

**Dependency: B1 must be fixed first** — the allowlist root-domain check uses
the same two-label extraction and would misfire on ccTLD NS providers.

Without an allowlist, enabling NS lookup in any real deployment immediately
creates millions of meaningless `trust-cluster:ns1.cloudflare.com` labels and
`related-to` relationships covering every Cloudflare-hosted domain.

**What to build:** `TRUST_CLUSTER_NS_ALLOWLIST` env var (comma-separated NS
root domains). When the resolved NS falls under an allowlisted root, skip NS
parent creation entirely — no observable, no relationship, no cluster label.

```
TRUST_CLUSTER_NS_ALLOWLIST=cloudflare.com,amazonaws.com,google.com,azure.com,\
  digitalocean.com,godaddy.com,namecheap.com,name.com,ovh.com
```

**Acceptance criteria:**
- [ ] Domains using Cloudflare NS produce no NS parent and no cluster label
- [ ] Domains using `ns1.vdsina.ru` (not in allowlist) produce NS parent as before
- [ ] Empty allowlist restores current behaviour
- [ ] Tests cover both allowlisted and non-allowlisted NS

---

### #1 · Parent Reputation Aggregator (new connector)

**Dependency: B1 and B3 should be fixed first** — wrong parents (B1) or
duplicate X509 anchors (B3) would produce incorrect aggregation results.

Without this, cascades never fire automatically. Feed connectors score individual
IPs and domains directly; no connector scores CIDR blocks, NS domains, or CA
certificates. Parents stay at `score=50` (UNKNOWN) indefinitely →
`_classify_parent` always returns `UNKNOWN` → propagation stops → the entire
cascade mechanism is dormant.

**What to build:** A new `connector-parent-promoter` INTERNAL_ENRICHMENT
connector. When triggered on a parent observable, it reads the score
distribution of its `related-to` children:

- ≥ `PROMOTER_MALICIOUS_CHILD_PCT`% (default 60%) of *scored* children
  CONFIRMED_MALICIOUS **and** ≥ `PROMOTER_MIN_CHILDREN` (default 3):
  → set parent score to `PROMOTER_MALICIOUS_SCORE` (default 80), add audit note
- ≥ `PROMOTER_BENIGN_CHILD_PCT`% (default 70%) of children carry `fp-candidate`,
  none CONFIRMED_MALICIOUS, ≥ `PROMOTER_MIN_CHILDREN`:
  → set parent score to 15, add `fp-candidate`, add audit note
- "Scored children" means score ≠ 50; unknown anchors excluded from denominator
- Promotion is idempotent: re-running on an already-promoted parent does nothing

**Acceptance criteria:**
- [ ] CIDR with 5+ AbuseIPDB-confirmed children (score ≥ 70) auto-promotes to
      score ≥ 75
- [ ] CIDR with 10+ fp-candidate children promotes to fp-candidate; new IPs
      from that CIDR inherit it via ioc-trust-cluster cascade
- [ ] Promotion note lists child evidence count and percentage
- [ ] Idempotent: second run on already-promoted parent changes nothing

---

## P2 — Operational correctness, not urgent

---

### #4 · malicious-cascade revocation path

`malicious-cascade` is never removed. A recycled IP or domain that gets a
clean re-assessment carries the label permanently.

OpenCTI's label model does not support programmatic removal. When a child
carries `malicious-cascade` and the parent's current verdict is UNKNOWN or
CONFIRMED_BENIGN, create a Note (once; deduplicated via abstract prefix):

> "Parent reassessed as UNKNOWN/BENIGN — analyst should review whether
> malicious-cascade label remains valid."

**Acceptance criteria:**
- [ ] Child with `malicious-cascade`, parent score later reset to 50 → Note
      created on next enrichment cycle
- [ ] Note not duplicated on re-processing
- [ ] No automatic removal of `malicious-cascade`

---

### #5 · fp-candidate + malicious-cascade conflict — explicit Note (partial)

The action string already includes a `REVIEW` flag when both labels coexist
(implemented), but only as text inside the audit note. An analyst triaging
observables in the feed view has no signal.

**What to add:** When `malicious-cascade` is being added to an observable that
already carries `fp-candidate`, create a dedicated Note with the conflict
explanation. Deduplicate via abstract prefix.

**Acceptance criteria:**
- [ ] `note.create` called with conflict body when both labels coexist
- [ ] Note not duplicated on re-processing
- [ ] Existing `REVIEW` action string retained (no regression)

---

### B5 · `confidence=75` hardcoded — `CONNECTOR_CONFIDENCE_LEVEL` ignored

`_ensure_relationship` and `_create_audit_note` both hardcode `confidence=75`.
`CONNECTOR_CONFIDENCE_LEVEL` is read into the pycti helper config but the
connector's own API calls never reference it.

**Fix:** `self.confidence = int(os.environ.get("CONNECTOR_CONFIDENCE_LEVEL", "75"))` in `__init__`; use `self.confidence` in both call sites.

**Acceptance criteria:**
- [ ] `CONNECTOR_CONFIDENCE_LEVEL=50` → relationships and notes use confidence=50
- [ ] Default remains 75

---

### B15 · ASN RDAP calls have no 429 backoff — owner permanently missed on rate-limit

IP RDAP uses IPWhois which handles 429 via `rate_limit_timeout`. The direct
ASN RDAP calls in `_get_asn_owner` use raw `urllib.request.urlopen` with no
retry. On a burst of new `Autonomous-System` observables, RIR rate limits hit;
`except Exception` logs at DEBUG and caches `None` — permanently wrong for
that session.

**Fix:** 2–3 retries with exponential backoff (1s, 2s, 4s) on HTTP 429 and 5xx.
Log at `WARNING` after max retries. Add `TRUST_CLUSTER_RDAP_RETRIES` (default 2).

**Acceptance criteria:**
- [ ] HTTP 429 triggers retry with backoff
- [ ] After max retries, cache `None` and log `WARNING`
- [ ] Test: first call returns 429, second returns valid data; owner is returned

---

## P3 — Housekeeping (low-friction; do alongside other work)

---

### B13 · Dockerfile runs as root

**Batch with V10** — identical change in both connectors; one PR.

```dockerfile
RUN adduser --disabled-password --no-create-home connector
USER connector
```

---

### B14 · `requirements.txt` has no upper-bound version pins

**Batch with V9** — identical change in both connectors; one PR.

`pycti` has had breaking API changes across minor versions.

```
pycti>=6.0.0,<7.0.0
ipwhois>=1.2.0,<2.0.0
dnspython>=2.0.0,<4.0.0
```

---

### B6 · `resp.read()` in `_get_asn_owner` has no size cap

Theoretical OOM via a misbehaving RDAP redirect. Cap at 1 MiB:
`resp.read(1_048_576)`. Valid RDAP autnum responses are under 100 KB.

---

### B9 · Session caches are unbounded and never TTL-refreshed

`_cidr_cache`, `_asn_desc_cache`, `_ns_cache`, `_ip_cache` grow for the
process lifetime. RDAP/DNS data can go stale. Replace with an `lru_cache`-style
wrapper: `maxsize=10_000` per cache, configurable TTL (default 24 h).

---

### B10 · IPv6 literal URL hosts skip parent extraction — and `.split(":")[0]` actively corrupts the address

`_extract_parent("Url")` does:

```python
host = (parsed.hostname or "").lower().split(":")[0]
```

For `http://[2001:db8::1]/path`, `parsed.hostname` returns `"2001:db8::1"`. The
`.split(":")[0]` then truncates it to `"2001"` — a single decimal number that
fails both the IPv4 regex and the domain validator. Parent extraction returns
`None` silently.

The `.split(":")[0]` was presumably intended to strip ports from `host:port`
strings, but `urlparse` already strips ports via `.hostname` (vs `.netloc`).
It is redundant for IPv4/domain URLs and actively wrong for IPv6.

**Fix:** Remove the `.split(":")[0]`, then add an IPv6 branch:

```python
host = (parsed.hostname or "").lower()   # urlparse already strips port
if not host:
    return None
try:
    ipaddress.IPv6Address(host)
    return self._extract_parent("IPv6-Addr", host)
except ValueError:
    pass
if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
    return self._extract_parent("IPv4-Addr", host)
return self._extract_parent("Domain-Name", host)
```

---

### B11 · `OBSERVABLE_PARENT_TYPES` and `LABEL_ONLY_PARENT_TYPES` are dead constants

Never referenced in logic. `StixFile` is in `OBSERVABLE_PARENT_TYPES` but has
no parent by design. Delete both or replace with an `assert`-guarded routing
check that stays correct.

---

### B16 · `fp_cascade_score_max` not validated against `malicious_score_min` — fp-candidate can reach malicious-scored observables

**Priority: P2 — silent data quality corruption on misconfiguration**

The CONFIRMED_BENIGN cascade guard:

```python
if (
    score <= self.fp_cascade_score_max
    and LABEL_FP_CANDIDATE      not in labels
    and LABEL_MALICIOUS_CASCADE not in labels
    and not has_malicious
):
```

When `TRUST_CLUSTER_FP_CASCADE_SCORE_MAX >= TRUST_CLUSTER_MALICIOUS_SCORE_MIN`
(e.g. `FP_CASCADE_SCORE_MAX=80`, `MALICIOUS_SCORE_MIN=70`), a child observable
scored 75 by a feed — but with no linked indicator and not yet cascaded from a
parent — passes all four conditions and receives `fp-candidate` from a
CONFIRMED_BENIGN parent. An observable flagged malicious by a feed is now
also labelled benign.

`not has_malicious` only blocks observables with linked indicators. Direct score
assignment without an indicator is the common case for many feed connectors.

The docstring already says "Must be kept below `TRUST_CLUSTER_MALICIOUS_SCORE_MIN`"
but there is no enforcement.

**Fix:** Add one condition to the cascade guard — no new config, no
init-time clamping:

```python
if (
    score <= self.fp_cascade_score_max
    and score < self.malicious_score_min   # ← add this
    and LABEL_FP_CANDIDATE      not in labels
    and LABEL_MALICIOUS_CASCADE not in labels
    and not has_malicious
):
```

This closes the gap regardless of how operators configure the thresholds.

**Acceptance criteria:**
- [ ] Child with score=75, `fp_cascade_score_max=80`, `malicious_score_min=70`
      does NOT receive `fp-candidate` from a CONFIRMED_BENIGN parent
- [ ] Child with score=50 still receives `fp-candidate` (no regression)
- [ ] Test: score=75 child, benign parent, `FP_CASCADE_SCORE_MAX=80` →
      no fp-candidate label applied

---

### B17 · Note creation failures silently swallowed at DEBUG

**Priority: P3 — same root cause as B4; consistency**

`_create_audit_note`, `_create_revocation_note`, and `_create_conflict_note`
all catch exceptions at `log_debug`:

```python
except Exception as e:
    self.helper.log_debug(f"[trust-cluster] audit note skipped: {e}")
```

B4 upgraded `_add_label` failure from DEBUG to WARNING because silent label
failures are invisible in production logs. Notes carry analyst-visible context;
failed notes are equally invisible at DEBUG (default log level is INFO).

**Fix:** Change all three to `log_warning`.

**Acceptance criteria:**
- [ ] All three `_create_*note` exception handlers log at WARNING
- [ ] No new tests required (log-level change only)

---

### B18 · Stats counter missing for revocation and conflict events

**Priority: P3 — operational monitoring blind spot**

The stats block matches action strings to counters:

```python
if "malicious-cascade" in action: self._stats["cascade_malicious"] += 1
if "fp-candidate inherited" in action: self._stats["cascade_fp"] += 1
...
```

The `cascade-revocation` action string (from the #4 fix) and the conflict note
trigger (from the #5 fix) match none of these patterns. Revocations are
recorded in `actions` (so `no_actions` does not increment) but are invisible in
the stats summary log line. In a deployment where many stale cascades are
being surfaced, there is no way to quantify this from logs.

**Fix:** Add two counters to `_reset_stats()` and the matching block:

```python
# in _reset_stats():
"cascade_revoked": 0, "cascade_conflict": 0,

# in the stats accumulation loop:
if "cascade-revocation"  in action: self._stats["cascade_revoked"]   += 1
if "fp/malicious conflict" in action: self._stats["cascade_conflict"] += 1
```

Note: conflict note creation does not append to `actions`, so `cascade_conflict`
cannot be counted from action strings. Use a dedicated `self._conflict_this_trigger`
bool flag set alongside `self._conflict_noted.add(entity_id)`.

**Acceptance criteria:**
- [ ] Stats summary line includes `cascade_revoked=N`
- [ ] `cascade_revoked` increments when a revocation advisory is issued

---

### B19 · `_find_observable` `extra_filters` parameter is dead code after B3

**Priority: P3 — dead API surface**

Before B3, `_find_or_create_parent("X509-Certificate")` called:

```python
existing = self._find_observable(
    "X509-Certificate", value,
    extra_filters=[("key": "subject", "values": [value])],
)
```

B3 replaced this with a direct `stix_cyber_observable.list` call. The three
remaining callers of `_find_observable` all pass only two arguments. The
`extra_filters` parameter is dead: it implements filtering capability that no
current caller uses.

**Fix:** Remove the `extra_filters` parameter and the `if extra_filters:` block
from `_find_observable`.

**Acceptance criteria:**
- [ ] `_find_observable` signature is `(self, obs_type: str, value: str) -> dict | None`
- [ ] All three call sites pass only two arguments (no change needed)
- [ ] Tests pass unchanged

---

## Deferred

---

### #3 · Parent promotion notification ← superseded by #1

Workaround for absent automatic parent scoring. Once #1 ships, this adds no
value. Only build if #1 is explicitly deferred long-term.

---

### #6 · Dynamic sinkhole IPs via OpenCTI labels ← simplify the design

The spec requires a background TTL-refresh thread — concurrency in a
single-process connector that's hard to test. Simpler: query OpenCTI for the
sinkhole label once at startup, merge with the static env var, rely on
container restarts for refresh. Revise spec before building.

---

### #7 · vectra-metadata-fp: mark CIDR parents ← wrong file

Change belongs in `connector-vectra-metadata-fp`. The ioc-trust-cluster side
already works once the parent carries the label.

---

### #9 · JA4/ASN verdict path ← YAGNI

No concrete feed producing scored JA4 fingerprints. Revisit when there is.

---

## Done

- **#8** Sighting source filter (`TRUST_CLUSTER_SIGHTING_SOURCE_FILTER`) ✅
- **#10** URL sinkhole check ✅
- **#11** Stats logging (`TRUST_CLUSTER_STATS_INTERVAL`) ✅

---

# vectra-metadata-fp

---

## P0 — Fix immediately (tests completely broken)

---

### V1 · Test suite never collects — `src/` not on `sys.path`

**Batch with V2** — fix both in one commit.

```python
from queries import (   # fails: no sys.path bootstrap
    ALL_QUERIES,
    ...
)
```

`queries.py` lives in `src/`, but there is no `sys.path` bootstrap in the test
file, no `conftest.py`, and no `pytest.ini`/`pyproject.toml` setting `pythonpath`.

ioc-trust-cluster solved this with:
```python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
```

**Fix:** Add `import os, sys` and the `sys.path.insert` line at the top of
`tests/test_connector.py`.

**Acceptance criteria:**
- [ ] `pytest tests/` from the connector directory collects without `PYTHONPATH` set

---

### V2 · `TestBreadthBucket` class-body import triggers pycti init at collection time

**Batch with V1** — fix both in one commit.

```python
class TestBreadthBucket:
    # Import inline to avoid triggering pycti init
    from connector import VectraMetadataFPConnector as _C   # ← NOT inline; runs at parse time
```

The comment is wrong. A class-body import runs at module parse time — the same
as a top-level import. It triggers `pycti` → FastAPI → crash:

```
TypeError: Router.__init__() got an unexpected keyword argument 'on_startup'
```

The import inside the test method on line 512 is already correct. Line 495 is
redundant and broken.

**Fix:** Delete line 495.

**Acceptance criteria:**
- [ ] `pytest tests/` collects all tests without a pycti/FastAPI error
- [ ] `TestBreadthBucket` parametrized cases all pass

---

## P1 — Fix before next feature ship

---

### V3 · `_add_label` swallows failures silently

**Batch with B4** — identical bug in ioc-trust-cluster; fix in one PR.

```python
def _add_label(self, obs_id: str, label: str, color: str) -> None:
    try:
        result = self.helper.api.label.create(value=label, color=color)
        self.helper.api.stix_cyber_observable.add_label(id=obs_id, label_id=result["id"])
    except Exception as exc:
        self.helper.log_debug(f"[vectra-fp] add_label skipped: {exc}")
```

If `label.create` returns a dict without `"id"` (transient 5xx), `result["id"]`
raises `KeyError`, caught at DEBUG. `_import_ioc` returns `True` and logs
`"imported"`. The cycle summary shows `imported=N` but N observables have no
labels in OpenCTI.

**Fix:** Return `bool`; log at `WARNING` on failure.

```python
def _add_label(self, obs_id: str, label: str, color: str) -> bool:
    try:
        result = self.helper.api.label.create(value=label, color=color)
        self.helper.api.stix_cyber_observable.add_label(id=obs_id, label_id=result["id"])
        return True
    except Exception as exc:
        self.helper.log_warning(f"[vectra-fp] add_label failed {label}: {exc}")
        return False
```

**Acceptance criteria:**
- [ ] `_add_label` returns `False` when `label.create` returns `{}` (no `id`)
- [ ] Failure logged at `WARNING`
- [ ] Test: mock `label.create` returning `{}`; verify return is `False`

---

### V4 · Discovery note fires on label failure; no dedup → accumulates every cycle

**Dependency: fix V3 first** — V4's fix uses V3's bool return value.

Two linked problems in `_import_ioc`:

**Problem A — note fires unconditionally:**
```python
if needs_fp_labels:
    self._add_label(obs_id, LABEL_FP_CANDIDATE,  COLOR_FP)   # may silently fail
    self._add_label(obs_id, LABEL_VECTRA_BENIGN, COLOR_VECTRA)
    self._add_discovery_note(obs_id, entry, query_label)     # fires regardless
```
When labels fail, the note is still attached, claiming `fp-candidate` was
applied when it wasn't.

**Problem B — no deduplication:**
If an observable lacks `fp-candidate` on the next cycle (API flake, or analyst
removed it), a new note is created. At the default 24 h interval, a week of
label failures → 7 identical notes.

**Fix:**
```python
if needs_fp_labels:
    ok_fp = self._add_label(obs_id, LABEL_FP_CANDIDATE,  COLOR_FP)
    ok_vec = self._add_label(obs_id, LABEL_VECTRA_BENIGN, COLOR_VECTRA)
    if ok_fp:
        self._add_discovery_note(obs_id, entry, query_label)
```

For deduplication, check for an existing note whose abstract starts with
`"Vectra FP: {entry.ioc_type}:{entry.value}"` before calling `note.create`.

**Acceptance criteria:**
- [ ] Note NOT created when `_add_label` returns `False` for fp-candidate
- [ ] Second cycle for the same observable does not create a duplicate note
- [ ] Test: `_add_label` succeeds once; re-processing same observable does not
      call `note.create` a second time

---

### V5 · `vectra-metadata-benign` permanently missing if the second `_add_label` fails

**Dependency: fix V3 first** — recovery path depends on V3's bool return.

`_import_ioc` uses `fp-candidate` as the sole proxy for "all fp labels applied":

```python
needs_fp_labels = LABEL_FP_CANDIDATE not in existing_labels
...
if needs_fp_labels:
    self._add_label(obs_id, LABEL_FP_CANDIDATE,  COLOR_FP)    # label A
    self._add_label(obs_id, LABEL_VECTRA_BENIGN, COLOR_VECTRA) # label B
```

If A succeeds and B silently fails: next cycle finds `fp-candidate` present →
`needs_fp_labels=False` → neither label re-attempted → `vectra-metadata-benign`
permanently absent with no log, no retry. Downstream queries filtering on
`vectra-metadata-benign` silently miss affected observables.

**Fix:** Track each label independently:
```python
needs_fp  = LABEL_FP_CANDIDATE  not in existing_labels
needs_vec = LABEL_VECTRA_BENIGN not in existing_labels
```

**Acceptance criteria:**
- [ ] Observable with `fp-candidate` but no `vectra-metadata-benign` has the
      second label re-applied on next cycle
- [ ] Test: existing observable with `fp-candidate` only; verify `_add_label`
      called for `vectra-metadata-benign` and not for `fp-candidate`

---

### V6 · `_native_execute`: poll `raise_for_status()` leaks `HTTPError` past `VectraMetadataError`

```python
try:
    pd: dict = poll.json()
except ValueError:
    poll.raise_for_status()   # ← raises requests.HTTPError on 5xx — not wrapped
    raise VectraMetadataError(...)
```

When the poll response is a 5xx with a non-JSON body (nginx error page),
`poll.json()` raises `ValueError`. `poll.raise_for_status()` then raises
`requests.HTTPError`, which is NOT caught by the `except requests.RequestException`
above (that wraps only the `requests.get()` call).

`HTTPError` propagates past `_process_query`'s `except VectraMetadataError`
and aborts the entire cycle — not just the one failing query.

**Fix:**
```python
except ValueError:
    try:
        poll.raise_for_status()
    except requests.RequestException as http_exc:
        raise VectraMetadataError(
            f"Poll HTTP {poll.status_code}: {http_exc}"
        ) from http_exc
    raise VectraMetadataError(
        f"Poll returned non-JSON HTTP {poll.status_code}"
    )
```

**Acceptance criteria:**
- [ ] 5xx non-JSON poll response raises `VectraMetadataError`, not `HTTPError`
- [ ] `_process_query` catches it; remaining queries continue
- [ ] Test: mock poll returning HTTP 503 with `"<html>"` body; verify
      `VectraMetadataError` raised and the next query in the cycle proceeds

---

## P2 — Operational correctness, not urgent

---

### V7 · Cycle exceptions logged without traceback

```python
except Exception as exc:
    self.helper.log_error(f"[vectra-fp] cycle error: {exc}")
```

Only `str(exc)` is logged. For `AttributeError` deep in a query handler,
the message is `"'NoneType' object has no attribute 'get'"` with no callsite.

**Fix:** `import traceback` (stdlib) and append `traceback.format_exc()`.

**Acceptance criteria:**
- [ ] Cycle exception log includes full traceback

---

### V8 · `_rows_from_native` misses `results: [...]` list branch

> **Risk:** `_rows_from_cantina` has `('results',)` in `_ROW_PATHS`, meaning
> the `results: [...]` shape has been observed in Cantina responses. If the
> native v3.4 API returns the same shape, every native-mode query silently
> returns zero rows. Upgrade to P0 if native mode is in active use.

```python
results = response.get('results')
if isinstance(results, dict):                    # handled
    data = results.get('data') or results.get('rows') or []
else:
    data = response.get('data') or []            # misses results=[...]
```

`_rows_from_cantina` handles `results: [...]` correctly via `_ROW_PATHS`.
The two methods are inconsistent.

**Fix:**
```python
results = response.get('results')
if isinstance(results, list):
    data = results
elif isinstance(results, dict):
    data = results.get('data') or results.get('rows') or []
else:
    data = response.get('data') or []
```

**Acceptance criteria:**
- [ ] `_rows_from_native({"results": [{"a": 1}]})` returns `[{"a": 1}]`
- [ ] Existing `test_rows_from_native_*` tests still pass
- [ ] New test added for the list branch

---

## P3 — Housekeeping

---

### V9 · `requirements.txt` has no upper-bound version pins

**Batch with B14** — same change in both connectors; one PR.

```
pycti>=6.0.0,<7.0.0
requests>=2.31.0,<3.0.0
```

---

### V10 · Dockerfile runs as root

**Batch with B13** — same change in both connectors; one PR.

```dockerfile
RUN adduser --disabled-password --no-create-home connector
USER connector
```

---

### V11 · OAuth2 token cache discarded on every cycle

`_build_client()` is called at the top of each loop iteration, creating a fresh
`VectraMetadataClient` instance. `_bearer_token` and `_token_expiry` start at
`None`/`0.0`, so a new OAuth2 token request fires every cycle.

For the default `interval_sec=86400`, one extra token per day is harmless. At
lower intervals (development, `interval_sec=300`), this hits OAuth2 rate limits.

The `ponytail:` comment in `_build_client` already acknowledges this. Filing
here so it is tracked.

`self._client` already exists on the instance (initialized to `None`). The fix
is straightforward: cache it, and reset to `None` only on `VectraMetadataError`
so a broken client is rebuilt automatically.

```python
def run(self) -> None:
    while True:
        if self._client is None:
            self._client = self._build_client()
        if self._client is not None:
            try:
                self._run_cycle(self._client)
            except KeyboardInterrupt:
                raise
            except VectraMetadataError:
                self._client = None   # force rebuild next cycle
                self.helper.log_error(...)
            except Exception as exc:
                self.helper.log_error(...)
        time.sleep(self.interval_sec)
```

**Acceptance criteria:**
- [ ] With `interval_sec=300`, token is fetched once and reused until near expiry
- [ ] `VectraMetadataError` during a cycle causes client rebuild on next cycle
- [ ] Non-auth cycle errors do not force a client rebuild

---

### V12 · `_add_discovery_note` failure logged at DEBUG, should be WARNING

```python
except Exception as exc:
    self.helper.log_debug(f"[vectra-fp] note create skipped: {exc}")
```

Failed note = analyst has no context for why `fp-candidate` was applied.
Invisible at the default INFO log level.

**Fix:** Change to `log_warning`.

---

### V13 · `if ok_fp and needs_fp:` — `needs_fp` is always True at that point

**Priority: P3 — misleading code, introduced in the V4 fix**

```python
if needs_fp:
    ok_fp = self._add_label(obs_id, LABEL_FP_CANDIDATE, COLOR_FP)
    if ok_fp and needs_fp:          # ← needs_fp is ALWAYS True here
        self._add_discovery_note(obs_id, entry, query_label)
```

The outer `if needs_fp:` block guarantees `needs_fp is True` for every line
inside it.  The inner `and needs_fp` is a dead condition — it never filters
anything.  A reader trying to understand why the note is gated will be confused
by the redundant term.

**Fix:** `if ok_fp:` only.

**Acceptance criteria:**
- [ ] Inner condition is `if ok_fp:` with no `and needs_fp`
- [ ] Behaviour unchanged (needs_fp was never False at that point)

---

### V14 · `_breadth_bucket` returns `"10-19"` for any breadth below 10

**Priority: P3 — wrong label when `host_threshold` is misconfigured**

```python
@staticmethod
def _breadth_bucket(n: int) -> str:
    if n >= 500: return "500+"
    ...
    if n >= 20:  return "20-49"
    return "10-19"   # ← catches n=0 through n=19
```

The function returns `"10-19"` for any value below 20 — including 0, 1, 5, 9.
Under the default `VECTRA_FP_HOST_BREADTH_THRESHOLD=10` this never triggers
because the SQL `HAVING COUNT(…) >= 10` filter means rows with breadth < 10
never reach Python.  But if someone sets `host_threshold=5`, rows with
breadth=5 get the label `breadth:10-19` — a lie that will confuse downstream
analysts.

**Fix:** Add an explicit floor bucket:

```python
    if n >= 20:  return "20-49"
    if n >= 10:  return "10-19"
    return f"1-9"   # below default threshold; only reachable if threshold lowered
```

Or validate `host_threshold >= 10` at init (see V17) to make this unreachable.

**Acceptance criteria:**
- [ ] `_breadth_bucket(5)` returns `"1-9"` (not `"10-19"`)
- [ ] `_breadth_bucket(10)` still returns `"10-19"` (no regression)

---

### V15 · `_find_observable` failure silently falls through to `create` — potential duplicates

**Priority: P3 — silent data quality risk; wrong log level**

```python
def _find_observable(self, obs_type: str, value: str) -> dict | None:
    try:
        ...
        return results[0] if results else None
    except Exception as exc:
        self.helper.log_debug(            # ← DEBUG, invisible in production
            f"[vectra-fp] observable lookup failed {obs_type}:{value}: {exc}"
        )
        return None
```

When `_find_observable` fails (transient 5xx, timeout), it returns `None`.
`_import_ioc` interprets `None` as "observable does not exist" and calls
`_create_observable`.  If the observable already exists in OpenCTI, this may
create a duplicate, depending on whether OpenCTI's `stix_cyber_observable.create`
is idempotent for the same (type, value) pair.

Even if OpenCTI deduplicates, the lookup failure is invisible at DEBUG —
consistent with B17/V12 pattern.

**Fix:** Change to `log_warning`.  Optionally propagate the exception so
`_import_ioc` can skip the observable rather than blindly creating.

**Acceptance criteria:**
- [ ] Lookup failure logs at WARNING

---

### V16 · `_build_client` exceptions are not caught in `run()` — unexpected error crashes the loop

**Priority: P3 — defensive gap; very unlikely to trigger in practice**

```python
while True:
    client = self._build_client()     # ← not wrapped in try-except
    if client is not None:
        try:
            self._run_cycle(client)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            self.helper.log_error(...)
    time.sleep(self.interval_sec)
```

`_build_client` catches `VectraMetadataError` and returns `None`.  Any other
exception (e.g., a bug in env-var processing, an unexpected `OSError`) propagates
out of the `while True` loop and crashes the connector entirely rather than
logging and retrying on the next cycle.

In practice `_build_client` only reads env vars and constructs a `VectraMetadataClient`,
which raises only `VectraMetadataError`.  Risk is very low but the loop should
be defensive.

**Fix:** Wrap `_build_client` call in the same try-except:

```python
try:
    client = self._build_client()
except Exception as exc:
    self.helper.log_error(f"[vectra-fp] client init error: {exc}\n{traceback.format_exc()}")
    client = None
```

**Acceptance criteria:**
- [ ] Unexpected exception in `_build_client` logs at ERROR and sleeps for next cycle
- [ ] Connector does not crash

---

### V17 · No lower-bound validation for breadth thresholds — threshold=0 marks everything fp-candidate

**Priority: P2 — foot-gun with real data quality impact**

`VECTRA_FP_HOST_BREADTH_THRESHOLD` and `VECTRA_FP_USER_BREADTH_THRESHOLD`
default to 10 and 20.  No validation prevents setting them to 0 or 1.

With `VECTRA_FP_HOST_BREADTH_THRESHOLD=0`:
- Each query builds SQL with `HAVING COUNT(DISTINCT id.orig_h) >= 0`
- This condition is always true — every row in the table within the lookback
  window is returned (up to `max_results`)
- Up to 500 × 6 = 3,000 IPs and domains per cycle receive `fp-candidate`,
  regardless of whether they are actually broadly observed
- This could cascade into ioc-trust-cluster, marking CIDR parents as benign
  and suppressing malicious-cascade on their children

The same applies to `VECTRA_FP_USER_BREADTH_THRESHOLD=0` for Q6 (M365 auth IPs).

**Fix:** Validate at init; clamp with a warning or raise:

```python
if self.host_threshold < 2:
    raise ValueError(
        f"VECTRA_FP_HOST_BREADTH_THRESHOLD={self.host_threshold} is dangerously low; "
        "minimum is 2.  Default is 10."
    )
```

Or a softer approach: warn and clamp to a safe minimum.

**Acceptance criteria:**
- [ ] `VECTRA_FP_HOST_BREADTH_THRESHOLD=0` raises `ValueError` (or logs `WARNING` and clamps)
- [ ] `VECTRA_FP_HOST_BREADTH_THRESHOLD=10` starts normally
- [ ] Test: threshold=0 raises or logs warning at init

---

### V18 · `malicious_guard` score check uses `or 50` falsy-zero pattern

**Priority: P3 — same anti-pattern as ioc-trust-cluster B2; behaviorally correct here**

```python
existing_score = int(existing.get("x_opencti_score") or 50)
if existing_score >= self.malicious_guard:
```

Score=0 is treated as 50 (`0 or 50 == 50`).  For the malicious guard
(`score >= 70`), treating 0 as 50 is **behaviourally correct** — a score-0
observable is unknown, not malicious, and should not be blocked.  But the
`or 50` pattern is the same anti-pattern fixed in ioc-trust-cluster B2,
and an explicit `None` check is clearer:

```python
raw = existing.get("x_opencti_score")
existing_score = int(raw) if raw is not None else 50
```

**Acceptance criteria:**
- [ ] Score=0 observable is still NOT blocked by the malicious guard
- [ ] Pattern consistent with ioc-trust-cluster `_entity_score` fix
