# ThreatFox

`docker-compose.yml` configures the unmodified public/community [`opencti/connector-threatfox:7.260910.0`](https://github.com/OpenCTI-Platform/connectors/tree/7.260910.0/external-import/threatfox). No local connector patch, proxy or alternate ingester.

## Configuration and operation

- Uses `https://threatfox.abuse.ch/export/csv/recent/`, not the full historical export. This endpoint worked without credentials during review; direct ThreatFox API queries require an abuse.ch Auth-Key. Provider fair-use/commercial restrictions still apply.
- Polls **daily**: this release actually uses integer `THREATFOX_INTERVAL` **in days**, despite its deprecated schema label. Its custom loop does not use `CONNECTOR_DURATION_PERIOD`.
- Imports all supported IOC types: IPv4 `ip:port`, domains, URLs, MD5, SHA-1 and SHA-256 files. URL/domain conversion does not infer associated host IPs.
- Creates indicators, exact `based-on` observable links, source author, malware context and optional external references. Native indicator confidence is source confidence; configured OpenCTI score is **50**, not that confidence. Existing labels/provider evidence can independently affect consumer verdicts.
- `THREATFOX_IMPORT_OFFLINE=true` is intentional: the upstream false branch discards records whose last-seen time is before the poll time, including recently observed records.
- Stable `CONNECTOR_THREATFOX_ID` matches `.env.sample` and the Compose fallback. Preserve it and its native watermark across restarts.
- Resource caps: 512 MiB and one CPU. The recent export and resource caps are **not hard row/age/download limits**. The connector builds one full-feed bundle in memory.

```sh
docker compose -p xtm -f docker-compose.yml config -q
docker compose -p xtm -f docker-compose.yml pull connector-threatfox
python3 tests/check_threatfox.py
# Start only after reviewing existing queue backlog and automatic enrichment policies:
docker compose -p xtm -f docker-compose.yml up -d --no-deps --no-build connector-threatfox
# Safe disable: preserves imported evidence and watermark; queued worker work remains.
docker compose -p xtm -f docker-compose.yml stop connector-threatfox
```

Started on **2026-10-15 at 19:55:07 UTC** after explicit operator approval, using only `up -d --no-deps --no-build --pull never connector-threatfox`. The first collection queued **30,448 STIX objects** (not unique IOCs) and finished sending at 19:56:24 UTC; worker backfill continues asynchronously. Native API verification observed 156 source-attributed indicators, with sampled confidence 100 and score 50, an active connector, zero connector errors/restarts and no OOM. Existing `xtm` container IDs were unchanged.

Imported direct IPs are eligible for the existing automatic AbuseIPDB host filter and can consume quota; VT/IPQS remain on demand. No manual provider enrichment was requested for validation. Do not purge shared queues or disable unrelated connectors to validate this feed.

## Freshness and upstream limitations

Operational owner: the operator of this repository's `xtm` Compose deployment. Target a completed collection at least every 24 hours after startup, then monitor **worker completion and source evidence**, not merely connector process health. This is a target, not an implemented alert/SLO guarantee; queue monitoring is tracked by `open-cti-h29`.

The provider's definition of "recent" is not a first-seen age bound. The 2026-10-15 snapshot contained 8,811 records, including 705 SHA-256 hashes and records first seen in 2021 but recently seen again. All 3,764 records first seen more than seven days earlier had recent last-seen times. Do not rely on the upstream README's seven-day wording as a strict age filter.

The stock converter parses but **does not persist first/last-seen timestamps or the ThreatFox record ID/link**; an optional source reference is not necessarily a ThreatFox record link. Its first-seen watermark skips later updates to older records. SHA-1 indicators use `hashes.SHA1` rather than the observable's `SHA-1` key; SHA-256 conversion is checked explicitly. IPv6 `ip:port` conversion is not supported. There is no hard download timeout/size/row cap or per-row failure isolation. The importer catches errors and can still log "success"/advance state, so inspect errors and actual ingestion before accepting a run.

These are documented upstream limitations, not patched or claimed fixed. Source-attributed indicators are verified live, but structured consumer ThreatFox verdict/freshness normalization and the full positive/benign hash comparison without VT remain unverified. ThreatFox only covers hashes it lists; it is not complete MalwareBazaar coverage. `open-cti-bgt` remains blocked on the remaining comparison and disposition of the original metadata/freshness requirements; the stock connector is deployed, not claimed to meet all original acceptance criteria.
