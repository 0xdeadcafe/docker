# URLhaus

Uses the unmodified upstream community connector [`opencti/connector-urlhaus:7.260910.0`](https://github.com/OpenCTI-Platform/connectors/tree/7.260910.0/external-import/urlhaus) in `docker-compose.yml`.

- Recent 30-day CSV feed, every three hours; first start imports the recent backlog.
- Includes online and offline URLs at upstream score 80, URL indicators, tags and source links. Upstream TLP:WHITE is normalized to TLP:CLEAR by this platform. Offline is historical evidence, not proof of current activity.
- Optional tag-to-threat graph expansion is disabled. The connector itself does not import associated IP/domain hosts.
- Stable `CONNECTOR_URLHAUS_ID`; default matches `.env.sample`. Keep it across restarts to retain the native watermark.
- Docker memory/CPU limits: 512 MiB / one CPU. These are resource bounds, **not a row limit or freshness guarantee**. Native scheduler queue backpressure remains at its upstream default.

```sh
docker compose -p xtm -f docker-compose.yml config -q
docker compose -p xtm -f docker-compose.yml pull connector-urlhaus
docker compose -p xtm -f docker-compose.yml up -d --no-deps connector-urlhaus
# Disable ingestion without deleting existing evidence:
docker compose -p xtm -f docker-compose.yml stop connector-urlhaus
```

This is an `EXTERNAL_IMPORT`, not on-demand `askEnrichment`. Existing automatic connector policies still apply to imported objects; VirusTotal/IPQS remain on demand. No malware URLs or payloads are fetched by this connector—only the URLhaus feed.

## Accepted upstream limitations

Per the operator's request to use the public connector as-is, there are no local patches, feed proxy, custom ingester or consumer changes. The connector omits `last_online`, uses a date-added watermark that skips later status changes to older entries, and has no hard HTTP timeout/download/per-run row limit. Status/threat are stored as descriptions; this does not add structured URLhaus verdict/freshness normalization to the IOC consumer. Do not infer current activity or host maliciousness from a historical URL score.

The configured legacy CSV endpoint was accessible without credentials during review. Provider documentation now describes Auth-Key exports and fair-use/commercial restrictions; check eligibility for your deployment. Do not put a credential-bearing export URL into `URLHAUS_CSV_URL`: upstream logs that URL. If the public endpoint becomes unavailable, stop this connector and review supported upstream access rather than adding a secret to logs or silently buying access.

Stopping the service preserves its OpenCTI state and imported evidence; it does not recall bundles already queued for workers. Do not purge shared queues, delete imported objects or reset its watermark as a routine rollback.
