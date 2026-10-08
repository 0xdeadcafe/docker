# Vectra Metadata FP Discovery

Mines Vectra Metadata for high-breadth observables that are common across the fleet and enriches them in OpenCTI for whitelist/cache-assisted triage.

It runs six metadata queries for broad IP, DNS, TLS SNI, HTTP host, benign beacon, and M365 shared-auth IP signals.

## Default safety model

- Missing observables are created by default for whitelist/cache mining.
  - Disable with `VECTRA_FP_CREATE_MISSING=false` for enrichment-only mode.
- Raw broad-reach IPs from Q1 are weak popularity context.
  - Label: `vectra-metadata-popular-ip`
  - They do **not** get `vectra-metadata-benign` by default.
  - Opt in with `VECTRA_FP_STRONG_RAW_IPS=true` if shared-infra risk is acceptable.
- Domain signals and M365 shared-auth IPs get `vectra-metadata-benign`.
- Cascade-capable `fp-candidate` is off by default.
  - Opt in with `VECTRA_FP_APPLY_FP_CANDIDATE=true`.

## Required OpenCTI env

```env
OPENCTI_URL=http://opencti:8080
OPENCTI_TOKEN=...
CONNECTOR_ID=...
CONNECTOR_NAME=Vectra Metadata FP Discovery
CONNECTOR_AUTO=true
CONNECTOR_LOG_LEVEL=info
```

## Vectra metadata auth

Use either Cantina/Darkstar:

```env
CANTINA_TOKEN=...
VECTRA_METADATA_CUSTOMER=...
# optional
CANTINA_USER=...
CANTINA_DARKSTAR_URL=https://cantina.vectra.ai/api/darkstar/lambda
```

Or native Vectra NDR metadata API:

```env
VECTRA_NDR_URL=https://your-ndr/api/v3.4
VECTRA_NDR_CLIENT_ID=...
VECTRA_NDR_CLIENT_SECRET=...
# or instead of client credentials
VECTRA_NDR_TOKEN=...
```

If neither auth mode is configured, the connector starts, logs a warning, sleeps, and retries next cycle.

## Tuning

```env
VECTRA_FP_LOOKBACK_DAYS=30
VECTRA_FP_HOST_BREADTH_THRESHOLD=10
VECTRA_FP_USER_BREADTH_THRESHOLD=20
VECTRA_FP_MAX_RESULTS=500
VECTRA_FP_INTERVAL_SEC=86400
VECTRA_FP_QUERY_TIMEOUT_SEC=180
VECTRA_FP_MALICIOUS_GUARD_SCORE=70
VECTRA_FP_SCORE=15
VECTRA_FP_CONFIDENCE=60
```

Thresholds below `2` are rejected at startup.

## Local tests

```sh
cd connectors/vectra-metadata-fp
pytest -q
```
