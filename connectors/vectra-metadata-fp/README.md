# Vectra Metadata endpoint commonness

Builds GreyNoise-like endpoint-behavior context in OpenCTI. It measures whether
existing observables are common in Vectra Metadata and discovers strongly
recurring HTTP domains and successful-M365 source IPs.

Common means **widespread and low-discrimination for IOC hunting**, not benign.
The connector never creates Indicators, changes scores, applies `fp-candidate`
or `fp-confirmed`, or suppresses detections. Malicious and common evidence can
coexist.

The deployment directory retains its historical `vectra-metadata-fp` name to
avoid an unnecessary container migration.

## Safety model

The default is read-only shadow mode:

```env
VECTRA_COMMONNESS_WRITE=false
VECTRA_COMMONNESS_SOURCE_ID=tenant-01
```

`VECTRA_COMMONNESS_SOURCE_ID` must be an opaque ID, never a customer name. Set
`VECTRA_COMMONNESS_WRITE=true` only after reviewing a shadow cycle.

Neutral connector-owned labels:

- `vectra-metadata:common-domain`
- `vectra-metadata:common-ip`
- `vectra-metadata:shared-auth-ip`
- `vectra-metadata:commonness-conflict`
- `vectra-metadata:herd-common` (review reducer only; requires at least two fresh sources)

One deterministic aggregate Note is upserted per source/tenant and Observable.
It contains only signal/window counts, breadth, first/last seen, recurrence, and
query version. No raw users, internal hosts, or events leave Metadata.

## Query contract

- Existing OpenCTI observables: exact DNS, SNI, HTTP, successful-M365 and
  destination-session queries in batches of at most 50.
- Discovery: HTTP Host breadth >=10 and successful-M365 user breadth >=3 only.
- Qualification: threshold met in at least two of three fixed disjoint windows.
- Discovery output: at most 500 aggregate rows per query.
- Creation: at most 100 missing Observables per run; no score is assigned.
- Broad DNS/SNI/iSession, beacon, JA3, X509, URL, email, hash and port discovery
  are disabled.

See [`../../docs/decisions/vectra-endpoint-commonness-validation.md`](../../docs/decisions/vectra-endpoint-commonness-validation.md),
the [`cross-source review contract`](../../docs/decisions/vectra-commonness-review-contract.md),
and the [`shadow pilot`](../../docs/decisions/vectra-commonness-review-pilot.md).

## Configuration

```env
OPENCTI_URL=http://opencti:8080
OPENCTI_TOKEN=...
CONNECTOR_ID=...
CONNECTOR_NAME=Vectra Metadata Commonness

VECTRA_COMMONNESS_SOURCE_ID=tenant-01
VECTRA_COMMONNESS_WRITE=false
VECTRA_COMMONNESS_LOOKBACK_DAYS=30
VECTRA_COMMONNESS_BATCH_SIZE=50
VECTRA_COMMONNESS_PAGE_SIZE=100
VECTRA_COMMONNESS_DISCOVERY_LIMIT=500
VECTRA_COMMONNESS_CREATION_LIMIT=100
VECTRA_COMMONNESS_INTERVAL_SEC=86400
VECTRA_COMMONNESS_QUERY_TIMEOUT_SEC=180

# Separate cross-source review gate
VECTRA_COMMONNESS_REVIEW_WRITE=false
VECTRA_COMMONNESS_REVIEW_PAGE_SIZE=100
VECTRA_COMMONNESS_REVIEW_MAX_PAGES=10
VECTRA_COMMONNESS_REVIEW_MAX_AGE_DAYS=2
```

Use either native Vectra OAuth:

```env
VECTRA_NDR_URL=https://your-ndr/api/v3.4
VECTRA_NDR_CLIENT_ID=...
VECTRA_NDR_CLIENT_SECRET=...
# or VECTRA_NDR_TOKEN=...
```

or Cantina/Darkstar:

```env
CANTINA_TOKEN=...
VECTRA_METADATA_CUSTOMER=...
```

## Rollout and rollback

1. Deploy with `VECTRA_COMMONNESS_WRITE=false`.
2. Review the aggregate cycle log: queries, zero/error/partial counts,
   candidates, qualified/reused/missing/conflicts, projected writes and runtime.
3. Audit legacy state:

   ```bash
   docker compose run --rm --no-deps --entrypoint python \
     connector-vectra-metadata-fp \
     /opt/opencti-connector-vectra-metadata-fp/scripts/audit_legacy_state.py dry-run
   ```

4. Set `VECTRA_COMMONNESS_WRITE=true` and recreate only this connector.
5. To stop writes, restore `false` and recreate it. Existing threat evidence is
   untouched. Run the migration script in `apply` mode only after reviewing its
   dry-run counts.
6. Run the bounded cross-source reducer in shadow mode:

   ```bash
   docker compose run --rm --no-deps --entrypoint python \
     connector-vectra-metadata-fp review.py shadow
   ```

   It counts each fresh opaque source once. A source-local candidate keeps its
   y5g explanation; two or more sources project `vectra-metadata:herd-common`
   and one aggregate review Note. Applying either requires the separate
   `VECTRA_COMMONNESS_REVIEW_WRITE=true` gate and `review.py apply`.
7. To roll back reducer-owned state, stop review writes, explicitly enable the
   gate for the command, and run `review.py purge`. Purge removes only the herd
   label and aggregate review Notes.
8. To remove one source's evidence, preview and then optionally apply:

   ```bash
   docker compose run --rm --no-deps --entrypoint python \
     connector-vectra-metadata-fp \
     /opt/opencti-connector-vectra-metadata-fp/scripts/delete_source_evidence.py tenant-01 dry-run
   ```

The migration removes only legacy `vectra-metadata-benign`,
`vectra-metadata-popular-ip`, or `vectra-discovered-common` labels attached to a
matching generated Note. It never removes generic `fp-candidate`, changes scores,
or deletes Observables.

Paid VirusTotal/IPQS enrichment is already on-demand, so commonness does not
block explicit analyst enrichment or threat-feed ingestion. A future routing
policy may consume the neutral labels only if separately implemented and enabled.

## Tests

```bash
cd connectors/vectra-metadata-fp
pytest -q
```
