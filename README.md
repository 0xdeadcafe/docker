# OpenCTI Docker deployment

## Documentation

You can find the detailed documentation about the Docker installation in the [OpenCTI documentation space](https://docs.opencti.io/latest/deployment/installation/#using-docker).

## VirusTotal and IPQS enrichment

VirusTotal and IPQS are paid, on-demand enrichment connectors. They stay running with `CONNECTOR_AUTO=false`; importing an observable does not call either provider. An authorized user must select a connector in the OpenCTI UI or request it through GraphQL. IPQS handles IPv4 addresses, domains, and URLs. VirusTotal handles files, artifacts, IPv4 addresses, and domains.

### One-time rollout

The old automatic configuration may have queued enrichment work. During a maintenance window, stop both connectors, purge only their listener queues, and recreate them:

```bash
set -a; source .env; set +a

docker compose stop connector-ipqs connector-virustotal
docker compose exec rabbitmq rabbitmqctl purge_queue "listen_${CONNECTOR_IPQS_ID}"
docker compose exec rabbitmq rabbitmqctl purge_queue "listen_${CONNECTOR_VIRUSTOTAL_ID}"
docker compose up -d --force-recreate connector-ipqs connector-virustotal

docker compose exec rabbitmq rabbitmqctl list_queues \
  name messages_ready messages_unacknowledged | \
  grep -E "listen_(${CONNECTOR_IPQS_ID}|${CONNECTOR_VIRUSTOTAL_ID})"
```

Both queues should remain at zero until a user requests enrichment.

### GraphQL request

Set `OBSERVABLE_ID` to the OpenCTI object ID and choose exactly one connector ID. Each request can consume provider quota.

```bash
set -a; source .env; set +a
export OBSERVABLE_ID='<observable-id>'
export ENRICHMENT_CONNECTOR_ID="$CONNECTOR_IPQS_ID" # or CONNECTOR_VIRUSTOTAL_ID

curl --fail-with-body "http://localhost:${OPENCTI_PORT:-8080}/graphql" \
  -H "Authorization: Bearer ${OPENCTI_ADMIN_TOKEN}" \
  -H 'Content-Type: application/json' \
  --data-binary @- <<JSON
{"query":"mutation Enrich(\$id: ID!, \$connectorId: ID!) { stixCoreObjectEdit(id: \$id) { askEnrichment(connectorId: \$connectorId) { id } } }","variables":{"id":"${OBSERVABLE_ID}","connectorId":"${ENRICHMENT_CONNECTOR_ID}"}}
JSON
```

A successful response contains the created work ID under `data.stixCoreObjectEdit.askEnrichment.id`.

## XTM One

This stack bundles [XTM One](https://filigran.io), Filigran's AI-powered assistant, alongside OpenCTI. The following services are started by default:

| Service | Description |
|---------|-------------|
| `xtm-one` | XTM One platform (web UI + API, exposed on `XTM_ONE_PORT`) |
| `xtm-one-worker` | XTM One background worker |
| `pgsql-xtm-one` | Dedicated PostgreSQL + `pgvector` instance for XTM One |

XTM One reuses the shared `redis` and `minio` services and connects to OpenCTI internally via `OPENCTI_API_URL`. OpenCTI registers itself with XTM One using `PLATFORM_REGISTRATION_TOKEN` — this shared secret **must be identical** across every platform connected to the same XTM One instance.

All XTM One configuration (admin credentials, dedicated Postgres credentials, S3 bucket, license, log settings) lives in the `XTM ONE` section of [.env.sample](.env.sample). Once the stack is healthy, XTM One is available on `http://localhost:${XTM_ONE_PORT}` (default `8090`).

## Community

### Status & bugs

Currently OpenCTI is under heavy development, if you wish to report bugs or ask for new features, you can directly use the [Github issues module](https://github.com/OpenCTI-Platform/opencti/issues).

### Discussion

If you need support or you wish to engage a discussion about the OpenCTI platform, feel free to join us on our [Slack channel](https://community.filigran.io). You can also send us an email to contact@opencti.io.

## About

OpenCTI is a product designed and developed by the company [Filigran](https://filigran.io).

<a href="https://filigran.io" alt="Filigran"><img src="https://github.com/OpenCTI-Platform/opencti/raw/master/.github/img/logo_filigran.png" width="300" /></a>