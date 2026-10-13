# IOC Trust Cluster

Single OpenCTI connector for IOC trust edges and one-hop verdict fanout.

## Trust edges vs label-only grouping

Only relationship-backed parent observables (`IPv4-Addr`, `IPv6-Addr`, `Domain-Name`) participate in trust edges and verdict fanout. Structural trust is graph-only: child observables link to parent observables with connector-owned `related-to` relationships because OpenCTI rejects `belongs-to` for SCO parentage pairs such as IP→CIDR, URL→host, and subdomain→domain. CIDR anchors link to AS observables with `belongs-to`, where OpenCTI allows ownership semantics. See `docs/decisions/trust-parent-relationship-semantics.md`. X509 issuer-DN strings are not stable certificate identities, so the connector does not create synthetic CA parents. `Network-Traffic` JA4 profiles and direct `Autonomous-System` owner grouping remain label-only display aids; they never cascade verdicts.

Inherited verdict labels are namespaced (`trust-cluster:malicious-cascade`, `trust-cluster:fp-candidate`) so the connector can remove only state it owns. Generic `malicious-cascade` / `fp-candidate` labels from analysts, feeds, or old runs are never auto-removed.

DNS NS parent discovery is opt-in (`TRUST_CLUSTER_USE_NS_LOOKUP=true` or `TRUST_CLUSTER_USE_NS=true`). The default avoids cross-tenant NS-provider clusters.

## Deployment

`ioc-trust-cluster` is the deployment unit for trust-chain behavior. The old standalone `parent-promoter` worker was removed and is not wired separately.

The feed label `sinkhole` and the connector label `sinkholed` are compatibility aliases. Either is a direct malicious assessment regardless of score and drives the same one-hop verdict fanout. The connector creates only the canonical `sinkholed` spelling and does not add it when either alias is already present.

## Trust-state activation workflow

Direct assessments are inputs:

- An analyst or trusted feed applies `fp-confirmed` to a parent that is known benign.
- A feed may apply `sinkhole`; the connector applies `sinkholed` when DNS resolves to a configured sinkhole IP.
- A parent score at or above `TRUST_CLUSTER_MALICIOUS_SCORE_MIN` (default `70`) is a direct malicious assessment unless the parent itself carries an inherited cascade label.

The connector alone owns the inherited outputs `trust-cluster:fp-candidate` and `trust-cluster:malicious-cascade`. Analysts and feeds should not apply those labels directly. Generic unnamespaced `fp-candidate` and `malicious-cascade` labels are legacy/manual state and are not automatically removed.

Propagation requires a connector-owned child→parent `related-to` relationship. Only real `IPv4-Addr`, `IPv6-Addr`, and `Domain-Name` parents participate; label-only ASN/JA4 groups do not. A benign parent must carry `fp-confirmed` and remain below the malicious threshold. Its child must be at or below `TRUST_CLUSTER_FP_CASCADE_SCORE_MAX` (default `50`), below the malicious threshold, and have no malicious cascade label or linked high-score Indicator. A directly malicious or sinkhole parent applies inherited malicious state to each direct child. Unknown and inherited-only parents do not fan out, and propagation is one hop.

Zero assignments are therefore valid when no parent has a direct assessment, no eligible child relationship exists, or the connector has not received a parent/child update event. Synthetic UNKNOWN parent anchors are created with score `0`; OpenCTI's score `50` is not used because downstream clients commonly treat it as suspicious.

Legacy synthetic anchors can be migrated safely after reviewing a dry run:

```sh
python3 connectors/ioc-trust-cluster/scripts/migrate_unknown_anchor_scores.py dry-run
python3 connectors/ioc-trust-cluster/scripts/migrate_unknown_anchor_scores.py apply
python3 connectors/ioc-trust-cluster/scripts/migrate_unknown_anchor_scores.py verify
```

The migration requires `OPENCTI_URL` and `OPENCTI_TOKEN`. It changes only score-50 observables with the exact generated anchor description and no labels, indicators, external references, or creator; every candidate is re-read immediately before update.

## Optional OpenCTI contract smoke test

The fast unit tests stay mocked and Docker-free. To verify the real compose OpenCTI API accepts the trust-edge contract, run the opt-in smoke test against a running stack:

```sh
export OPENCTI_URL=http://localhost:8080
export OPENCTI_TOKEN=<admin/api token>
python3 connectors/ioc-trust-cluster/scripts/opencti_trust_edge_contract.py
```

Optional: set `CONNECTOR_ID` to the connector UUID and `TRUST_CONTRACT_KEEP=1` to keep the temporary observables for inspection. Without that flag, the script uses randomized temporary Observables and removes them and their relationships afterward; it does not alter existing IOC verdicts. It verifies both an `fp-confirmed` parent→eligible-child transition and a directly malicious parent→child transition, forces pycti pagination with `first=1,getAll=True`, and checks connector-owned label add/remove behavior.

## CIDR parent rule

For IP observables, CIDR trust parents are ASN/RDAP-derived:

1. Load connector-owned CIDR→ASN `belongs-to` edges into a bounded in-memory prefix index when the connector starts.
2. Reuse the most-specific indexed CIDR containing a new IP, without another RDAP request.
3. On an index miss, query IPWhois/RDAP for the announced/allocation CIDR (`network.cidr` / `asn_cidr`).
4. If multiple CIDRs are returned, use the most-specific valid CIDR that contains the IP.
5. Reuse the matching OpenCTI CIDR observable when it exists, or create it when absent.
6. Link RDAP-derived CIDRs to their ASN and add them to the session index.
7. If ASN/RDAP has no usable CIDR, do not invent a `/24` or `/48` trust parent by default.

Only CIDRs with this connector's CIDR→ASN relationship are indexed; arbitrary feed-created CIDRs are ignored. OpenCTI stores/reuses CIDR observables, while the trusted graph edge or RDAP chooses the CIDR shape.

## Legacy structural label cleanup

Structural `trust-cluster:<parent>` labels are obsolete now that connector-owned relationships are authoritative. Audit them before cleanup:

```sh
python3 connectors/ioc-trust-cluster/scripts/cleanup_structural_labels.py dry-run
```

`dry-run` reads the authoritative `object-label` relationship index, covering every OpenCTI object type. `apply` removes an association only when the exact connector-owned structural relationship exists, then rechecks OpenCTI immediately before deleting each unreferenced definition. Inherited state labels, ASN-owner labels, TLS-profile labels, and any referenced/manual labels are preserved. Use `--limit N` for a bounded apply and `verify` afterward; `apply` requires `OPENCTI_URL` and `OPENCTI_TOKEN`. For strict protection against a new label assignment in the final check/delete window, pause label-writing connectors and analyst changes during `apply`.
