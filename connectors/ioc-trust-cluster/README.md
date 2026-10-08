# IOC Trust Cluster

Single OpenCTI connector for IOC trust edges and one-hop verdict fanout.

## Trust edges vs label-only grouping

Only relationship-backed parent observables (`IPv4-Addr`, `IPv6-Addr`, `Domain-Name`) participate in trust edges and verdict fanout. New structural trust is graph-only: child observables link to parent observables with connector-owned relationships, and CIDR anchors link to AS observables with `belongs-to`. X509 issuer-DN strings are not stable certificate identities, so the connector does not create synthetic CA parents. `Network-Traffic` JA4 profiles and direct `Autonomous-System` owner grouping remain label-only display aids; they never cascade verdicts.

Inherited verdict labels are namespaced (`trust-cluster:malicious-cascade`, `trust-cluster:fp-candidate`) so the connector can remove only state it owns. Generic `malicious-cascade` / `fp-candidate` labels from analysts, feeds, or old runs are never auto-removed.

DNS NS parent discovery is opt-in (`TRUST_CLUSTER_USE_NS_LOOKUP=true` or `TRUST_CLUSTER_USE_NS=true`). The default avoids cross-tenant NS-provider clusters.

## Deployment

`ioc-trust-cluster` is the deployment unit for trust-chain behavior. The old standalone `parent-promoter` worker was removed and is not wired separately.

## Optional OpenCTI contract smoke test

The fast unit tests stay mocked and Docker-free. To verify the real compose OpenCTI API accepts the trust-edge contract, run the opt-in smoke test against a running stack:

```sh
export OPENCTI_URL=http://localhost:8080
export OPENCTI_TOKEN=<admin/api token>
python3 connectors/ioc-trust-cluster/scripts/opencti_trust_edge_contract.py
```

Optional: set `CONNECTOR_ID` to the connector UUID and `TRUST_CONTRACT_KEEP=1` to keep the temporary observables for inspection. The script creates child→parent `related-to` edges, forces pycti pagination with `first=1,getAll=True`, adds/removes a connector-owned label, and calls `process_message` on the child.

## CIDR parent rule

For IP observables, CIDR trust parents are ASN/RDAP-derived:

1. Query IPWhois/RDAP for the announced/allocation CIDR (`network.cidr` / `asn_cidr`).
2. If multiple CIDRs are returned, use the most-specific valid CIDR that contains the IP.
3. Reuse the matching OpenCTI CIDR observable when it exists.
4. Create a CIDR parent only for that ASN/RDAP-derived CIDR.
5. If ASN/RDAP has no usable CIDR, do not invent a `/24` or `/48` trust parent by default.

OpenCTI stores/reuses CIDR observables; ASN/RDAP chooses the CIDR shape.
