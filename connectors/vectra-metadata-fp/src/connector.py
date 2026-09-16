#!/usr/bin/env python3
"""
Vectra Metadata False-Positive Discovery — OpenCTI External Import Connector

Periodically executes 6 Vectra Metadata SQL queries that identify network
endpoints (IPs, domains) observed across a BROAD SET of internal hosts.
High host-breadth is a strong signal for benign infrastructure (CDN, SaaS,
OS telemetry, corporate proxies) and a direct analogue of the ubiquity
heuristic in the ioc-trust-cluster connector.

Each discovered observable (new or existing) is labelled in OpenCTI with:
  - Labels: fp-candidate, vectra-metadata-benign, breadth:<tier>
    Applied to newly created observables AND to existing observables that are
    missing the fp-candidate label, ensuring pre-existing high-breadth IOCs
    are correctly marked and flow into ioc-trust-cluster's cascade pipeline.
  - x_opencti_score = VECTRA_FP_SCORE (default 15) is set only when the
    connector creates a new observable; existing scores are never overwritten.
  - A Note with the metadata context is attached whenever fp-candidate is
    newly applied — whether the observable is brand-new or pre-existing.
  - breadth:<tier> is refreshed when the observable moves to a higher tier;
    previous tier labels are retained for audit history.

Safety guard: if an observable already exists with score ≥
VECTRA_FP_MALICIOUS_GUARD_SCORE (default 70) — i.e. a feed connector has
independently confirmed it as malicious — the connector does NOT apply
fp-candidate to it.

Integration with ioc-trust-cluster: once an observable carries fp-candidate,
ioc-trust-cluster's CONFIRMED_BENIGN cascade propagates the verdict down to
all child observables in the same CIDR block / domain root / CA chain.

The 6 queries (all Trino SQL against Vectra Metadata):

  Q1 broad_reach_ips       External IPs contacted by ≥N distinct hosts     (network.isession)
  Q2 broad_reach_dns       Domains resolved by ≥N distinct hosts            (network.dns)
  Q3 broad_reach_tls_sni   TLS SNI names seen from ≥N distinct hosts        (network.ssl)
  Q4 broad_reach_http      HTTP hosts seen by ≥N hosts, majority success     (network.http)
  Q5 benign_beacons        Vectra-ML non-C2 beacon destinations, ≥N hosts   (network.beacon)
  Q6 shared_auth_ips       IPs used for M365 auth by ≥N distinct users      (m365.signins)
"""

from __future__ import annotations

import os
import time
import traceback
from datetime import datetime, timezone

from pycti import OpenCTIConnectorHelper

from metadata_client import VectraMetadataClient, VectraMetadataError
from queries import ALL_QUERIES, IOCEntry, QueryDefinition


# ─── constants ────────────────────────────────────────────────────────────────

LABEL_FP_CANDIDATE = "fp-candidate"
LABEL_VECTRA_BENIGN = "vectra-metadata-benign"

COLOR_FP = "#2e7d32"         # green  — benign / fp candidate
COLOR_VECTRA = "#0d47a1"     # dark blue — vectra-sourced
COLOR_BREADTH = "#455a64"    # blue-grey — breadth tier

# Context keys already captured in the note header — skip in the detail table.
_CTX_SKIP = frozenset({'resp_ip', 'ip_address', 'domain', 'server_name', 'host', 'resp_domains'})


# ─── connector ────────────────────────────────────────────────────────────────

class VectraMetadataFPConnector:

    def __init__(self) -> None:
        _conf = int(os.environ.get("VECTRA_FP_CONFIDENCE", "60"))
        config = {
            "opencti": {
                "url":   os.environ.get("OPENCTI_URL",   "http://opencti:8080"),
                "token": os.environ.get("OPENCTI_TOKEN"),
            },
            "connector": {
                "id":               os.environ.get("CONNECTOR_ID"),
                "type":             "EXTERNAL_IMPORT",
                "name":             os.environ.get(
                                        "CONNECTOR_NAME",
                                        "Vectra Metadata FP Discovery"
                                    ),
                "scope":            "IPv4-Addr,Domain-Name",
                "auto":             os.environ.get(
                                        "CONNECTOR_AUTO", "true"
                                    ).lower() == "true",
                "confidence_level": _conf,
                "log_level":        os.environ.get(
                                        "CONNECTOR_LOG_LEVEL", "info"
                                    ),
                "only_contextual":  False,
            },
        }
        self.helper = OpenCTIConnectorHelper(config)

        # ── query parameters ───────────────────────────────────────────────
        self.lookback_days: int    = int(os.environ.get("VECTRA_FP_LOOKBACK_DAYS",          "30"))
        self.host_threshold: int   = int(os.environ.get("VECTRA_FP_HOST_BREADTH_THRESHOLD", "10"))
        self.user_threshold: int   = int(os.environ.get("VECTRA_FP_USER_BREADTH_THRESHOLD", "20"))
        if self.host_threshold < 2:
            raise ValueError(
                f"VECTRA_FP_HOST_BREADTH_THRESHOLD={self.host_threshold} is dangerously low "
                "(minimum 2, default 10). A threshold of 0 or 1 matches nearly every "
                "external endpoint and would mark all of them fp-candidate."
            )
        if self.user_threshold < 2:
            raise ValueError(
                f"VECTRA_FP_USER_BREADTH_THRESHOLD={self.user_threshold} is dangerously low "
                "(minimum 2, default 20)."
            )
        self.max_results: int      = int(os.environ.get("VECTRA_FP_MAX_RESULTS",            "500"))
        self.interval_sec: int     = int(os.environ.get("VECTRA_FP_INTERVAL_SEC",           "86400"))
        # Seconds to sleep between consecutive queries within a cycle.
        # Avoids hammering the Vectra metadata cluster when all 6 queries fire
        # back-to-back; also staggers load if the cluster is already under pressure.
        self.inter_query_delay_sec: int = int(os.environ.get(
                                        "VECTRA_FP_INTER_QUERY_DELAY_SEC", "2"
                                    ))

        # ── import scoring / safety ────────────────────────────────────────
        self.fp_score: int          = int(os.environ.get("VECTRA_FP_SCORE",                "15"))
        self.confidence: int        = _conf
        self.malicious_guard: int   = int(os.environ.get("VECTRA_FP_MALICIOUS_GUARD_SCORE","70"))

        # ── Vectra metadata client (lazy — created in run()) ───────────────
        self._client: VectraMetadataClient | None = None

        # per-cycle dedup: avoid importing the same (type, value) twice
        self._seen_this_cycle: set[tuple[str, str]] = set()

    # ── metadata client factory ────────────────────────────────────────────────

    def _build_client(self) -> VectraMetadataClient | None:
        """Try to construct a VectraMetadataClient from env vars.

        Returns None (and logs) if neither Cantina nor native config is present.
        This lets the connector start without crashing even when Vectra is not
        yet configured — it will sleep and retry each interval.
        """
        # OAuth2 token is cached on the client instance; reusing self._client
        # across cycles avoids a token fetch on every run.
        cantina_token    = os.environ.get("CANTINA_TOKEN", "").strip()
        cantina_customer = os.environ.get("VECTRA_METADATA_CUSTOMER", "").strip()
        ndr_url          = os.environ.get("VECTRA_NDR_URL", "").strip()
        client_id        = os.environ.get("VECTRA_NDR_CLIENT_ID", "").strip()
        client_secret    = os.environ.get("VECTRA_NDR_CLIENT_SECRET", "").strip()
        ndr_token        = os.environ.get("VECTRA_NDR_TOKEN", "").strip()

        cantina_ok = bool(cantina_token and cantina_customer)
        native_ok  = bool(ndr_url and (ndr_token or (client_id and client_secret)))

        if not cantina_ok and not native_ok:
            self.helper.log_warning(
                "[vectra-fp] Vectra metadata not configured — skipping this cycle.\n"
                "  Cantina: set CANTINA_TOKEN + VECTRA_METADATA_CUSTOMER\n"
                "  Native:  set VECTRA_NDR_URL + VECTRA_NDR_CLIENT_ID + "
                "VECTRA_NDR_CLIENT_SECRET (or VECTRA_NDR_TOKEN)"
            )
            return None

        try:
            client = VectraMetadataClient(
                cantina_token    = cantina_token,
                cantina_user     = os.environ.get("CANTINA_USER", "").strip(),
                cantina_url      = os.environ.get(
                                       "CANTINA_DARKSTAR_URL",
                                       "https://cantina.vectra.ai/api/darkstar/lambda"
                                   ).strip(),
                cantina_customer = cantina_customer,
                vectra_ndr_url   = ndr_url,
                vectra_client_id = client_id,
                vectra_client_secret = client_secret,
                vectra_token     = ndr_token,
                timeout_sec      = int(os.environ.get(
                                       "VECTRA_FP_QUERY_TIMEOUT_SEC", "180"
                                   )),
            )
            self.helper.log_info(
                f"[vectra-fp] metadata client ready (mode={client.mode})"
            )
            return client
        except VectraMetadataError as exc:
            self.helper.log_error(f"[vectra-fp] metadata client init failed: {exc}")
            return None

    # ── breadth bucketing ──────────────────────────────────────────────────────

    @staticmethod
    def _breadth_bucket(n: int) -> str:
        if n >= 500: return "500+"
        if n >= 250: return "250-499"
        if n >= 100: return "100-249"
        if n >= 50:  return "50-99"
        if n >= 20:  return "20-49"
        if n >= 10:  return "10-19"
        return "1-9"   # reachable only if host_threshold is lowered below 10

    # ── OpenCTI observable helpers ─────────────────────────────────────────────

    def _find_observable(self, obs_type: str, value: str) -> dict | None:
        try:
            results = self.helper.api.stix_cyber_observable.list(
                types=[obs_type],
                filters={
                    "mode": "and",
                    "filters": [{"key": "value", "values": [value]}],
                    "filterGroups": [],
                },
                first=1,
            )
            return results[0] if results else None
        except Exception as exc:
            self.helper.log_warning(
                f"[vectra-fp] observable lookup failed {obs_type}:{value}: {exc}"
            )
            return None

    def _create_observable(self, obs_type: str, value: str) -> str | None:
        stix_type = {
            "IPv4-Addr":   "ipv4-addr",
            "Domain-Name": "domain-name",
        }.get(obs_type)
        if not stix_type:
            return None
        try:
            created = self.helper.api.stix_cyber_observable.create(
                observableData={
                    "type":  stix_type,
                    "value": value,
                    "x_opencti_score":       self.fp_score,
                    "x_opencti_description": (
                        f"Auto-created by Vectra Metadata FP Discovery "
                        f"({obs_type}: {value}). "
                        "Assessed as benign infrastructure based on fleet-wide "
                        "breadth heuristic. Awaiting feed enrichment."
                    ),
                }
            )
            return created.get("id")
        except Exception as exc:
            self.helper.log_error(
                f"[vectra-fp] observable create failed {obs_type}:{value}: {exc}"
            )
            return None

    def _add_label(self, obs_id: str, label: str, color: str) -> bool:
        # label.create is idempotent — returns existing label if value already exists.
        try:
            result = self.helper.api.label.create(value=label, color=color)
            self.helper.api.stix_cyber_observable.add_label(id=obs_id, label_id=result["id"])
            return True
        except Exception as exc:
            self.helper.log_warning(f"[vectra-fp] add_label failed '{label}': {exc}")
            return False

    def _add_discovery_note(
        self, obs_id: str, entry: IOCEntry, query_label: str
    ) -> None:
        """Attach a markdown note with full metadata context to the observable."""
        ctx = entry.context
        bucket = self._breadth_bucket(entry.breadth)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        ctx_rows = [(k, v) for k, v in ctx.items()
                    if k not in _CTX_SKIP and v is not None and v != '']

        table_md = "\n".join(
            f"| `{k}` | `{v}` |" for k, v in ctx_rows
        ) if ctx_rows else "*(no additional context)*"

        content = (
            f"## Vectra Metadata — Benign IOC Discovery\n\n"
            f"**Observable:** `{entry.value}`  \n"
            f"**Type:** `{entry.ioc_type}`  \n"
            f"**Discovery Query:** `{entry.query_name}` — {query_label}  \n"
            f"**Host/User Breadth:** **{entry.breadth}** distinct "
            f"{'users' if entry.query_name == 'shared_auth_ips' else 'internal hosts'}  \n"
            f"**Breadth Tier:** `{bucket}`  \n"
            f"**Lookback:** {self.lookback_days} days  \n\n"
            f"### Metadata Context\n\n"
            f"| Field | Value |\n|---|---|\n"
            f"{table_md}\n\n"
            f"---\n"
            f"*Generated by `connector-vectra-metadata-fp` at {ts}*"
        )

        try:
            self.helper.api.note.create(
                abstract=(
                    f"Vectra FP: {entry.ioc_type}:{entry.value} "
                    f"breadth={entry.breadth} [{entry.query_name}]"
                ),
                content=content,
                objectRefs=[obs_id],
                confidence=self.confidence,
            )
        except Exception as exc:
            self.helper.log_warning(f"[vectra-fp] note create failed: {exc}")

    # ── IOC import pipeline ────────────────────────────────────────────────────

    def _import_ioc(self, entry: IOCEntry, query_label: str) -> bool:
        """
        Import one IOC entry into OpenCTI.  Returns True if the observable was
        newly created or had labels/notes applied this cycle.

        Pipeline:
          1. Dedup check (within this cycle)
          2. Find or create observable
          3. Safety guard — skip if existing score ≥ malicious_guard
          4. Diff labels: apply fp-candidate, vectra-metadata-benign, and breadth
             tier on new observables AND on existing ones that are missing them.
             breadth:<tier> is also added when the observable has moved to a
             higher tier since the last cycle (old tier label stays for history).
          5. Attach a discovery note whenever fp-candidate is newly applied.
        """
        key = (entry.ioc_type, entry.value)
        if key in self._seen_this_cycle:
            return False
        self._seen_this_cycle.add(key)

        existing = self._find_observable(entry.ioc_type, entry.value)
        if existing:
            existing_score = int(existing.get("x_opencti_score") or 50)
            if existing_score >= self.malicious_guard:
                self.helper.log_info(
                    f"[vectra-fp] SKIP confirmed-malicious "
                    f"{entry.ioc_type}:{entry.value} score={existing_score}"
                )
                return False
            obs_id = existing["id"]
            existing_labels: set[str] = {
                lbl.get("value", "")
                for lbl in (existing.get("objectLabel") or [])
            }
            is_new = False
        else:
            obs_id = self._create_observable(entry.ioc_type, entry.value)
            if not obs_id:
                return False
            existing_labels = set()
            is_new = True

        new_bucket = self._breadth_bucket(entry.breadth)
        needs_fp  = LABEL_FP_CANDIDATE  not in existing_labels
        needs_vec = LABEL_VECTRA_BENIGN not in existing_labels
        needs_breadth_lbl = f"breadth:{new_bucket}" not in existing_labels

        if not needs_fp and not needs_vec and not needs_breadth_lbl:
            self.helper.log_debug(
                f"[vectra-fp] seen {entry.ioc_type}:{entry.value} "
                f"breadth={entry.breadth} query={entry.query_name}"
            )
            return False

        # Apply fp labels independently so a failure on the second label
        # (vectra-metadata-benign) is retried next cycle even after fp-candidate
        # succeeds.  Note is only attached when fp-candidate is newly applied
        # successfully — this deduplicates notes across cycles naturally.
        if needs_fp:
            ok_fp = self._add_label(obs_id, LABEL_FP_CANDIDATE, COLOR_FP)
            if ok_fp:
                self._add_discovery_note(obs_id, entry, query_label)
        if needs_vec:
            self._add_label(obs_id, LABEL_VECTRA_BENIGN, COLOR_VECTRA)

        if needs_breadth_lbl:
            self._add_label(obs_id, f"breadth:{new_bucket}", COLOR_BREADTH)

        action = "imported" if is_new else "labelled"
        self.helper.log_debug(
            f"[vectra-fp] {action} {entry.ioc_type}:{entry.value} "
            f"breadth={entry.breadth} query={entry.query_name}"
        )
        return True

    # ── query execution ────────────────────────────────────────────────────────

    def _process_query(
        self, qdef: QueryDefinition, client: VectraMetadataClient
    ) -> tuple[int, int, int]:
        """
        Execute one query and import all extracted IOCs.

        Returns: (rows_returned, iocs_extracted, iocs_imported)
        """
        sql = qdef.build_sql(
            days=self.lookback_days,
            host_threshold=self.host_threshold,
            user_threshold=self.user_threshold,
            max_results=self.max_results,
        )

        self.helper.log_info(
            f"[vectra-fp] running query: {qdef.name} "
            f"(days={self.lookback_days}, "
            f"host_threshold={self.host_threshold}, "
            f"user_threshold={self.user_threshold})"
        )

        try:
            rows = client.execute(sql)
        except VectraMetadataError as exc:
            self.helper.log_error(
                f"[vectra-fp] query {qdef.name} failed: {exc}"
            )
            return 0, 0, 0

        n_rows = len(rows)
        n_iocs = 0
        n_imported = 0

        for entry in qdef.extract_iocs(rows):
            n_iocs += 1
            if self._import_ioc(entry, qdef.label):
                n_imported += 1

        self.helper.log_info(
            f"[vectra-fp] {qdef.name}: "
            f"rows={n_rows} iocs={n_iocs} imported={n_imported}"
        )
        return n_rows, n_iocs, n_imported

    # ── cycle ──────────────────────────────────────────────────────────────────

    def _run_cycle(self, client: VectraMetadataClient) -> None:
        """Execute all 6 queries and import results for one cycle."""
        self._seen_this_cycle = set()
        cycle_start = time.monotonic()

        total_rows = total_iocs = total_imported = 0

        for idx, qdef in enumerate(ALL_QUERIES):
            if idx > 0 and self.inter_query_delay_sec > 0:
                time.sleep(self.inter_query_delay_sec)
            r, n, imp = self._process_query(qdef, client)
            total_rows     += r
            total_iocs     += n
            total_imported += imp

        elapsed = time.monotonic() - cycle_start
        self.helper.log_info(
            f"[vectra-fp] cycle complete: "
            f"total_rows={total_rows} "
            f"total_iocs_extracted={total_iocs} "
            f"total_imported={total_imported} "
            f"elapsed={elapsed:.1f}s "
            f"next_run_in={self.interval_sec}s"
        )

    # ── main loop ──────────────────────────────────────────────────────────────

    def run(self) -> None:
        """Start the connector.  Runs immediately then sleeps for interval_sec."""
        self.helper.log_info(
            f"[vectra-fp] starting — "
            f"lookback_days={self.lookback_days} "
            f"host_threshold={self.host_threshold} "
            f"user_threshold={self.user_threshold} "
            f"interval_sec={self.interval_sec}"
        )

        while True:
            # Client is cached on self._client; only rebuilt when absent.
            # Env-var changes (credentials, URLs) take effect on next container restart.
            if self._client is None:
                try:
                    self._client = self._build_client()
                except Exception as exc:   # V16: defensive — _build_client rarely raises
                    self.helper.log_error(
                        f"[vectra-fp] client init error: {exc}\n{traceback.format_exc()}"
                    )
            if self._client is not None:
                try:
                    self._run_cycle(self._client)
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    self.helper.log_error(
                        f"[vectra-fp] cycle error: {exc}\n{traceback.format_exc()}"
                    )
            time.sleep(self.interval_sec)


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    connector = VectraMetadataFPConnector()
    connector.run()
