#!/usr/bin/env python3
"""
Vectra Metadata False-Positive Discovery — OpenCTI External Import Connector

Periodically executes 6 Vectra Metadata SQL queries that identify network
endpoints (IPs, domains) observed across a BROAD SET of internal hosts.
High host-breadth is a strong signal for benign infrastructure (CDN, SaaS,
OS telemetry, corporate proxies) and a direct analogue of the ubiquity
heuristic in the ioc-trust-cluster connector.

Each discovered observable (new or existing) is labelled in OpenCTI with:
  - Labels: vectra-metadata-benign or vectra-metadata-popular-ip, breadth:<tier>
    Raw Q1 broad-reach IPs get the weaker popular-ip label by default; stronger
    domain/M365 signals get vectra-metadata-benign. The cascade-capable
    fp-candidate label is opt-in via VECTRA_FP_APPLY_FP_CANDIDATE=true.
  - x_opencti_score = VECTRA_FP_SCORE (default 15) is set only when the
    connector creates a new observable; existing scores are never overwritten.
  - A Note with the metadata context is attached whenever the source label is
    newly applied — whether the observable is brand-new or pre-existing.
  - breadth:<tier> is refreshed when the observable moves to a higher tier;
    previous tier labels are retained for audit history.

Safety guard: if an observable already exists with score ≥
VECTRA_FP_MALICIOUS_GUARD_SCORE (default 70) — i.e. a feed connector has
independently confirmed it as malicious — the connector does NOT apply benign
labels to it.

Integration with ioc-trust-cluster: Vectra labels are source context by default.
Only opt-in fp-candidate/explicit confirmed labels should feed cascade behavior.

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
LABEL_VECTRA_POPULAR_IP = "vectra-metadata-popular-ip"

COLOR_FP = "#2e7d32"         # green  — benign / fp candidate
COLOR_VECTRA = "#0d47a1"     # dark blue — vectra-sourced
COLOR_POPULAR_IP = "#6d4c41" # brown — weak popularity context
COLOR_BREADTH = "#455a64"    # blue-grey — breadth tier

# Context keys already captured in the note header — skip in the detail table.
_CTX_SKIP = frozenset({
    'resp_ip', 'ip_address', 'domain', 'server_name', 'host', 'resp_domains',
    '_matched_queries', '_query_labels', '_context_count',
})


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
        self.apply_fp_candidate: bool = os.environ.get(
                                        "VECTRA_FP_APPLY_FP_CANDIDATE", "false"
                                    ).lower() == "true"
        self.create_missing: bool     = os.environ.get(
                                        "VECTRA_FP_CREATE_MISSING", "true"
                                    ).lower() == "true"
        self.strong_raw_ips: bool     = os.environ.get(
                                        "VECTRA_FP_STRONG_RAW_IPS", "false"
                                    ).lower() == "true"
        self._skipped_missing: int    = 0

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

    @staticmethod
    def _query_names(entry: IOCEntry) -> set[str]:
        raw = entry.context.get('_matched_queries') if isinstance(entry.context, dict) else None
        if raw:
            return {str(q) for q in raw}
        return {q for q in str(entry.query_name).split(',') if q}

    def _source_labels(self, entry: IOCEntry) -> list[tuple[str, str]]:
        queries = self._query_names(entry)
        labels: list[tuple[str, str]] = []
        if 'broad_reach_ips' in queries:
            labels.append((LABEL_VECTRA_POPULAR_IP, COLOR_POPULAR_IP))
        if self.strong_raw_ips or any(q != 'broad_reach_ips' for q in queries):
            labels.append((LABEL_VECTRA_BENIGN, COLOR_VECTRA))
        return labels

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

        query_labels = ctx.get('_query_labels') or {entry.query_name: query_label}
        query_md = "\n".join(
            f"- `{name}` — {label}" for name, label in query_labels.items()
        )
        breadth_subject = (
            "users" if set(query_labels) == {"shared_auth_ips"}
            else "internal hosts/users"
        )

        content = (
            f"## Vectra Metadata — Benign IOC Discovery\n\n"
            f"**Observable:** `{entry.value}`  \n"
            f"**Type:** `{entry.ioc_type}`  \n"
            f"**Discovery Queries:**\n{query_md}\n\n"
            f"**Host/User Breadth:** **{entry.breadth}** distinct {breadth_subject}  \n"
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
                    f"breadth={entry.breadth} [{', '.join(query_labels)}]"
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
          4. Diff labels: apply source label, breadth tier, and the opt-in
             fp-candidate label on observables missing them.
          5. Attach a discovery note whenever the source/cascade label is newly
             applied.
        """
        key = (entry.ioc_type, entry.value)
        if key in self._seen_this_cycle:
            return False
        self._seen_this_cycle.add(key)

        existing = self._find_observable(entry.ioc_type, entry.value)
        if existing:
            raw_score = existing.get("x_opencti_score")
            existing_score = int(raw_score) if raw_score is not None else 50
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
            if not self.create_missing:
                self._skipped_missing += 1
                self.helper.log_debug(
                    f"[vectra-fp] skip missing {entry.ioc_type}:{entry.value} "
                    "(VECTRA_FP_CREATE_MISSING=false)"
                )
                return False
            obs_id = self._create_observable(entry.ioc_type, entry.value)
            if not obs_id:
                return False
            existing_labels = set()
            is_new = True

        new_bucket = self._breadth_bucket(entry.breadth)
        needs_fp  = self.apply_fp_candidate and LABEL_FP_CANDIDATE not in existing_labels
        source_labels = [
            (label, color) for label, color in self._source_labels(entry)
            if label not in existing_labels
        ]
        needs_breadth_lbl = f"breadth:{new_bucket}" not in existing_labels

        if not needs_fp and not source_labels and not needs_breadth_lbl:
            self.helper.log_debug(
                f"[vectra-fp] seen {entry.ioc_type}:{entry.value} "
                f"breadth={entry.breadth} query={entry.query_name}"
            )
            return False

        # Apply labels independently so failures are retried next cycle.
        # Note is attached when the first source/cascade label is newly applied;
        # this deduplicates notes across cycles naturally.
        noted = False
        if needs_fp:
            ok_fp = self._add_label(obs_id, LABEL_FP_CANDIDATE, COLOR_FP)
            if ok_fp:
                self._add_discovery_note(obs_id, entry, query_label)
                noted = True
        for label, color in source_labels:
            ok_source = self._add_label(obs_id, label, color)
            if ok_source and not noted:
                self._add_discovery_note(obs_id, entry, query_label)
                noted = True

        if needs_breadth_lbl:
            self._add_label(obs_id, f"breadth:{new_bucket}", COLOR_BREADTH)

        action = "imported" if is_new else "labelled"
        self.helper.log_debug(
            f"[vectra-fp] {action} {entry.ioc_type}:{entry.value} "
            f"breadth={entry.breadth} query={entry.query_name}"
        )
        return True

    # ── query execution ────────────────────────────────────────────────────────

    @staticmethod
    def _collect_ioc(
        aggregate: dict[tuple[str, str], dict], entry: IOCEntry, query_label: str
    ) -> None:
        key = (entry.ioc_type, entry.value)
        item = aggregate.setdefault(
            key,
            {"entry": entry, "query_labels": {}, "context_count": 0},
        )
        if entry.breadth > item["entry"].breadth:
            item["entry"] = entry
        item["query_labels"][entry.query_name] = query_label
        item["context_count"] += 1

    @staticmethod
    def _aggregated_entry(item: dict) -> IOCEntry:
        best: IOCEntry = item["entry"]
        ctx = dict(best.context)
        ctx["_query_labels"] = item["query_labels"]
        ctx["_matched_queries"] = list(item["query_labels"])
        ctx["_context_count"] = item["context_count"]
        return IOCEntry(
            ioc_type=best.ioc_type,
            value=best.value,
            breadth=best.breadth,
            query_name=",".join(item["query_labels"]),
            context=ctx,
        )

    def _process_query(
        self,
        qdef: QueryDefinition,
        client: VectraMetadataClient,
        aggregate: dict[tuple[str, str], dict],
    ) -> tuple[int, int]:
        """
        Execute one query and collect extracted IOCs.

        Returns: (rows_returned, iocs_extracted)
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
            return 0, 0

        n_rows = len(rows)
        n_iocs = 0

        for entry in qdef.extract_iocs(rows):
            n_iocs += 1
            self._collect_ioc(aggregate, entry, qdef.label)

        self.helper.log_info(
            f"[vectra-fp] {qdef.name}: rows={n_rows} iocs={n_iocs}"
        )
        return n_rows, n_iocs

    # ── cycle ──────────────────────────────────────────────────────────────────

    def _run_cycle(self, client: VectraMetadataClient) -> None:
        """Execute all 6 queries and import results for one cycle."""
        self._seen_this_cycle = set()
        self._skipped_missing = 0
        cycle_start = time.monotonic()

        total_rows = total_iocs = total_imported = 0
        aggregate: dict[tuple[str, str], dict] = {}

        for idx, qdef in enumerate(ALL_QUERIES):
            if idx > 0 and self.inter_query_delay_sec > 0:
                time.sleep(self.inter_query_delay_sec)
            r, n = self._process_query(qdef, client, aggregate)
            total_rows += r
            total_iocs += n

        for item in aggregate.values():
            entry = self._aggregated_entry(item)
            query_label = "; ".join(item["query_labels"].values())
            if self._import_ioc(entry, query_label):
                total_imported += 1

        elapsed = time.monotonic() - cycle_start
        self.helper.log_info(
            f"[vectra-fp] cycle complete: "
            f"total_rows={total_rows} "
            f"total_iocs_extracted={total_iocs} "
            f"unique_iocs={len(aggregate)} "
            f"total_imported={total_imported} "
            f"skipped_missing={self._skipped_missing} "
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
