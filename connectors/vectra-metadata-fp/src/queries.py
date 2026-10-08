"""
Six Vectra Metadata Trino SQL queries that discover broadly-observed
external network endpoints across the fleet.

Signal: if an IP or domain is contacted by a BROAD SET of distinct internal
hosts it is almost certainly benign infrastructure (CDN, SaaS, OS telemetry,
corporate proxy, etc.) and should be marked fp-candidate in OpenCTI so the
ioc-trust-cluster connector can cascade the verdict to related observables.

SQL dialect: Trino (Vectra custom).
  - No JOINs, CTEs, or subqueries.
  - network.beacon._all uses first_event_time (not timestamp).
  - resp_domains is an ARRAY in beacon — handled by _parse_resp_domains().
  - Use LIKE for substring matching (contains() rejected on some deployments).
  - Column names: id.orig_h / id.resp_h / id.resp_p / orig_ip_bytes /
    resp_ip_bytes / local_orig / local_resp.
  - No network.conn._all — use network.isession._all for flow data.

Docs imported from vectra/reference/metadata/:
  table-schemas.md | execution.md | metadata-sql-gotchas.md
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Iterator

# ─── validation patterns ──────────────────────────────────────────────────────

_IPV4_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_DOMAIN_LABEL_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')

# Suffixes never valid as external IOC domains
_SKIP_SUFFIXES: tuple[str, ...] = (
    '.arpa', '.local', '.internal', '.corp', '.lan', '.home',
    '.test', '.example', '.invalid', '.localhost',
)


# ─── data model ───────────────────────────────────────────────────────────────

@dataclass
class IOCEntry:
    """One benign IOC discovered from a Vectra metadata query."""
    ioc_type: str    # "IPv4-Addr" or "Domain-Name"
    value: str       # normalized (lowercase domain, plain IP)
    breadth: int     # distinct host or user count — confidence signal
    query_name: str  # which query found it
    context: dict    # raw result row for note generation


@dataclass
class QueryDefinition:
    """A Vectra metadata query + its IOC extraction logic."""
    name: str
    label: str           # human-readable description for notes
    sql_template: str    # Trino SQL; {days}/{host_threshold}/{user_threshold}/{max_results}

    # extraction callable: (query_name, row) -> Iterator[IOCEntry]
    _extract_impl: object

    def build_sql(self, *, days: int, host_threshold: int,
                  user_threshold: int, max_results: int) -> str:
        return self.sql_template.format(
            days=days,
            host_threshold=host_threshold,
            user_threshold=user_threshold,
            max_results=max_results,
        )

    def extract_iocs(self, rows: list[dict]) -> Iterator[IOCEntry]:
        for row in rows:
            yield from self._extract_impl(self.name, row)  # type: ignore[operator]


# ─── validators ───────────────────────────────────────────────────────────────

def _is_private_ip(addr: str) -> bool:
    """Return True for any non-globally-routable address."""
    try:
        return not ipaddress.ip_address(addr.split('/')[0]).is_global
    except ValueError:
        return True


def _is_valid_ipv4(addr: str) -> bool:
    """Return True for a routable public IPv4 address (no CIDR notation)."""
    addr = (addr or '').strip()
    if not _IPV4_RE.match(addr):
        return False
    return not _is_private_ip(addr)


def _is_valid_domain(domain: str) -> bool:
    """Return True for an external FQDN suitable as a Domain-Name observable."""
    if not domain:
        return False
    d = domain.lower().strip('.')
    if not d or '.' not in d or len(d) < 4:
        return False
    for suffix in _SKIP_SUFFIXES:
        if d.endswith(suffix):
            return False
    labels = d.split('.')
    if len(labels) < 2:
        return False
    for label in labels:
        if not label or len(label) > 63 or not _DOMAIN_LABEL_RE.match(label):
            return False
    return True


def _parse_resp_domains(value: object) -> list[str]:
    """Normalise resp_domains from beacon: None | str | list | JSON-encoded list."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if v]
    if isinstance(value, str):
        v = value.strip()
        if v.startswith('['):
            try:
                parsed = json.loads(v)
                return [str(x).strip() for x in parsed if x]
            except (ValueError, TypeError):
                pass
        return [v] if v else []
    return []


# ══════════════════════════════════════════════════════════════════════════════
# Query 1 — Broad-reach external IPs (network sessions)
#
# Signal: External IPs contacted by ≥ HOST_THRESHOLD distinct internal hosts.
# Table:  network.isession._all
# IOC:    IPv4-Addr (resp_ip)
# Why:    If ≥N internal hosts independently connect to the same external IP
#         it is almost certainly CDN/SaaS/OS-update infrastructure.
# ══════════════════════════════════════════════════════════════════════════════

_SQL_BROAD_REACH_IPS = """\
SELECT
    id.resp_h                       AS resp_ip,
    COUNT(DISTINCT resp_domain)     AS resp_domain_count,
    COUNT(DISTINCT id.resp_p)       AS resp_port_count,
    COUNT(DISTINCT service)         AS service_count,
    COUNT(DISTINCT id.orig_h)       AS src_host_count,
    COUNT(*)                        AS session_count,
    SUM(orig_ip_bytes)              AS total_orig_bytes,
    SUM(resp_ip_bytes)              AS total_resp_bytes,
    MIN(timestamp)                  AS first_seen,
    MAX(timestamp)                  AS last_seen
FROM network.isession._all
WHERE local_resp  = FALSE
  AND local_orig  = TRUE
  AND id.resp_h  IS NOT NULL
  AND dt        > date_add('day', -{days}, now())
  AND timestamp  BETWEEN date_add('day', -{days}, now()) AND now()
GROUP BY id.resp_h
HAVING COUNT(DISTINCT id.orig_h) >= {host_threshold}
ORDER BY src_host_count DESC, session_count DESC
LIMIT {max_results}
"""


def _extract_broad_reach_ips(query_name: str, row: dict) -> Iterator[IOCEntry]:
    resp_ip = (row.get('resp_ip') or '').strip()
    if _is_valid_ipv4(resp_ip):
        yield IOCEntry(
            ioc_type='IPv4-Addr',
            value=resp_ip,
            breadth=int(row.get('src_host_count') or 0),
            query_name=query_name,
            context=row,
        )


# ══════════════════════════════════════════════════════════════════════════════
# Query 2 — Broad-reach DNS domains
#
# Signal: External domain names resolved by ≥ HOST_THRESHOLD distinct hosts.
# Table:  network.dns._all
# IOC:    Domain-Name (query)
# Why:    A domain queried fleet-wide is organisational infrastructure, not C2.
# ══════════════════════════════════════════════════════════════════════════════

_SQL_BROAD_REACH_DNS = """\
SELECT
    query                           AS domain,
    COUNT(DISTINCT id.orig_h)       AS resolver_count,
    COUNT(*)                        AS total_queries,
    MIN(timestamp)                  AS first_seen,
    MAX(timestamp)                  AS last_seen
FROM network.dns._all
WHERE query IS NOT NULL
  AND query != ''
  AND query NOT LIKE '%.arpa'
  AND query NOT LIKE '%.local'
  AND query NOT LIKE '%.internal'
  AND dt        > date_add('day', -{days}, now())
  AND timestamp  BETWEEN date_add('day', -{days}, now()) AND now()
GROUP BY query
HAVING COUNT(DISTINCT id.orig_h) >= {host_threshold}
  -- Exclude the domain entirely if ANY response for it ever contained a
  -- private/RFC1918 address.  Operates at HAVING (post-GROUP BY) so even
  -- CNAME-only rows cannot sneak an internal hostname through: the moment
  -- any sibling row shows 192.168.x / 10.x / 172.16-31.x the domain is out.
  AND SUM(
      CASE WHEN answers IS NOT NULL
                AND any_match(
                       answers,
                       x -> REGEXP_LIKE(x,
                           '^(10[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[01])[.]|127[.]|169[.]254[.])'))
           THEN 1 ELSE 0 END
  ) = 0
ORDER BY resolver_count DESC, total_queries DESC
LIMIT {max_results}
"""


def _extract_broad_reach_dns(query_name: str, row: dict) -> Iterator[IOCEntry]:
    domain = (row.get('domain') or '').strip().lower()
    if _is_valid_domain(domain):
        yield IOCEntry(
            ioc_type='Domain-Name',
            value=domain,
            breadth=int(row.get('resolver_count') or 0),
            query_name=query_name,
            context=row,
        )


# ══════════════════════════════════════════════════════════════════════════════
# Query 3 — Broad-reach TLS/SNI names (SSL handshakes)
#
# Signal: TLS server_name (SNI) seen from ≥ HOST_THRESHOLD distinct hosts.
# Table:  network.ssl._all
# IOC:    Domain-Name (server_name) or IPv4-Addr if numeric
# Why:    High-breadth SNI = well-known HTTPS service not always in DNS logs.
#         Corroborates Q2 at the TLS layer.
# ══════════════════════════════════════════════════════════════════════════════

_SQL_BROAD_REACH_TLS_SNI = """\
SELECT
    server_name,
    COUNT(DISTINCT id.orig_h)       AS src_host_count,
    COUNT(*)                        AS connection_count,
    MIN(timestamp)                  AS first_seen,
    MAX(timestamp)                  AS last_seen
FROM network.ssl._all
WHERE server_name IS NOT NULL
  AND server_name != ''
  AND server_name NOT LIKE '%.arpa'
  AND server_name NOT LIKE '%.local'
  -- Drop connections whose TCP destination is a private IP — those SNI names
  -- belong to internal services and are not useful as external IOCs.
  AND NOT REGEXP_LIKE(id.resp_h,
      '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|127\\.|169\\.254\\.)')
  AND dt        > date_add('day', -{days}, now())
  AND timestamp  BETWEEN date_add('day', -{days}, now()) AND now()
GROUP BY server_name
HAVING COUNT(DISTINCT id.orig_h) >= {host_threshold}
ORDER BY src_host_count DESC, connection_count DESC
LIMIT {max_results}
"""


def _extract_broad_reach_tls_sni(query_name: str, row: dict) -> Iterator[IOCEntry]:
    sni = (row.get('server_name') or '').strip().lower()
    if not sni:
        return
    if _IPV4_RE.match(sni):
        if _is_valid_ipv4(sni):
            yield IOCEntry(
                ioc_type='IPv4-Addr',
                value=sni,
                breadth=int(row.get('src_host_count') or 0),
                query_name=query_name,
                context=row,
            )
    elif _is_valid_domain(sni):
        yield IOCEntry(
            ioc_type='Domain-Name',
            value=sni,
            breadth=int(row.get('src_host_count') or 0),
            query_name=query_name,
            context=row,
        )


# ══════════════════════════════════════════════════════════════════════════════
# Query 4 — Broad-reach HTTP hosts
#
# Signal: HTTP Host headers seen from ≥ HOST_THRESHOLD hosts, majority success.
# Table:  network.http._all
# IOC:    Domain-Name (host) or IPv4-Addr
# Why:    HTTP breadth + success rate confirms a live, widely-used service.
#         HAVING guard on success_count > 0 excludes scan/error-only traffic.
# ══════════════════════════════════════════════════════════════════════════════

_SQL_BROAD_REACH_HTTP = """\
SELECT
    CASE
        WHEN REGEXP_LIKE(host, '^[^:]+:[0-9]+$')
        THEN REGEXP_REPLACE(host, ':[0-9]+$', '')
        ELSE host
    END                                                                     AS host,
    COUNT(DISTINCT id.orig_h)                                               AS src_host_count,
    COUNT(*)                                                                AS request_count,
    COUNT(CASE WHEN status_code BETWEEN 200 AND 399 THEN 1 END)            AS success_count,
    MIN(timestamp)                                                          AS first_seen,
    MAX(timestamp)                                                          AS last_seen
FROM network.http._all
WHERE host IS NOT NULL
  AND host != ''
  AND host NOT LIKE '%.arpa'
  AND host NOT LIKE '%.local'
  -- Same as Q3: drop rows where the HTTP server is at a private IP.
  AND NOT REGEXP_LIKE(id.resp_h,
      '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|127\\.|169\\.254\\.)')
  AND dt        > date_add('day', -{days}, now())
  AND timestamp  BETWEEN date_add('day', -{days}, now()) AND now()
GROUP BY CASE
        WHEN REGEXP_LIKE(host, '^[^:]+:[0-9]+$')
        THEN REGEXP_REPLACE(host, ':[0-9]+$', '')
        ELSE host
    END
HAVING COUNT(DISTINCT id.orig_h) >= {host_threshold}
   AND COUNT(CASE WHEN status_code BETWEEN 200 AND 399 THEN 1 END) > 0
ORDER BY src_host_count DESC, request_count DESC
LIMIT {max_results}
"""


def _extract_broad_reach_http(query_name: str, row: dict) -> Iterator[IOCEntry]:
    # strip optional port (:80, :8080) before classifying
    host_raw = (row.get('host') or '').strip().lower()
    # handle host:port format
    host = host_raw.split(':')[0] if ':' in host_raw and not host_raw.startswith('[') else host_raw
    if not host:
        return
    breadth = int(row.get('src_host_count') or 0)
    if _IPV4_RE.match(host):
        if _is_valid_ipv4(host):
            yield IOCEntry(ioc_type='IPv4-Addr', value=host,
                           breadth=breadth, query_name=query_name, context=row)
    elif _is_valid_domain(host):
        yield IOCEntry(ioc_type='Domain-Name', value=host,
                       breadth=breadth, query_name=query_name, context=row)


# ══════════════════════════════════════════════════════════════════════════════
# Query 5 — Vectra-labeled non-C2 beacons
#
# Signal: Beacon records where Vectra ML classified beacon_type as a known-benign
#         value (see BENIGN_BEACON_TYPES), seen from ≥ HOST_THRESHOLD distinct hosts.
# Table:  network.beacon._all
# IOC:    Domain-Name (resp_domains array) and/or IPv4-Addr (resp_ip)
# Why:    Strongest signal — Vectra's own ML has already reviewed the periodic
#         communication pattern and classified it as non-C2 behaviour.
#         High breadth on top makes false-positive risk negligible.
#
# IMPORTANT: beacon uses first_event_time (not timestamp) for event filtering.
#            resp_domains is an ARRAY — Python normalisation in _parse_resp_domains.
# ══════════════════════════════════════════════════════════════════════════════

# Exhaustive safelist of Vectra beacon_type values that indicate benign periodic
# communication.  Using IN (safelist) rather than NOT IN (denylist) ensures that
# any new malicious beacon type added in future Vectra product updates (e.g.
# 'ransomware_c2', 'threat') is automatically excluded without a code change.
BENIGN_BEACON_TYPES: tuple[str, ...] = (
    'regular', 'known', 'normal', 'periodic', 'automated', 'benign',
)

_SQL_BENIGN_BEACONS = """\
SELECT
    resp_domains,
    id.resp_h                       AS resp_ip,
    COUNT(DISTINCT service)         AS service_count,
    COUNT(DISTINCT beacon_type)     AS beacon_type_count,
    COUNT(DISTINCT id.orig_h)       AS src_host_count,
    COUNT(*)                        AS beacon_record_count,
    SUM(session_count)              AS total_sessions,
    MIN(first_event_time)           AS first_seen,
    MAX(first_event_time)           AS last_seen
FROM network.beacon._all
WHERE beacon_type IN ('regular', 'known', 'normal', 'periodic', 'automated', 'benign')
  -- Belt-and-suspenders: Vectra ML already skips internal traffic, but
  -- explicitly drop rows where the beacon destination is a private IP.
  AND NOT REGEXP_LIKE(id.resp_h,
      '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|127\\.|169\\.254\\.)')
  AND dt           > date_add('day', -{days}, now())
  AND first_event_time BETWEEN date_add('day', -{days}, now()) AND now()
GROUP BY resp_domains, id.resp_h
HAVING COUNT(DISTINCT id.orig_h) >= {host_threshold}
ORDER BY src_host_count DESC, total_sessions DESC
LIMIT {max_results}
"""


def _extract_benign_beacons(query_name: str, row: dict) -> Iterator[IOCEntry]:
    breadth = int(row.get('src_host_count') or 0)
    # Domains from resp_domains array
    for domain in _parse_resp_domains(row.get('resp_domains')):
        domain = domain.strip().lower()
        if _is_valid_domain(domain):
            yield IOCEntry(ioc_type='Domain-Name', value=domain,
                           breadth=breadth, query_name=query_name, context=row)
    # IP from resp_ip field
    resp_ip = (row.get('resp_ip') or '').strip()
    if resp_ip and _is_valid_ipv4(resp_ip):
        yield IOCEntry(ioc_type='IPv4-Addr', value=resp_ip,
                       breadth=breadth, query_name=query_name, context=row)


# ══════════════════════════════════════════════════════════════════════════════
# Query 6 — Shared M365 authentication IPs
#
# Signal: IPs used for successful M365 sign-ins by ≥ USER_THRESHOLD distinct
#         users over the lookback window.
# Table:  m365.signins._all
# IOC:    IPv4-Addr (ip_address)
# Why:    These IPs are corporate egress nodes, NAT gateways, VPN endpoints,
#         or known proxy pools.  They frequently appear in threat-feed blocklists
#         as "suspicious" but are actually well-known internal infrastructure.
#         User breadth is the cleaner signal here (vs host breadth for network).
# ══════════════════════════════════════════════════════════════════════════════

_SQL_SHARED_AUTH_IPS = """\
SELECT
    ip_address,
    COALESCE(location.country_or_region, '') AS country,
    COALESCE(location.city,              '') AS city,
    COUNT(DISTINCT user_principal_name)      AS unique_user_count,
    COUNT(*)                                 AS total_signins,
    MIN(timestamp)                           AS first_seen,
    MAX(timestamp)                           AS last_seen
FROM m365.signins._all
WHERE status.error_code = 0
  AND ip_address IS NOT NULL
  AND ip_address != ''
  AND dt        > date_add('day', -{days}, now())
  AND timestamp  BETWEEN date_add('day', -{days}, now()) AND now()
GROUP BY ip_address, location.country_or_region, location.city
HAVING COUNT(DISTINCT user_principal_name) >= {user_threshold}
ORDER BY unique_user_count DESC, total_signins DESC
LIMIT {max_results}
"""


def _extract_shared_auth_ips(query_name: str, row: dict) -> Iterator[IOCEntry]:
    ip = (row.get('ip_address') or '').strip()
    if _is_valid_ipv4(ip):
        yield IOCEntry(
            ioc_type='IPv4-Addr',
            value=ip,
            breadth=int(row.get('unique_user_count') or 0),
            query_name=query_name,
            context=row,
        )


# ─── registry ─────────────────────────────────────────────────────────────────

ALL_QUERIES: list[QueryDefinition] = [
    QueryDefinition(
        name='broad_reach_ips',
        label='Broad-Reach External IPs (network sessions)',
        sql_template=_SQL_BROAD_REACH_IPS,
        _extract_impl=_extract_broad_reach_ips,
    ),
    QueryDefinition(
        name='broad_reach_dns',
        label='Broad-Reach DNS Domains (DNS resolver)',
        sql_template=_SQL_BROAD_REACH_DNS,
        _extract_impl=_extract_broad_reach_dns,
    ),
    QueryDefinition(
        name='broad_reach_tls_sni',
        label='Broad-Reach TLS/SNI Names (SSL handshakes)',
        sql_template=_SQL_BROAD_REACH_TLS_SNI,
        _extract_impl=_extract_broad_reach_tls_sni,
    ),
    QueryDefinition(
        name='broad_reach_http',
        label='Broad-Reach HTTP Hosts (HTTP sessions)',
        sql_template=_SQL_BROAD_REACH_HTTP,
        _extract_impl=_extract_broad_reach_http,
    ),
    QueryDefinition(
        name='benign_beacons',
        label='Vectra-Labeled Non-C2 Beacons (beacon analysis)',
        sql_template=_SQL_BENIGN_BEACONS,
        _extract_impl=_extract_benign_beacons,
    ),
    QueryDefinition(
        name='shared_auth_ips',
        label='Shared M365 Authentication IPs (sign-in logs)',
        sql_template=_SQL_SHARED_AUTH_IPS,
        _extract_impl=_extract_shared_auth_ips,
    ),
]
