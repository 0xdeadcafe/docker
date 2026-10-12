"""Validated Vectra Metadata query contract for endpoint commonness."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator

BATCH_SIZE = 50
DISCOVERY_LIMIT = 500
WINDOW_COUNT = 3

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SKIP_SUFFIXES = (
    ".arpa", ".local", ".internal", ".corp", ".lan", ".home",
    ".test", ".example", ".invalid", ".localhost",
)


def normalize_domain(value: object) -> str | None:
    value = str(value or "").strip().lower().rstrip(".")
    if not value or len(value) > 253 or "." not in value or value.endswith(_SKIP_SUFFIXES):
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    labels = value.split(".")
    return value if all(_DOMAIN_LABEL_RE.fullmatch(label) for label in labels) else None


def normalize_ipv4(value: object) -> str | None:
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    return str(address) if address.version == 4 and address.is_global else None


def batches(values: Iterable[str], size: int = BATCH_SIZE) -> Iterator[list[str]]:
    if not 1 <= size <= BATCH_SIZE:
        raise ValueError(f"batch size must be between 1 and {BATCH_SIZE}")
    ordered = sorted(set(values))
    for index in range(0, len(ordered), size):
        yield ordered[index:index + size]


@dataclass(frozen=True)
class Window:
    id: str
    start: datetime
    end: datetime


def build_windows(anchor: datetime | None = None, lookback_days: int = 30) -> tuple[Window, ...]:
    if lookback_days <= 0 or lookback_days % WINDOW_COUNT:
        raise ValueError("lookback days must be positive and divisible by 3")
    anchor = (anchor or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(second=0, microsecond=0)
    width = timedelta(days=lookback_days // WINDOW_COUNT)
    start = anchor - timedelta(days=lookback_days)
    return tuple(Window(f"w{i + 1}", start + width * i, start + width * (i + 1)) for i in range(WINDOW_COUNT))


@dataclass(frozen=True)
class Observation:
    signal: str
    observable_type: str
    value: str
    window_id: str
    breadth: int
    event_count: int
    first_seen: str
    last_seen: str


@dataclass(frozen=True)
class QueryDefinition:
    name: str
    observable_type: str
    table: str
    event_time: str
    candidate_expression: str
    breadth_expression: str
    threshold: int
    discovery: bool
    extra_where: str = ""

    @property
    def normalizer(self):
        return normalize_domain if self.observable_type == "Domain-Name" else normalize_ipv4

    def build_targeted(self, candidates: Iterable[str], windows: tuple[Window, ...]) -> str:
        candidates = [value for value in (self.normalizer(v) for v in candidates) if value]
        if not candidates or len(candidates) > BATCH_SIZE:
            raise ValueError(f"targeted query requires 1-{BATCH_SIZE} valid candidates")
        return self._build(windows, candidates)

    def build_discovery(self, windows: tuple[Window, ...], limit: int = DISCOVERY_LIMIT) -> str:
        if not self.discovery:
            raise ValueError(f"unsupported discovery query shape: {self.name}")
        if not 1 <= limit <= DISCOVERY_LIMIT:
            raise ValueError(f"discovery limit must be between 1 and {DISCOVERY_LIMIT}")
        return self._build(windows, None, limit)

    def _build(self, windows: tuple[Window, ...], candidates: list[str] | None, limit: int = DISCOVERY_LIMIT) -> str:
        if len(windows) != WINDOW_COUNT:
            raise ValueError("exactly three windows are required")
        start, end = windows[0].start, windows[-1].end
        win = (
            f"CASE WHEN {self.event_time} < {_timestamp(windows[0].end)} THEN 'w1' "
            f"WHEN {self.event_time} < {_timestamp(windows[1].end)} THEN 'w2' ELSE 'w3' END"
        )
        target = ""
        if candidates is not None:
            quoted = ",".join(f"'{value}'" for value in candidates)
            target = f"\n  AND {self.candidate_expression} IN ({quoted})"
        having = ""
        if candidates is None:
            having = f"\nHAVING COUNT(DISTINCT {self.breadth_expression}) >= {self.threshold}"
        return f"""SELECT
    {self.candidate_expression} AS candidate,
    {win} AS window_id,
    COUNT(DISTINCT {self.breadth_expression}) AS breadth,
    COUNT(*) AS event_count,
    MIN({self.event_time}) AS first_seen,
    MAX({self.event_time}) AS last_seen
FROM {self.table}
WHERE dt >= {_timestamp(start)}
  AND dt < {_timestamp(end)}
  AND {self.event_time} >= {_timestamp(start)}
  AND {self.event_time} < {_timestamp(end)}{self.extra_where}{target}
GROUP BY {self.candidate_expression}, {win}{having}
ORDER BY breadth DESC, event_count DESC
LIMIT {limit}"""

    def observations(self, rows: Iterable[dict]) -> list[Observation]:
        observations = []
        for row in rows:
            value = self.normalizer(row.get("candidate"))
            window_id = str(row.get("window_id") or "")
            if not value or window_id not in {"w1", "w2", "w3"}:
                continue
            observations.append(Observation(
                signal=self.name,
                observable_type=self.observable_type,
                value=value,
                window_id=window_id,
                breadth=int(row.get("breadth") or 0),
                event_count=int(row.get("event_count") or 0),
                first_seen=str(row.get("first_seen") or ""),
                last_seen=str(row.get("last_seen") or ""),
            ))
        return observations


def _timestamp(value: datetime) -> str:
    return f"from_iso8601_timestamp('{value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')}')"


_PRIVATE_DESTINATION_FILTER = """
  AND NOT REGEXP_LIKE(id.resp_h,
      '^(10[.]|192[.]168[.]|172[.](1[6-9]|2[0-9]|3[01])[.]|127[.]|169[.]254[.])')"""

TARGETED_QUERIES = (
    QueryDefinition(
        "dns", "Domain-Name", "network.dns._all", "timestamp",
        "lower(regexp_replace(query, '[.]$', ''))", "id.orig_h", 10, False,
    ),
    QueryDefinition(
        "sni", "Domain-Name", "network.ssl._all", "timestamp",
        "lower(regexp_replace(server_name, '[.]$', ''))", "id.orig_h", 10, False,
        _PRIVATE_DESTINATION_FILTER,
    ),
    QueryDefinition(
        "http", "Domain-Name", "network.http._all", "timestamp",
        "lower(regexp_replace(regexp_replace(host, ':[0-9]+$', ''), '[.]$', ''))",
        "id.orig_h", 10, True,
        _PRIVATE_DESTINATION_FILTER + "\n  AND status_code BETWEEN 200 AND 399",
    ),
    QueryDefinition(
        "m365", "IPv4-Addr", "m365.signins._all", "timestamp",
        "ip_address", "user_principal_name", 3, True,
        "\n  AND status.error_code = 0",
    ),
    QueryDefinition(
        "isession", "IPv4-Addr", "network.isession._all", "timestamp",
        "id.resp_h", "id.orig_h", 10, False,
        "\n  AND local_orig = TRUE AND local_resp = FALSE",
    ),
)
QUERY_BY_NAME = {query.name: query for query in TARGETED_QUERIES}
DISCOVERY_QUERIES = tuple(query for query in TARGETED_QUERIES if query.discovery)
