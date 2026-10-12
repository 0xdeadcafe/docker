"""Small in-process quota circuit and enrichment usage counter."""

import os
import time
from email.utils import parsedate_to_datetime

from prometheus_client import Counter, Gauge


_ENRICHMENT_TOTAL = None
_URL_REPUTATION_READY = None
QUOTA_TERMS = ("insufficient credit", "quota", "rate limit", "too many requests")


class QuotaExceeded(RuntimeError):
    def __init__(self, message, retry_after=None):
        super().__init__(message)
        self.retry_after = retry_after


class CircuitOpenError(RuntimeError):
    pass


def is_quota_error(message):
    return any(term in str(message or "").lower() for term in QUOTA_TERMS)


def retry_after_seconds(response, now=None):
    value = (getattr(response, "headers", {}) or {}).get("Retry-After")
    if not value:
        return None
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        try:
            timestamp = parsedate_to_datetime(value).timestamp()
            return max(1, int(timestamp - (now or time.time())))
        except (TypeError, ValueError, OverflowError):
            return None


def enrichment_counter():
    global _ENRICHMENT_TOTAL
    if _ENRICHMENT_TOTAL is None:
        _ENRICHMENT_TOTAL = Counter(
            "opencti_enrichment_requests",
            "On-demand enrichment outcomes",
            ("provider", "observable_type", "outcome"),
        )
    return _ENRICHMENT_TOTAL


def url_readiness_gauge():
    global _URL_REPUTATION_READY
    if _URL_REPUTATION_READY is None:
        _URL_REPUTATION_READY = Gauge(
            "opencti_url_reputation_provider_ready",
            "Whether a provider has Url scope and a closed quota circuit",
            ("provider",),
        )
    return _URL_REPUTATION_READY


class QuotaCircuit:
    def __init__(
        self, provider, helper, clock=time.monotonic, counter=None, readiness_gauge=None
    ):
        self.provider = provider.lower()
        self.display_name = "IPQS" if self.provider == "ipqs" else "VirusTotal"
        self.helper = helper
        self.clock = clock
        prefix = self.provider.upper()
        fallback = os.environ.get("ENRICHMENT_QUOTA_COOLDOWN_SECONDS", "3600")
        self.cooldown = self._bounded_int(
            os.environ.get(f"{prefix}_QUOTA_COOLDOWN_SECONDS", fallback), 3600
        )
        self.max_cooldown = self._bounded_int(
            os.environ.get("ENRICHMENT_QUOTA_MAX_COOLDOWN_SECONDS", "86400"), 86400
        )
        self.recent_seconds = self._bounded_int(
            os.environ.get(f"{prefix}_RECENT_ENRICHMENT_SECONDS", "300"), 300
        )
        self.counter = counter or enrichment_counter()
        self.url_capable = "url" in {
            scope.strip().lower()
            for scope in os.environ.get("CONNECTOR_SCOPE", "").split(",")
        }
        self.open_until = 0.0
        self.url_readiness = (readiness_gauge or url_readiness_gauge()).labels(
            provider=self.provider
        )
        self.url_readiness.set_function(
            lambda: int(self.url_capable and self.remaining() == 0)
        )
        self.recent_requests = {}

    @staticmethod
    def _bounded_int(value, default):
        try:
            return max(1, min(int(value), 86400))
        except (TypeError, ValueError):
            return default

    def _record(self, observable_type, outcome):
        self.counter.labels(
            provider=self.provider,
            observable_type=observable_type or "Unknown",
            outcome=outcome,
        ).inc()

    def remaining(self):
        remaining = int(self.open_until - self.clock())
        if remaining <= 0:
            self.open_until = 0.0
            return 0
        return remaining

    def reset(self):
        self.open_until = 0.0
        self.recent_requests.clear()

    def run(self, observable_type, operation, request_key=None):
        self._record(observable_type, "requested")
        remaining = self.remaining()
        if remaining:
            self._record(observable_type, "skipped")
            self._record(observable_type, "quota_blocked")
            message = (
                f"{self.display_name} enrichment skipped: provider quota circuit is open; "
                f"retry in {remaining}s or restart the connector after quota recovery."
            )
            self.helper.log_warning(message)
            raise CircuitOpenError(message)

        now = self.clock()
        previous = self.recent_requests.get(request_key) if request_key else None
        if previous is not None and now - previous < self.recent_seconds:
            self._record(observable_type, "skipped")
            message = (
                f"skipped: {self.display_name} enrichment for this object was already "
                f"requested in the last {self.recent_seconds}s"
            )
            self.helper.log_info(message)
            return message
        if request_key:
            if len(self.recent_requests) >= 10000:
                self.recent_requests.clear()
            self.recent_requests[request_key] = now

        self._record(observable_type, "executed")
        try:
            result = operation()
        except QuotaExceeded as exc:
            cooldown = min(exc.retry_after or self.cooldown, self.max_cooldown)
            self.open_until = self.clock() + cooldown
            self._record(observable_type, "failed")
            self._record(observable_type, "quota_blocked")
            message = (
                f"{self.display_name} quota exhausted; provider circuit opened for "
                f"{cooldown}s. Retry after quota recovery or restart the connector to reset."
            )
            self.helper.log_warning(message)
            raise CircuitOpenError(message) from exc
        except Exception:
            self._record(observable_type, "failed")
            raise

        text = str(result or "").lower()
        if text.startswith("skipped:"):
            self._record(observable_type, "skipped")
        elif "failed" in text or "api error" in text:
            self._record(observable_type, "failed")
        else:
            self._record(observable_type, "successful")
        return result
