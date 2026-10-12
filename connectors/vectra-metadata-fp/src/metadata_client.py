"""Vectra Metadata client with structured query outcomes and result pagination."""
from __future__ import annotations

import base64
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any

import requests


class VectraMetadataError(Exception):
    pass


@dataclass
class QueryResult:
    status: str
    rows: list[dict] = field(default_factory=list)
    error_kind: str = ""
    error_message: str = ""
    partial: bool = False
    truncated: bool = False
    available_rows: int | None = None
    pages_fetched: int = 0
    retry_count: int = 0
    runtime_seconds: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status in {"ok", "zero"}


class VectraMetadataClient:
    """Execute read-only Trino SQL against native Vectra or Cantina."""

    _ROW_PATHS = (
        ("results",), ("rows",), ("data",), ("data", "results"),
        ("data", "rows"), ("data", "data"), ("result", "results"),
        ("result", "rows"), ("response", "results"), ("response", "rows"),
        ("body", "results"), ("body", "rows"),
    )

    def __init__(self, *, cantina_token: str = "", cantina_user: str = "",
                 cantina_url: str = "https://cantina.vectra.ai/api/darkstar/lambda",
                 cantina_customer: str = "", vectra_ndr_url: str = "",
                 vectra_client_id: str = "", vectra_client_secret: str = "",
                 vectra_token: str = "", timeout_sec: int = 180,
                 poll_interval_sec: float = 5, page_size: int = 1000,
                 max_pages: int = 200, max_retries: int = 2, logger: Any = None) -> None:
        self._cantina_token = cantina_token.strip()
        self._cantina_user = cantina_user.strip()
        self._cantina_url = cantina_url.rstrip("/")
        self._cantina_customer = cantina_customer.strip()
        self._ndr_url = vectra_ndr_url.rstrip("/")
        self._client_id = vectra_client_id.strip()
        self._client_secret = vectra_client_secret.strip()
        self._static_token = vectra_token.strip()
        self._timeout = timeout_sec
        self._poll_interval = poll_interval_sec
        self._page_size = max(1, page_size)
        self._max_pages = max(1, max_pages)
        self._max_retries = max(0, max_retries)
        self._log = logger or _NoOpLogger()
        self._bearer_token: str | None = None
        self._token_expiry = 0.0
        if self._cantina_token and self._cantina_customer:
            self._mode = "cantina"
        elif self._ndr_url and (self._static_token or (self._client_id and self._client_secret)):
            self._mode = "native"
        else:
            raise VectraMetadataError("Vectra Metadata credentials are not configured")

    @property
    def mode(self) -> str:
        return self._mode

    def execute(self, sql: str) -> list[dict]:
        result = self.execute_result(sql)
        if not result.ok and not result.partial:
            raise VectraMetadataError(f"{result.error_kind}: {result.error_message}")
        return result.rows

    def execute_result(self, sql: str) -> QueryResult:
        started = time.monotonic()
        try:
            result = self._cantina_execute(sql) if self._mode == "cantina" else self._native_execute(sql)
        except requests.RequestException as exc:
            result = QueryResult("error", error_kind="http", error_message=str(exc))
        except (ValueError, TypeError, KeyError) as exc:
            result = QueryResult("error", error_kind="invalid_response", error_message=str(exc))
        result.runtime_seconds = round(time.monotonic() - started, 3)
        return result

    def _get_bearer_token(self, force: bool = False) -> str:
        if self._static_token:
            return self._static_token
        now = time.monotonic()
        if not force and self._bearer_token and now < self._token_expiry - 60:
            return self._bearer_token
        base = re.sub(r"/api/v\d+(?:\.\d+)?/?$", "", self._ndr_url)
        token_url = os.environ.get("VECTRA_NDR_TOKEN_URL") or f"{base}/oauth2/token"
        basic = base64.b64encode(f"{self._client_id}:{self._client_secret}".encode()).decode()
        response = requests.post(token_url, data={"grant_type": "client_credentials"}, headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        }, timeout=30)
        response.raise_for_status()
        data = response.json()
        token = data.get("access_token")
        if not token:
            raise ValueError("OAuth response has no access_token")
        self._bearer_token = token
        self._token_expiry = now + int(data.get("expires_in") or 3600)
        return token

    def _headers(self, force: bool = False) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._get_bearer_token(force)}", "Accept": "application/json"}

    def _request(self, method: str, url: str, **kwargs) -> tuple[requests.Response, int]:
        retries = 0
        while True:
            response = requests.request(method, url, **kwargs)
            if response.status_code == 401 and retries < self._max_retries and self._mode == "native":
                retries += 1
                kwargs["headers"] = self._headers(force=True)
                continue
            if response.status_code == 429 and retries < self._max_retries:
                retries += 1
                wait = int(response.headers.get("Retry-After") or 1)
                time.sleep(min(max(wait, 1), 30))
                continue
            response.raise_for_status()
            return response, retries

    def _native_execute(self, sql: str) -> QueryResult:
        submit, retries = self._request("POST", f"{self._ndr_url}/investigations",
                                        headers={**self._headers(), "Content-Type": "application/json"},
                                        json={"query": sql, "version": "1.0"}, timeout=30)
        request_id = submit.json().get("request_id") or submit.json().get("requestId")
        if not request_id:
            return QueryResult("error", error_kind="unexpected_schema", error_message="missing request_id", retry_count=retries)
        poll_url = f"{self._ndr_url}/investigations/{request_id}"
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            time.sleep(self._poll_interval)
            try:
                response, poll_retries = self._request(
                    "GET", poll_url, headers=self._headers(),
                    params={"page": 1, "page_size": self._page_size}, timeout=30,
                )
                retries += poll_retries
                payload = response.json()
            except requests.RequestException as exc:
                return QueryResult("error", error_kind="poll_http", error_message=str(exc), retry_count=retries)
            except ValueError:
                return QueryResult("error", error_kind="invalid_json", error_message="poll response was not JSON", retry_count=retries)
            if payload.get("error"):
                return QueryResult("error", error_kind="sql_error", error_message=str(payload["error"]), retry_count=retries)
            meta = payload.get("meta") or {}
            status = str(meta.get("query_status") or meta.get("queryStatus") or payload.get("status") or "").upper()
            if "data" in payload or status in {"SUCCESS", "FINISHED"}:
                return self._collect_native_pages(poll_url, payload, retries)
            if status == "FAILED":
                return QueryResult("error", error_kind="sql_error", error_message=str(meta.get("error") or "query failed"), retry_count=retries)
            if status and status not in {"RUNNING", "PENDING", "PROCESSING"}:
                return QueryResult("error", error_kind="unexpected_status", error_message=status, retry_count=retries)
        return QueryResult("error", error_kind="timeout", error_message=f"timed out after {self._timeout}s", retry_count=retries)

    def _collect_native_pages(self, url: str, first: dict, retries: int) -> QueryResult:
        rows = self._rows_from_native(first)
        meta = first.get("meta") or {}
        available = int(meta.get("num_rows_available") or len(rows))
        page_size = int(meta.get("page_size") or self._page_size)
        pages = max(1, (available + page_size - 1) // page_size)
        pages_fetched = 1
        for page in range(2, min(pages, self._max_pages) + 1):
            try:
                response, page_retries = self._request("GET", url, headers=self._headers(),
                                                       params={"page": page, "page_size": page_size}, timeout=30)
                retries += page_retries
                rows.extend(self._rows_from_native(response.json()))
                pages_fetched += 1
            except (requests.RequestException, ValueError) as exc:
                return QueryResult("partial", rows, "page_fetch_failed", str(exc), True, True,
                                   available, pages_fetched, retries)
        truncated = len(rows) < available
        status = "partial" if truncated else ("zero" if not rows else "ok")
        return QueryResult(status, rows, "max_pages" if truncated else "", "", truncated, truncated,
                           available, pages_fetched, retries)

    @staticmethod
    def _rows_from_native(response: dict) -> list[dict]:
        results = response.get("results")
        if isinstance(results, list):
            return results
        if isinstance(results, dict):
            rows = results.get("data") or results.get("rows") or []
            return rows if isinstance(rows, list) else []
        rows = response.get("data") or []
        return rows if isinstance(rows, list) else []

    def _cantina_execute(self, sql: str) -> QueryResult:
        lower = sql.lower()
        sources = [source for prefix, source in (("network.", "network"), ("m365.", "o365")) if prefix in lower]
        payload: dict[str, Any] = {"functionName": os.environ.get("CANTINA_METADATA_FUNCTION_NAME", "rux-investigate"),
                                   "data": {"customer": self._cantina_customer, "query": sql}}
        if sources:
            payload["data"]["metadata_sources"] = sources
        if self._cantina_user:
            payload["data"]["cantina_user"] = self._cantina_user
        response, retries = self._request("POST", self._cantina_url, headers={
            "authorization": f"Token {self._cantina_token}", "content-type": "application/json",
        }, json=payload, timeout=self._timeout)
        body: Any = response.json().get("body", response.json())
        if isinstance(body, str):
            body = json.loads(body)
        if isinstance(body, dict) and body.get("error"):
            return QueryResult("error", error_kind="sql_error", error_message=str(body["error"]), retry_count=retries)
        rows = self._rows_from_cantina(body)
        return QueryResult("zero" if not rows else "ok", rows, available_rows=len(rows), pages_fetched=1, retry_count=retries)

    def _rows_from_cantina(self, body: Any) -> list[dict]:
        if isinstance(body, list):
            return body
        if not isinstance(body, dict):
            return []
        for path in self._ROW_PATHS:
            value: Any = body
            for key in path:
                if not isinstance(value, dict):
                    value = None
                    break
                value = value.get(key)
                if isinstance(value, str):
                    try:
                        value = json.loads(value)
                    except ValueError:
                        pass
            if isinstance(value, list):
                return value
        return []


class _NoOpLogger:
    def info(self, _msg: str) -> None: pass
    def debug(self, _msg: str) -> None: pass
    def warning(self, _msg: str) -> None: pass
    def error(self, _msg: str) -> None: pass
