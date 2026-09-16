"""
Vectra Metadata SQL client — Python port of:
  vectra/scripts/metadata/vectra-metadata-sql.sh   (native bearer)
  common/darkstar_metadata_search.py               (Cantina/Darkstar)

Auth mode selection (evaluated at init):
  1. Cantina/Darkstar  — CANTINA_TOKEN + VECTRA_METADATA_CUSTOMER
  2. Native OAuth2     — VECTRA_NDR_URL + VECTRA_NDR_CLIENT_ID + SECRET
  3. Native pre-issued — VECTRA_NDR_URL + VECTRA_NDR_TOKEN

Docs: vectra/reference/metadata/execution.md
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
from typing import Any

import requests


class VectraMetadataError(Exception):
    """Raised for all client-level failures (auth, network, query errors)."""


class VectraMetadataClient:
    """Execute read-only Trino SQL against the Vectra Metadata engine."""

    POLL_INTERVAL_SEC: int = 10
    DEFAULT_TIMEOUT_SEC: int = 180

    # Ordered paths searched in Cantina responses for result rows.
    # Mirrors ROW_PATHS in darkstar_metadata_search.py.
    _ROW_PATHS: tuple[tuple[str, ...], ...] = (
        ('results',), ('rows',), ('data',),
        ('data', 'results'), ('data', 'rows'), ('data', 'data'),
        ('result', 'results'), ('result', 'rows'),
        ('response', 'results'), ('response', 'rows'),
        ('body', 'results'), ('body', 'rows'),
    )

    def __init__(
        self,
        *,
        # Cantina/Darkstar
        cantina_token: str = '',
        cantina_user: str = '',
        cantina_url: str = 'https://cantina.vectra.ai/api/darkstar/lambda',
        cantina_customer: str = '',
        # Native Vectra API
        vectra_ndr_url: str = '',
        vectra_client_id: str = '',
        vectra_client_secret: str = '',
        vectra_token: str = '',
        # Timeout
        timeout_sec: int = DEFAULT_TIMEOUT_SEC,
        logger: Any = None,
    ) -> None:
        self._cantina_token = cantina_token.strip()
        self._cantina_user = cantina_user.strip()
        self._cantina_url = cantina_url.rstrip('/')
        self._cantina_customer = cantina_customer.strip()

        self._ndr_url = vectra_ndr_url.rstrip('/')
        self._client_id = vectra_client_id.strip()
        self._client_secret = vectra_client_secret.strip()
        self._static_token = vectra_token.strip()

        self._timeout = timeout_sec
        self._log = logger or _NoOpLogger()

        # OAuth2 token cache
        self._bearer_token: str | None = None
        self._token_expiry: float = 0.0

        # Detect auth mode
        if self._cantina_token and self._cantina_customer:
            self._mode = 'cantina'
        elif self._ndr_url and (self._static_token or
                                (self._client_id and self._client_secret)):
            self._mode = 'native'
        else:
            raise VectraMetadataError(
                "Vectra metadata not configured. "
                "Set CANTINA_TOKEN + VECTRA_METADATA_CUSTOMER "
                "OR VECTRA_NDR_URL + (VECTRA_NDR_CLIENT_ID + VECTRA_NDR_CLIENT_SECRET "
                "or VECTRA_NDR_TOKEN)."
            )

        self._log.info(f"[metadata-client] auth mode: {self._mode}")

    # ── OAuth2 token management ───────────────────────────────────────────────

    def _get_bearer_token(self) -> str:
        if self._static_token:
            return self._static_token

        now = time.monotonic()
        if self._bearer_token and now < self._token_expiry - 60:
            return self._bearer_token

        # Token URL: strip /api/vX.Y from NDR URL, append /oauth2/token
        base = re.sub(r'/api/v\d+(\.\d+)?/?$', '', self._ndr_url)
        token_url = (
            os.environ.get('VECTRA_NDR_TOKEN_URL')
            or f"{base}/oauth2/token"
        )

        basic = base64.b64encode(
            f"{self._client_id}:{self._client_secret}".encode()
        ).decode()
        try:
            resp = requests.post(
                token_url,
                data={'grant_type': 'client_credentials'},
                headers={
                    'Authorization': f'Basic {basic}',
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                timeout=30,
            )
            resp.raise_for_status()
            data: dict = resp.json()
        except requests.RequestException as exc:
            raise VectraMetadataError(f"OAuth2 token fetch failed: {exc}") from exc

        token = data.get('access_token')
        if not token:
            raise VectraMetadataError(
                f"No access_token in OAuth2 response: {str(data)[:200]}"
            )

        expires_in = int(data.get('expires_in') or 3600)
        self._bearer_token = token
        self._token_expiry = time.monotonic() + expires_in
        self._log.debug(
            f"[metadata-client] token refreshed, expires_in={expires_in}s"
        )
        return token

    def _auth_headers(self) -> dict[str, str]:
        return {
            'Authorization': f'Bearer {self._get_bearer_token()}',
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

    # ── native Vectra v3.4 API ────────────────────────────────────────────────

    def _native_execute(self, sql: str) -> list[dict]:
        """Submit → poll → return rows via the /api/v3.4/investigations endpoint."""
        headers = self._auth_headers()

        # Submit
        try:
            submit = requests.post(
                f'{self._ndr_url}/investigations',
                headers=headers,
                json={'query': sql, 'version': '1.0'},
                timeout=30,
            )
            submit.raise_for_status()
        except requests.RequestException as exc:
            raise VectraMetadataError(f"Query submit failed: {exc}") from exc

        submit_data: dict = submit.json()
        request_id = (
            submit_data.get('requestId')
            or submit_data.get('request_id')
        )
        if not request_id:
            raise VectraMetadataError(
                f"No requestId in submit response: {str(submit_data)[:200]}"
            )
        self._log.debug(
            f"[metadata-client] query submitted requestId={request_id}"
        )

        # Poll until SUCCESS / FAILED / timeout
        deadline = time.monotonic() + self._timeout
        while time.monotonic() < deadline:
            time.sleep(self.POLL_INTERVAL_SEC)
            try:
                poll = requests.get(
                    f'{self._ndr_url}/investigations/{request_id}',
                    headers=headers,
                    timeout=30,
                )
            except requests.RequestException as exc:
                raise VectraMetadataError(f"Poll request failed: {exc}") from exc

            try:
                pd: dict = poll.json()
            except ValueError:
                # Non-JSON body: wrap raise_for_status so HTTPError becomes
                # VectraMetadataError and is caught by _process_query, not
                # the outer cycle handler (which would abort all remaining queries).
                try:
                    poll.raise_for_status()
                except requests.RequestException as http_exc:
                    raise VectraMetadataError(
                        f"Poll HTTP {poll.status_code}: {http_exc}"
                    ) from http_exc
                raise VectraMetadataError(
                    f"Poll returned non-JSON HTTP {poll.status_code}"
                )
            meta = pd.get('meta') or {}
            status = (
                meta.get('query_status') or meta.get('queryStatus')
                or pd.get('status') or ''
            ).upper()

            if status in ('SUCCESS', 'FINISHED'):
                return self._rows_from_native(pd)
            if status == 'FAILED':
                err = meta.get('error') or meta.get('error_message') or pd.get('error') or 'no detail'
                raise VectraMetadataError(f"Query FAILED: {err}")
            if status not in ('RUNNING', 'PENDING', 'PROCESSING'):
                raise VectraMetadataError(
                    f"Unexpected query status '{status}': {str(pd)[:200]}"
                )

        raise VectraMetadataError(
            f"Query timed out after {self._timeout}s — add tighter filters or "
            "raise VECTRA_FP_QUERY_TIMEOUT_SEC"
        )

    @staticmethod
    def _rows_from_native(response: dict) -> list[dict]:
        """Extract result rows from a v3.4 investigations response."""
        results = response.get('results')
        if isinstance(results, list):
            data = results
        elif isinstance(results, dict):
            data = results.get('data') or results.get('rows') or []
        else:
            data = response.get('data') or []
        return data if isinstance(data, list) else []

    # ── Cantina / Darkstar ────────────────────────────────────────────────────

    def _cantina_execute(self, sql: str) -> list[dict]:
        """Single-call Darkstar execution via the rux-investigate function."""
        # Infer metadata sources from table prefixes in SQL
        sources: list[str] = []
        lower = sql.lower()
        for prefix, source in (
            ('network.', 'network'),
            ('m365.', 'o365'),
            ('aws.', 'aws'),
            ('azurecp.', 'azurecp'),
        ):
            if prefix in lower and source not in sources:
                sources.append(source)

        function_name = os.environ.get(
            'CANTINA_METADATA_FUNCTION_NAME', 'rux-investigate'
        )
        payload: dict[str, Any] = {
            'functionName': function_name,
            'data': {
                'customer': self._cantina_customer,
                'query': sql,
            },
        }
        if sources:
            payload['data']['metadata_sources'] = sources
        if self._cantina_user:
            payload['data']['cantina_user'] = self._cantina_user

        try:
            resp = requests.post(
                self._cantina_url,
                headers={
                    'authorization': f'Token {self._cantina_token}',
                    'content-type': 'application/json',
                    'accept': 'application/json',
                },
                json=payload,
                timeout=self._timeout,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise VectraMetadataError(f"Cantina request failed: {exc}") from exc

        raw: dict = resp.json()

        # Handle optional outer statusCode envelope
        outer_status = raw.get('statusCode')
        body = raw.get('body', raw)
        if isinstance(body, str):
            try:
                body = json.loads(body)
            except (ValueError, TypeError):
                pass

        if isinstance(outer_status, int) and outer_status >= 400:
            detail = body.get('error') if isinstance(body, dict) else str(body)
            raise VectraMetadataError(
                f"Cantina HTTP {outer_status}: {detail}"
            )
        if isinstance(body, dict) and body.get('error'):
            raise VectraMetadataError(f"Cantina error: {body['error']}")

        return self._rows_from_cantina(body)

    def _rows_from_cantina(self, body: Any) -> list[dict]:
        """Walk ROW_PATHS to find result rows in a Darkstar response body."""
        if isinstance(body, list):
            return body
        if not isinstance(body, dict):
            return []

        for path in self._ROW_PATHS:
            val: Any = body
            for key in path:
                if not isinstance(val, dict):
                    val = None
                    break
                raw_val = val.get(key)
                if isinstance(raw_val, str):
                    try:
                        raw_val = json.loads(raw_val)
                    except (ValueError, TypeError):
                        pass
                val = raw_val
            if isinstance(val, list) and val:
                return val

        return []

    # ── public interface ──────────────────────────────────────────────────────

    def execute(self, sql: str) -> list[dict]:
        """Execute a read-only Trino SQL query and return rows as dicts."""
        if self._mode == 'cantina':
            return self._cantina_execute(sql)
        return self._native_execute(sql)

    @property
    def mode(self) -> str:
        return self._mode


class _NoOpLogger:
    def info(self, msg: str) -> None: pass
    def debug(self, msg: str) -> None: pass
    def warning(self, msg: str) -> None: pass
    def error(self, msg: str) -> None: pass
