from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import requests
from requests import Response

OSV_API_URL = "https://api.osv.dev/v1/query"


class OSVClientError(Exception):
    """Base class for OSV client errors."""


class OSVNetworkError(OSVClientError):
    """Raised when network-related errors occur."""


class OSVRateLimitError(OSVClientError):
    """Raised when the API appears to be rate limited."""


class OSVClient:
    """
    Minimal OSV API client with basic retry and timeout handling.
    """

    def __init__(
        self,
        base_url: str = OSV_API_URL,
        timeout_seconds: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 1.5,
    ) -> None:
        self.base_url = base_url
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self._session = requests.Session()

    def _handle_response(self, resp: Response) -> Dict[str, Any]:
        if resp.status_code == 429:
            raise OSVRateLimitError("OSV API rate limited (HTTP 429).")
        if resp.status_code >= 500:
            raise OSVNetworkError(
                f"OSV API server error: {resp.status_code} {resp.text}"
            )
        if resp.status_code >= 400:
            raise OSVClientError(
                f"OSV API client error: {resp.status_code} {resp.text}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise OSVClientError("Failed to decode OSV response as JSON.") from exc

    def query(self, package_name: str, version: str, ecosystem: str = "PyPI") -> Dict[str, Any]:
        """
        Query OSV for a specific package version.

        Implements simple exponential backoff for transient network and 5xx errors.
        """
        payload = {
            "package": {"name": package_name, "ecosystem": ecosystem},
            "version": version,
        }

        attempt = 0
        last_error: Optional[Exception] = None

        while attempt < self.max_retries:
            try:
                resp = self._session.post(
                    self.base_url,
                    json=payload,
                    timeout=self.timeout_seconds,
                )
                return self._handle_response(resp)
            except (requests.Timeout, requests.ConnectionError) as exc:
                last_error = OSVNetworkError(f"Network error contacting OSV: {exc}")
            except OSVNetworkError as exc:
                # treat server-side 5xx as retriable
                last_error = exc
            except OSVRateLimitError:
                # back off more aggressively on rate limiting
                last_error = OSVRateLimitError(
                    "Rate limit encountered when querying OSV API."
                )
                # we still sleep / retry in case transient
            except OSVClientError as exc:
                # 4xx errors are not retriable
                raise exc

            attempt += 1
            sleep_for = self.backoff_factor ** attempt
            time.sleep(sleep_for)

        assert last_error is not None  # for type checkers
        raise last_error


def extract_vulns_from_osv_response(resp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Normalize the OSV response a bit.

    OSV returns a `vulns` list (and sometimes `results`); we focus on `vulns`.
    """
    vulns = resp.get("vulns") or []
    if not isinstance(vulns, list):
        return []
    return [v for v in vulns if isinstance(v, dict)]

