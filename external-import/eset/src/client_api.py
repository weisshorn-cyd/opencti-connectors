"""Client for the new ESET Threat Intelligence (ETI) REST API (v2).

The old ETI portal (session-token login via ``POST /auth/``, XML responses,
TAXII 1.x collection polling via ``cabby``) was decommissioned at the end of
2024. It has been replaced by:

* A REST API (JSON) documented via Swagger at
  https://eti.eset.com/docs/api/public/v2 (requires a logged-in ETI account
  to view). Authentication is a single, self-service "API Token" generated
  once from the portal (Admin Settings > Access Credentials) and sent as a
  standard ``Authorization: Bearer <token>`` header -- there is no more
  username/password login call.
  See: https://help.eset.com/eti_portal/en-US/api.html
       https://help.eset.com/eti_portal/en-US/access_credentials.html

* Raw IOC data feeds, now served as native STIX 2.1 objects over TAXII 2.1
  (discovery root ``https://taxii.eset.com/taxii2``), authenticated with a
  *separate* set of TAXII Basic-auth credentials. ESET's own integration
  guide for OpenCTI (KB8315) recommends pointing OpenCTI's built-in,
  generic "TAXII 2.1" connector directly at that discovery root rather than
  reimplementing TAXII polling here, so this connector no longer embeds a
  TAXII client -- see the README for how to set that up alongside this
  connector.

This module therefore only has to talk REST/JSON, for APT / threat reports
and the indicators of compromise (IOCs) embedded in them.

NOTE: The exact JSON field names below (``REPORTS_PATH`` response shape,
report detail fields, IOC object shape) are ESET's public, documented REST
conventions as far as they're described outside the login-gated Swagger UI.
Before relying on this in production, open
https://eti.eset.com/docs/api/public/v2 with your own ETI account once and
confirm the field names in ``_report_from_json`` / ``iter_reports`` /
``iter_report_iocs`` below still match -- adjust the few ``.get(...)`` keys
there if your tenant's schema differs. Everything is written defensively
(``dict.get`` with fallbacks, tolerant of missing keys) specifically so that
a small field-name tweak is the only thing that should ever be needed.
"""

import time
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_BASE_URL = "https://eti.eset.com/api/public/v2"

# ESET's Fair Use Policy caps the ETI API at 180 requests/minute/user.
# See https://help.eset.com/eti_portal/en-US/fair_use_policy.html
MIN_SECONDS_BETWEEN_CALLS = 60 / 170  # small safety margin under the cap

REPORT_TYPES = ["all", "sample", "targeted", "botnet", "phish", "cert"]


class ETIApiError(Exception):
    """Raised for any non-recoverable error talking to the ETI API."""


class ETIAuthError(ETIApiError):
    """Raised when the API token is missing, invalid or expired."""


class EtiApiClient:
    """Thin wrapper around the ESET Threat Intelligence v2 REST API."""

    def __init__(
        self,
        helper,
        api_url: str = DEFAULT_BASE_URL,
        api_key: str = None,
    ):
        self.helper = helper
        self.api_url = api_url.rstrip("/")
        if not api_key:
            raise ETIAuthError("An ESET API token (ESET_API_KEY) is required.")
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
            }
        )
        # Retry on transient failures and on 429 (rate limit), honouring
        # any Retry-After header the API sends back.
        retries = Retry(
            total=5,
            backoff_factor=2,
            status_forcelist=[429, 500, 502, 503, 504],
            respect_retry_after_header=True,
            allowed_methods=["GET"],
        )
        adapter = HTTPAdapter(max_retries=retries)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self._last_call_at = 0.0

    # ------------------------------------------------------------------
    # Low-level request helper
    # ------------------------------------------------------------------
    def _throttle(self):
        """Self-imposed pacing so we stay comfortably under the 180/min cap."""
        elapsed = time.time() - self._last_call_at
        if elapsed < MIN_SECONDS_BETWEEN_CALLS:
            time.sleep(MIN_SECONDS_BETWEEN_CALLS - elapsed)

    def _get(self, path: str, params: Optional[dict] = None) -> Any:
        self._throttle()
        url = f"{self.api_url}/{path.lstrip('/')}"
        try:
            response = self.session.get(url, params=params, timeout=60)
        except requests.RequestException as err:
            raise ETIApiError(f"Failed to reach {url}: {err}") from err
        finally:
            self._last_call_at = time.time()

        if response.status_code in (401, 403):
            raise ETIAuthError(
                f"ESET API rejected the request ({response.status_code}) at "
                f"{url}. Check that ESET_API_KEY is a valid, non-expired "
                "API Token generated from Admin Settings > Access "
                "Credentials in the ETI portal."
            )
        if not response.ok:
            raise ETIApiError(
                f"ESET API error {response.status_code} at {url}: "
                f"{response.text[:500]}"
            )
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError as err:
            raise ETIApiError(
                f"Expected JSON from {url}, got non-JSON response."
            ) from err

    def _get_binary(self, path: str) -> bytes:
        self._throttle()
        url = f"{self.api_url}/{path.lstrip('/')}"
        try:
            response = self.session.get(url, timeout=120)
        except requests.RequestException as err:
            raise ETIApiError(f"Failed to reach {url}: {err}") from err
        finally:
            self._last_call_at = time.time()
        if not response.ok:
            raise ETIApiError(
                f"ESET API error {response.status_code} downloading {url}"
            )
        return response.content

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    def iter_reports(
        self,
        report_type: str = "all",
        date_from: Optional[datetime] = None,
        page_size: int = 50,
    ) -> Iterator[dict]:
        """Yields report summary dicts newer than *date_from*, handling pagination.

        Tolerant of a couple of common REST pagination shapes: either a
        top-level list, or an object with a ``results``/``items``/``data``
        list plus a ``next``/``next_page`` cursor.
        """
        if report_type not in REPORT_TYPES:
            raise ValueError(
                f"Unknown report type '{report_type}', must be one of {REPORT_TYPES}"
            )
        params = {"page_size": page_size}
        if date_from is not None:
            # ISO-8601 UTC, matching the "added_after" style filter ESET
            # documents for its feeds/report filters.
            params["date_from"] = date_from.astimezone(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            ) + "Z"

        page = 1
        next_cursor = None
        while True:
            request_params = dict(params)
            if next_cursor:
                request_params["page"] = next_cursor
            else:
                request_params["page"] = page
            data = self._get(f"reports/{report_type}", params=request_params)
            if data is None:
                return
            if isinstance(data, list):
                items = data
                next_cursor = None
            else:
                items = (
                    data.get("results")
                    or data.get("items")
                    or data.get("data")
                    or []
                )
                next_cursor = data.get("next") or data.get("next_page")
            if not items:
                return
            for item in items:
                yield item
            if not next_cursor:
                if isinstance(data, list) and len(items) == page_size:
                    page += 1
                    continue
                return
            page += 1

    def get_report(self, report_id) -> dict:
        """Fetches the full detail of a single report, including its IOC list."""
        data = self._get(f"reports/{report_id}")
        if data is None:
            raise ETIApiError(f"Report {report_id} not found.")
        return data

    def download_report_pdf(self, report_id) -> Optional[bytes]:
        """Downloads the PDF artifact for a report, if one is available."""
        try:
            return self._get_binary(f"reports/{report_id}/pdf")
        except ETIApiError as err:
            self.helper.connector_logger.warning(
                f"Could not download PDF for report {report_id}: {err}"
            )
            return None

    @staticmethod
    def iter_report_iocs(report: dict) -> Iterator[dict]:
        """Normalizes the IOC list embedded in a report detail payload.

        Expected shape per IOC: ``{"type": "domain|url|ip|md5|sha1|sha256",
        "value": "..."}``. Falls back gracefully if the key holding the list
        is named differently on your tenant (``iocs`` vs ``indicators``).
        """
        iocs = report.get("iocs") or report.get("indicators") or []
        for ioc in iocs:
            if isinstance(ioc, dict) and ioc.get("value"):
                yield ioc
