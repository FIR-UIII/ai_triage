import logging
import sys
from typing import Dict, List, Optional

import requests
import urllib3
from tenacity import retry, stop_after_attempt, wait_exponential, before_sleep_log

from core.exceptions import DDApiError

# Suppress SSL warnings for self-signed corporate certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_DEBUG = "[DEBUG]"


def _DEBUG(msg: str, *args) -> None:
    formatted = msg % args if args else msg
    print(f"{_DEBUG} {formatted}", file=sys.stderr, flush=True)


# Default timeout for HTTP requests (connect, read) in seconds
_HTTP_TIMEOUT = (10, 30)


class DefectDojoClient:
    """DefectDojo REST API v2 client with automatic pagination and retry."""

    def __init__(self, api_url: str, api_key: str, verify_ssl: bool = False):
        self.api_url = api_url.rstrip("/")
        self.verify = verify_ssl
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Token {api_key}",
                "Content-Type": "application/json",
            }
        )
        _DEBUG("DDClient init: api_url=%s, verify_ssl=%s", self.api_url, self.verify)

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        before_sleep=before_sleep_log(logger, logging.WARNING),
    )
    def _get(self, url: str, params: Optional[Dict] = None) -> Dict:
        _DEBUG("HTTP GET %s params=%s verify=%s", url, params, self.verify)
        try:
            r = self.session.get(url, params=params, verify=self.verify, timeout=_HTTP_TIMEOUT)
            _DEBUG("HTTP GET %s -> status=%d", url, r.status_code)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.SSLError as e:
            _DEBUG("SSL ERROR on GET %s: %s", url, e)
            raise DDApiError(f"SSL error on GET {url}: {e}") from e
        except requests.exceptions.ConnectionError as e:
            _DEBUG("CONNECTION ERROR on GET %s: %s", url, e)
            raise DDApiError(f"Connection error on GET {url}: {e}") from e
        except requests.exceptions.Timeout as e:
            _DEBUG("TIMEOUT on GET %s: %s", url, e)
            raise DDApiError(f"Timeout on GET {url}: {e}") from e
        except requests.exceptions.RequestException as e:
            _DEBUG("REQUEST ERROR on GET %s: %s", url, e)
            raise DDApiError(f"GET {url} failed: {e}") from e

    def _paginate(self, url: str, params: Optional[Dict] = None) -> List[Dict]:
        """Fetch all pages of a paginated endpoint."""
        items: List[Dict] = []
        page = 1
        while url:
            _DEBUG("_paginate: page=%d, url=%s", page, url)
            data = self._get(url, params=params)
            results = data.get("results") or []
            items.extend(results)
            _DEBUG("_paginate: page=%d got %d results (total=%d)", page, len(results), len(items))
            url = data.get("next")
            params = None  # params only needed on first request
            page += 1
        _DEBUG("_paginate: done, total items=%d", len(items))
        return items

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_findings(self, test_id: int) -> List[Dict]:
        """
        Скачивает findings по test id для triage функции, т.е. для анализ актуальные и не закрытых сработок. 
        Фильтры: active=True, false_p=False
        """
        test_name = self.get_test_name(test_id)
        findings = self._paginate(
            f"{self.api_url}/api/v2/findings/",
            params= {
                "test": test_id,
                "false_p": False,
                "active": True,
                },
        )
        for f in findings:
            f["test_name"] = test_name
            self._dedup_vulnerability_ids(f)
        logger.info("Fetched %d findings for test %d", len(findings), test_id)
        return findings

    def fetch_false_positives_by_test_id(self, test_id: int) -> List[Dict]:
        """
        Загрузка False Positive findings. 
        Фильтры: false_p=True, active=False.
        """
        url = f"{self.api_url}/api/v2/findings/"
        params = {
            "test": test_id,
            "false_p": True,
            "active": False,
            "limit": 100,
        }
        _DEBUG("fetch_false_positives_by_test_id: test_id=%d, url=%s, params=%s",
                test_id, url, params)
        findings = self._paginate(url, params=params)
        for f in findings:
            self._dedup_vulnerability_ids(f)
        _DEBUG("fetch_false_positives_by_test_id: got %d findings", len(findings))
        logger.info(
            "Fetched %d false positives for test_id %d", len(findings), test_id
        )
        return findings

    def get_test_name(self, test_id: int) -> Optional[str]:
        try:
            data = self._get(f"{self.api_url}/api/v2/tests/{test_id}/")
            return data.get("test_type_name")
        except DDApiError as e:
            logger.warning("Could not get test name for test %d: %s", test_id, e)
            return None

    def add_comment(self, finding_id: int, comment: str) -> bool:
        """Post a note/comment to a finding."""
        try:
            r = self.session.post(
                f"{self.api_url}/api/v2/notes/",
                json={"entry": comment, "finding": finding_id},
                verify=self.verify,
            )
            r.raise_for_status()
            logger.info("Posted comment to finding %d", finding_id)
            return True
        except requests.exceptions.RequestException as e:
            logger.error("Failed to post comment to finding %d: %s", finding_id, e)
            return False

    @staticmethod
    def _dedup_vulnerability_ids(finding: Dict) -> None:
        """Remove duplicate vulnerability_id entries from a finding in-place."""
        vuln_ids = finding.get("vulnerability_ids")
        if not vuln_ids or not isinstance(vuln_ids, list):
            return
        seen = set()
        unique = []
        for v in vuln_ids:
            vid = v.get("vulnerability_id", "")
            if vid and vid not in seen:
                seen.add(vid)
                unique.append(v)
            elif not vid:
                unique.append(v)
        if len(unique) < len(vuln_ids):
            finding["vulnerability_ids"] = unique
