import logging
from typing import Dict, List, Optional

import requests
import urllib3
from tenacity import retry, stop_after_attempt, wait_exponential

from core.exceptions import DDApiError

# Suppress SSL warnings for self-signed corporate certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


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

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def _get(self, url: str, params: Optional[Dict] = None) -> Dict:
        try:
            r = self.session.get(url, params=params, verify=self.verify)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.RequestException as e:
            raise DDApiError(f"GET {url} failed: {e}") from e

    def _paginate(self, url: str, params: Optional[Dict] = None) -> List[Dict]:
        """Fetch all pages of a paginated endpoint."""
        items: List[Dict] = []
        while url:
            data = self._get(url, params=params)
            items.extend(data.get("results") or [])
            url = data.get("next")
            params = None  # params only needed on first request
        return items

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fetch_findings(self, test_id: int) -> List[Dict]:
        """Fetch all findings for a given test, enriched with test_name."""
        test_name = self.get_test_name(test_id)
        findings = self._paginate(
            f"{self.api_url}/api/v2/findings/",
            params={"test": test_id},
        )
        for f in findings:
            f["test_name"] = test_name
        logger.info("Fetched %d findings for test %d", len(findings), test_id)
        return findings

    def fetch_false_positives_by_product(self, product_id: int) -> List[Dict]:
        """Fetch all closed False Positive findings for a product.

        Filters: false_p=True, active=False (i.e., mitigated/closed FPs).
        The `notes` field on each finding contains the analyst's justification.
        """
        findings = self._paginate(
            f"{self.api_url}/api/v2/findings/",
            params={
                "product": product_id,
                "false_p": True,
                "active": False,
                "limit": 100,
            },
        )
        logger.info(
            "Fetched %d false positives for product %d", len(findings), product_id
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
