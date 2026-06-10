"""
Модуль client.py содержит реализацию DefectDojoClient - клиента для взаимодействия с REST API DefectDojo v2.
Клиент поддерживает:
- Получение сработок (findings) с автоматической пагинацией
- Получение False Positive сработок по test_id
- Получение имени теста по test_id
- Добавление комментариев к сработкам
"""

import logging
from typing import Dict, List, Optional

import requests
import urllib3
from tenacity import retry, stop_after_attempt, wait_exponential, before_sleep_log

from core.exceptions import DDApiError

# Suppress SSL warnings for self-signed corporate certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


# Default timeout for HTTP requests (connect, read) in seconds
_HTTP_TIMEOUT = (10, 30)


class DefectDojoClient:
    """
    Класс DefectDojoClient обеспечивает взаимодействие с REST API DefectDojo v2
    На вход принимает базовый URL API, API ключ и опцию проверки SSL
    Методы:
        - fetch_findings(test_id): Получает все активные и не помеченные как false positive сработки для данного test_id
        - get_test_name(test_id): Получает имя теста по test_id
        - add_comment(finding_id, comment): Добавляет комментарий к сработке
    Внутренние методы:
        - _get(url, params): Выполняет HTTP GET запрос с обработкой ошибок и
            поддержкой повторов с экспоненциальной задержкой
        - _paginate(url, params): Получает все страницы результатов для пагинированного эндпоинта
        - _dedup_vulnerability_ids(finding): Удаляет дубликаты из списка vulnerability_ids в сработке
    """

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
        logger.debug("DDClient init: api_url=%s, verify_ssl=%s", self.api_url, self.verify)

    # retry нужен для обработки временных проблем с сетью или сервером, таких как 502/503/504 ошибки, 
    # а также для обработки нестабильных соединений при проверке SSL.
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        before_sleep=before_sleep_log(logger, logging.WARNING),
    )
    def _get(self, url: str, params: Optional[Dict] = None) -> Dict:
        logger.debug("HTTP GET %s params=%s verify=%s", url, params, self.verify)
        try:
            r = self.session.get(url, params=params, verify=self.verify, timeout=_HTTP_TIMEOUT)
            logger.debug("HTTP GET %s -> status=%d", url, r.status_code)
            r.raise_for_status()
            return r.json()
        except requests.exceptions.SSLError as e:
            logger.debug("SSL ERROR on GET %s: %s", url, e)
            raise DDApiError(f"SSL error on GET {url}: {e}") from e
        except requests.exceptions.ConnectionError as e:
            logger.debug("CONNECTION ERROR on GET %s: %s", url, e)
            raise DDApiError(f"Connection error on GET {url}: {e}") from e
        except requests.exceptions.Timeout as e:
            logger.debug("TIMEOUT on GET %s: %s", url, e)
            raise DDApiError(f"Timeout on GET {url}: {e}") from e
        except requests.exceptions.RequestException as e:
            logger.debug("REQUEST ERROR on GET %s: %s", url, e)
            raise DDApiError(f"GET {url} failed: {e}") from e

    def _paginate(self, url: str, params: Optional[Dict] = None) -> List[Dict]:
        items: List[Dict] = []
        page = 1
        while url:
            logger.debug("_paginate: page=%d, url=%s", page, url)
            data = self._get(url, params=params)
            results = data.get("results") or []
            items.extend(results)
            logger.debug("_paginate: page=%d got %d results (total=%d)", page, len(results), len(items))
            url = data.get("next")
            params = None  # params only needed on first request
            page += 1
        logger.debug("_paginate: done, total items=%d", len(items))
        return items

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
        Фильтры: false_p=True, active=False
        """
        url = f"{self.api_url}/api/v2/findings/"
        params = {
            "test": test_id,
            "false_p": True,
            "active": False,
            "limit": 100,
        }
        logger.debug("fetch_false_positives_by_test_id: test_id=%d, url=%s, params=%s",
                test_id, url, params)
        findings = self._paginate(url, params=params)
        for f in findings:
            self._dedup_vulnerability_ids(f)
        logger.debug("fetch_false_positives_by_test_id: got %d findings", len(findings))
        logger.info(
            "Fetched %d false positives for test_id %d", len(findings), test_id
        )
        return findings

    def fetch_all_findings(self, test_id: int) -> List[Dict]:
        """
        Загрузка всех findings по test_id без фильтрации по статусу.
        Используется для бенчмарка — получение окончательно размеченных сработок.
        """
        url = f"{self.api_url}/api/v2/findings/"
        params = {
            "test": test_id,
            "limit": 100,
        }
        logger.debug("fetch_all_findings: test_id=%d, url=%s, params=%s",
                test_id, url, params)
        findings = self._paginate(url, params=params)
        for f in findings:
            self._dedup_vulnerability_ids(f)
        logger.debug("fetch_all_findings: got %d findings", len(findings))
        logger.info(
            "Fetched %d total findings for test_id %d", len(findings), test_id
        )
        return findings

    def _get_product_id_by_name(self, product_name: str) -> int:
        """Вспомогательная функция для fetch_findings_by_product_name. Резолвит имя продукта в product_id через /api/v2/products/?name=<name>."""
        data = self._get(f"{self.api_url}/api/v2/products/", params={"name": product_name})
        results = data.get("results") or []
        if not results:
            raise DDApiError(f"Product not found: {product_name!r}")
        if len(results) > 1:
            logger.warning("Multiple products match name %r, using first (id=%d)", product_name, results[0]["id"])
        return results[0]["id"]

    def fetch_findings_by_product_name(self, product_name: str) -> List[Dict]:
        """
        Скачивает активные не-FP findings по имени продукта.
        Сначала резолвит имя в product_id, затем фильтрует findings.
        Фильтры: active=True, false_p=False, test__engagement__product=product_id
        """
        product_id = self._get_product_id_by_name(product_name)
        url = f"{self.api_url}/api/v2/findings/"
        params = {
            "test__engagement__product": product_id,
            "false_p": False,
            "active": True,
        }
        logger.debug("fetch_findings_by_product_name: product_name=%r, product_id=%d, params=%s", product_name, product_id, params)
        findings = self._paginate(url, params=params)
        for f in findings:
            self._dedup_vulnerability_ids(f)
        logger.info("Fetched %d findings for product %r (id=%d)", len(findings), product_name, product_id)
        return findings

    def fetch_false_positives_by_product_name(self, product_name: str) -> List[Dict]:
        """
        Скачивает False Positive findings по имени продукта.
        Фильтры: false_p=True, active=False, test__engagement__product=product_id
        """
        product_id = self._get_product_id_by_name(product_name)
        url = f"{self.api_url}/api/v2/findings/"
        params = {
            "test__engagement__product": product_id,
            "false_p": True,
            "active": False,
        }
        logger.debug("fetch_false_positives_by_product_name: product_name=%r, product_id=%d, params=%s", product_name, product_id, params)
        findings = self._paginate(url, params=params)
        for f in findings:
            self._dedup_vulnerability_ids(f)
        logger.info("Fetched %d false positives for product %r (id=%d)", len(findings), product_name, product_id)
        return findings

    def get_test_name(self, test_id: int) -> Optional[str]:
        try:
            data = self._get(f"{self.api_url}/api/v2/tests/{test_id}/")
            return data.get("test_type_name")
        except DDApiError as e:
            logger.warning("Could not get test name for test %d: %s", test_id, e)
            return None

    def add_comment(self, finding_id: int, comment: str) -> bool:
        """
        Добавляет комментарий к сработке. Возвращает True при успехе, False при ошибке
        """
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
        """
        Убирает дубликаты из списка vulnerability_ids в сработке. Иногда DefectDojo может возвращать дубликаты, что может мешать анализу
        """
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
