import requests
from typing import List, Dict
import urllib3
# отключаем всплывающие ошибки из отсутствия корневого серта ГА
requests.packages.urllib3.disable_warnings()
from typing import List, Dict, Optional

class DefectDojoClient:
    def __init__(self, api_url: str, api_key: str, verify_ssl: bool = False):
        self.api_url = api_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'Authorization': f'Token {api_key}', 'Content-Type': 'application/json'})
        self.verify = verify_ssl

    def fetch_findings(self, test_id: str) -> List[Dict]:
        """Fetch findings for a given test_id. Returns list of finding dicts."""
        url = f"{self.api_url}/api/v2/findings/"
        params = {'test': test_id}
        findings = []
        test_name = self.get_test_name(test_id)
        while url:
            r = self.session.get(url, params=params, verify=self.verify)
            r.raise_for_status()
            data = r.json()
            results = data.get('results') or data.get('objects') or []
            # Добавляем test_name к каждому finding
            for finding in results:
                finding['test_name'] = test_name
            findings.extend(results)
            url = data.get('next')
            params = None
        return findings

    def get_test_name(self, test_id: str) -> Optional[str]:
        """
        Получает имя типа теста по его ID.
        Возвращает строку с именем или None в случае ошибки.
        """
        url_test_info = f"{self.api_url}/api/v2/tests/{test_id}/"
        try:
            test_info_req = self.session.get(url_test_info, verify=self.verify)
            test_info_req.raise_for_status()
            test_info_data = test_info_req.json()
            test_name = test_info_data.get('test_type_name')
            return test_name
        except requests.exceptions.RequestException as e:
            print(f"Ошибка при получении информации о тесте {test_id}: {e}")
            return None