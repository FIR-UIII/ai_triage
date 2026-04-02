import json
from defectdojo_api.defectdojo_apiv2 import DefectDojoAPIv2
# docs https://github.com/DefectDojo/defectdojo_api/tree/master

host = "https://ddojo.dev.rosatom.local/"
api_key = "3d1ccf6ca95dce7d09ab2e0136107a994ab6e773"
user = "gren-d-ArYPaderin"

DD = DefectDojoAPIv2(host, api_key, user, api_version='v2', verify_ssl=False)
# ensure_ascii=False нужно изменить для метода data_json: return json.dumps(self.data, sort_keys=True, ensure_ascii=False, indent=4, separators=(',', ': '))
# find = DD.get_finding(2982970)
# print(find.data_json(pretty=True))

# test_info = DD.get_test(17627)
# print(test_info.data_json(pretty=True))

# получить все findings по test id 
# проблема пагинации запроса для обработки большего кол-ва запроса
# find_list = DD.list_findings(test_id_in=17627, severity_gt="Critical")
# find_list = find_list.data_json(pretty=True)
# print(find_list)

# with open('raw_findings.json', 'w', encoding='utf-8') as file:
#     json.dump(find_list, file, ensure_ascii=False)


# =============
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from typing import List, Dict


# =========================
# CONFIG
# =========================

DEFECTDOJO_URL = "https://ddojo.dev.rosatom.local/"
API_TOKEN = "3d1ccf6ca95dce7d09ab2e0136107a994ab6e773"
TEST_ID = 17627  # <-- нужный test_id
PAGE_SIZE = 100  # можно увеличить (например 200/500 если позволяет сервер)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

def get_all_findings(test_id: int) -> List[Dict]:
    """
    Получает все findings для указанного test_id с учетом пагинации.
    Возвращает массив вида [{finding1}, {finding2}, ...]
    """

    headers = {
        "Authorization": f"Token {API_TOKEN}",
        "Content-Type": "application/json",
    }

    findings = []
    offset = 0

    while True:
        url = f"{DEFECTDOJO_URL}/api/v2/findings/"
        params = {
            "test": test_id,
            "limit": PAGE_SIZE,
            "offset": offset,
        }

        response = requests.get(url, headers=headers, params=params, timeout=30)

        if response.status_code != 200:
            raise Exception(
                f"Ошибка запроса: {response.status_code} {response.text}"
            )

        data = response.json()

        # results — это массив findings
        batch = data.get("results", [])
        findings.extend(batch)

        # Общее количество сработок
        total_count = data.get("count", 0)

        print(
            f"Получено {len(findings)} из {total_count} (offset={offset})"
        )

        # Проверяем, получили ли все записи
        if offset + PAGE_SIZE >= total_count:
            break

        offset += PAGE_SIZE

    return findings


all_findings = get_all_findings(TEST_ID)

print(f"\nВсего найдено сработок: {len(all_findings)}")

# Пример структуры итогового массива:
# [{finding1}, {finding2}, ..., {findingN}]
print(type(all_findings))
print(all_findings[:2])  # показать первые 2 для примера
