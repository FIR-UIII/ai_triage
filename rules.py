from typing import Dict, Tuple


def analyze_finding(finding: Dict) -> Tuple[bool, str]:
    """
    TODO: описать
    """
    # Severity 'Info' as out-of-scope
    sev = finding.get('severity') or finding.get('severity_name')
    if sev and str(sev).lower() in ('info', 'informational', 'low'):
        return True, f"Flagged by deterministic rule: severity is {sev}, which is current out-of-scope"

    # Место для вашей рекламы и новых правил
    return False, ''

def dedublicate():
    """
    Правило для анализа дубликатов сработок внутри одной проверки (test id)
    """
    pass
    return None