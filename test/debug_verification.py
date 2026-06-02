#!/usr/bin/env python3

"""
Скрипт для отладки этапа верификации (Checker LLM) на одном конкретном finding из кеша.
Запустить 

python debug_verification.py
"""
import json
import logging
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(name)s: %(message)s')

from config.settings import Settings
from main import _build_dd_client, _build_vector_store, _build_llm_client, _build_checker_llm_client
from triage.engine import TriageEngine

def debug_single_finding():
    settings = Settings()
    
    # Загружаем найденный finding из кеша (или возьми test_id)
    cache_file = "D:\\Project\\ai_triage\\test\\test_LLM.json"  # Замени на свой test_id
    if not cache_file.exists():
        print(f"❌ Cache not found: {cache_file}")
        print("Run: python main.py fetch --test-id <ID>")
        return
    
    with open(cache_file) as f:
        findings = json.load(f)
    
    if not findings:
        print("❌ No findings in cache")
        return
    
    # Берем первый finding
    finding = findings[0]
    print(f"\n📌 Testing finding #{finding['id']}: {finding['title'][:60]}")
    print("=" * 80)
    
    # Строим engine с verification
    store = _build_vector_store(settings)
    llm = _build_llm_client(settings)
    checker_llm = _build_checker_llm_client(settings)
    
    engine = TriageEngine(
        vector_store=store,
        llm_client=llm,
        dd_base_url=settings.dd_api_url,
        checker_llm_client=checker_llm,
    )
    
    # Запускаем триаж
    result = engine.triage(finding)
    
    # Выводим результат
    print(f"\n✅ RESULT:")
    print(f"  Verdict: {result.verdict}")
    print(f"  Confidence: {result.confidence}")
    print(f"  Action: {result.action}")
    print(f"  Explanation: {result.explanation}")
    if result.dd_comment:
        print(f"  DD Comment: {result.dd_comment}")
    
    # Если был verification, видно по объяснению [Verified: ...]
    if "[Verified:" in result.explanation:
        print("\n🔍 VERIFICATION APPLIED:")
        parts = result.explanation.split("[Verified:")
        print(f"  Initial: {parts[0].strip()}")
        print(f"  Verification: {parts[1].strip()}")

if __name__ == "__main__":
    debug_single_finding()