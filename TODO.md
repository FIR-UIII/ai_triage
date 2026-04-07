Нужен метод для ручного удаление и добавления из RAG finding через мету
Проверка LLM при обогащении должна учитывать поиск дубликатов по описанию FP
Нужно чтобы лог писался не только в терминал но и в файле для анализа (каждый раз отдельно)
Нужны тесты
Дописать чтобы для анализа кода и триажа использовались разные LLM через указание пути через env
Для rag_similarity_match нужен фильтр на 0.5


нужно проверить логику записи в БД duplicate = self.store.find_duplicate - уже и выполняет роьль дедупликации по описнаию?

Убрать запросы т.к локальное использование
```
2026-04-07 09:26:28,572 [INFO] sentence_transformers.SentenceTransformer: Load pretrained SentenceTransformer: all-MiniLM-L6-v2
2026-04-07 09:26:28,996 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/modules.json "HTTP/1.1 307 Temporary Redirect"
2026-04-07 09:26:29,029 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/api/resolve-cache/models/sentence-transformers/all-MiniLM-L6-v2/c9745ed1d9f207416be6d2e6f8de32d1f16199bf/modules.json "HTTP/1.1 200 OK"
2026-04-07 09:26:29,207 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config_sentence_transformers.json "HTTP/1.1 307 Temporary Redirect"
Warning: You are sending unauthenticated requests to the HF Hub. Please set a HF_TOKEN to enable higher rate limits and faster downloads.
2026-04-07 09:26:29,209 [WARNING] huggingface_hub.utils._http: Warning: You are sending unauthenticated requests to the HF Hub. Please set a HF_TOKEN to enable higher rate limits 
and faster downloads.
2026-04-07 09:26:29,245 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/api/resolve-cache/models/sentence-transformers/all-MiniLM-L6-v2/c9745ed1d9f207416be6d2e6f8de32d1f16199bf/config_sentence_transformers.json "HTTP/1.1 200 OK"
2026-04-07 09:26:29,401 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config_sentence_transformers.json "HTTP/1.1 307 Temporary Redirect"
2026-04-07 09:26:29,437 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/api/resolve-cache/models/sentence-transformers/all-MiniLM-L6-v2/c9745ed1d9f207416be6d2e6f8de32d1f16199bf/config_sentence_transformers.json "HTTP/1.1 200 OK"
2026-04-07 09:26:29,588 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/README.md "HTTP/1.1 307 Temporary Redirect"
2026-04-07 09:26:29,625 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/api/resolve-cache/models/sentence-transformers/all-MiniLM-L6-v2/c9745ed1d9f207416be6d2e6f8de32d1f16199bf/README.md "HTTP/1.1 200 OK"
2026-04-07 09:26:29,783 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/modules.json "HTTP/1.1 307 Temporary Redirect"
2026-04-07 09:26:29,823 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/api/resolve-cache/models/sentence-transformers/all-MiniLM-L6-v2/c9745ed1d9f207416be6d2e6f8de32d1f16199bf/modules.json "HTTP/1.1 200 OK"
2026-04-07 09:26:29,984 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/sentence_bert_config.json "HTTP/1.1 307 Temporary Redirect"
2026-04-07 09:26:30,021 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/api/resolve-cache/models/sentence-transformers/all-MiniLM-L6-v2/c9745ed1d9f207416be6d2e6f8de32d1f16199bf/sentence_bert_config.json "HTTP/1.1 200 OK"
2026-04-07 09:26:30,189 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/adapter_config.json "HTTP/1.1 404 Not Found"
2026-04-07 09:26:30,353 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2/resolve/main/config.json "HTTP/1.1 307 Temporary Redirect"
2026-04-07 09:26:30,389 [INFO] httpx: HTTP Request: HEAD https://huggingface.co/api/resolve-cache/models/sentence-transformers/all-MiniLM-L6-v2/c9745ed1d9f207416be6d2e6f8de32d1f16199bf/config.json "HTTP/1.1 200 OK"
```

В knowledge\enrichment.py в моедль добавить test_id, file_path, test_name
 entry = KnowledgeEntry(
            id=f"fp_{finding_id}_{doc_hash}",
            document=document,
            cve=cve,
            component_name=component or None,
            component_version=component_version or None,
            rule=rule or None,
            source_finding_id=finding_id,
            product_id=finding.get("product") or finding.get("product_id"),
            date=(finding.get("mitigated") or "")[:10] or None,
            hash=doc_hash,
        )