Нужен метод для ручного удаление и добавления из RAG finding через мету
Проверка LLM при обогащении должна учитывать поиск дубликатов по описанию FP
Нужно чтобы лог писался не только в терминал но и в файле для анализа (каждый раз отдельно)
Нужны тесты

нужно проверить логику записи в БД duplicate = self.store.find_duplicate - уже и выполняет роьль дедупликации по описнаию?


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