#!/usr/bin/env python3

from chromadb import PersistentClient
import os

# Путь к папке с БД (как и при создании)
current_dir = os.path.dirname(os.path.abspath(__file__))
persistent_directory = os.path.join(current_dir, "chroma_db_metadata")

# Подключаемся к существующей БД
client = PersistentClient(path=persistent_directory)

# Получаем коллекцию БЕЗ указания embedding_function
collection = client.get_collection(name="example_collection")

# Выводим информацию
print(f"Коллекция: {collection.name}")
print(f"Количество объектов: {collection.count()}\n")

# Получаем все данные
data = collection.get()

# Выводим только finding IDs и rules
finding_ids = set()
rules = set()
if data['metadatas']:
    for md in data['metadatas']:
        fid = md.get('source_finding_id')
        if fid is not None:
            finding_ids.add(fid)
        rule = md.get('rule')
        if rule:
            rules.add(rule)

print(f"Finding IDs ({len(finding_ids)}):")
for fid in sorted(finding_ids):
    print(f"  - {fid}")

print(f"\nRules ({len(rules)}):")
for rule in sorted(rules):
    print(f"  - {rule}")