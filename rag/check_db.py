#!/usr/bin/env python3
"""
Скрипт для проверки содержимого базы данных Chroma, используемой в RAG.
Позволяет убедиться, что данные были успешно сохранены и доступны для поиска.
Выводит записи в формате: finding_id : rule : {описание документа}

Пример использования:
    python check_db.py ./chroma_db_metadata example_collection
"""

import argparse
from chromadb import PersistentClient


def main():
    parser = argparse.ArgumentParser(
        description="Проверка содержимого базы данных Chroma (RAG)"
    )
    parser.add_argument(
        "persistent_directory",
        help="Путь к папке с БД Chroma",
    )
    parser.add_argument(
        "collection_name",
        help="Имя коллекции в БД",
    )
    args = parser.parse_args()

    client = PersistentClient(path=args.persistent_directory)
    collection = client.get_collection(name=args.collection_name)

    print(f"Коллекция: {collection.name}")
    print(f"Количество объектов: {collection.count()}\n")

    data = collection.get()

    if data['metadatas']:
        for md, doc in zip(data['metadatas'], data['documents']):
            fid = md.get('source_finding_id', '—')
            rule = md.get('rule', '—')
            print(f"{fid} : {rule} : {doc}")


if __name__ == "__main__":
    main()