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
print("ID объектов:", data['ids'])
if data['documents']:
    print("Документы:", data['documents'])
if data['metadatas']:
    print("Метаданные:", data['metadatas'])