#!/usr/bin/env python3

"""
Этот скрипт предназначен для однократного запуска при первоначальной настройке системы. 
"""

import os
from uuid import uuid4
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_ollama import OllamaEmbeddings 

# Define the directory containing the text file and the persistent directory
current_dir = os.path.dirname(os.path.abspath(__file__))
persistent_directory = os.path.join(current_dir, "chroma_db_metadata")

# Ручной ввод данных с метаданными
finding_1 = Document(
    page_content="title musl:1.2.5-r10 Affected By: CVE-2025-26519 (NVD), Заключение = Ложное срабатывание. Используемая версия alpine 3.22-main содержит исправление уязвимости. https://security.alpinelinux.org/vuln/CVE-2025-26519",
    metadata = {
        "id": "2309693", 
        "source": "dependency_track", 
        "product_id": 298,
        "date": "2025-10-02",
        "file_path": "pkg:apk/alpine/musl@1.2.5-r10?arch=x86_64&distro=alpine-3.22.1",
        "component_name": "musl",
        "component_version": "1.2.5-r10",
        "cve": "CVE-2025-26519"},
    id=1,
)

finding_2 = Document(
    page_content="libarchive:0:3.8.1-1.el7 Affected By: CVE-2015-8930 (NVD), Заключение = False-positive. Используемая версия 3.8.1-1.el7 содержит исправление уязвимости согласно документации вендора",
    metadata = {
        "id": "2728961", 
        "source": "dependency_track", 
        "product_id": 298,
        "date": "2025-10-02",
        "file_path": "pkg:rpm/redos/libarchive@3.8.1-1.el7?arch=x86_64&distro=redos-7.3&epoch=0&upstream=libarchive-3.8.1-1.el7.src.rpm",
        "component_name": "libarchive",
        "component_version": "3.8.1-1.el7",
        "cve": "CVE-2015-8930"},
    id=2,
)

# List of documents to be added
documents = [
    finding_1,
    finding_2,
]

# Assign unique IDs to each document
uuids = [str(uuid4()) for _ in range(len(documents))]

# Create embeddings (using qwen3-embedding:0.6b on local Ollama server)
print("\n--- Creating embeddings ---")
embeddings = OllamaEmbeddings(model="nomic-embed-text:v1.5", base_url="http://localhost:11434")
print("\n--- Finished creating embeddings ---")

# Create the vector store and persist it automatically
print("\n--- Creating vector store ---")
db = Chroma(collection_name="example_collection", embedding_function=embeddings, persist_directory=persistent_directory)
db.add_documents(documents=documents, ids=uuids) # добавление документов в векторное хранилище
print("\n--- Finished creating vector store ---")

# Check
res = db.search(query="libarchive", search_type="similarity")
print(f"Тестовая выгрузка из БД для проверки успешности: {res}")