import os
import time
from langchain_chroma import Chroma
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import OllamaEmbeddings
from langchain_ollama import OllamaLLM

# v2
import requests
import json

# Define the persistent directory
current_dir = os.path.dirname(os.path.abspath(__file__))
# persistent_directory = os.path.join(current_dir, "chroma_db")
persistent_directory = os.path.join(current_dir, "chroma_db_metadata")

# Define the embedding model
embeddings = OllamaEmbeddings(model="nomic-embed-text:v1.5", base_url="http://localhost:11434")

# Load the existing vector store with the embedding function
db = Chroma(collection_name="example_collection", embedding_function=embeddings, persist_directory=persistent_directory)

# Define question
# TODO: сделать динамический query по входящему finding
search_rag_query = "Какие уязвимости относятся к musl версии 1.2.5-r10?"
start_dbquery = time.time() # debug
relevant_docs = db.similarity_search_with_relevance_scores(
    query=search_rag_query,
    score_threshold=0.7,  # порог релевантности
    k=4  # сколько чанков (document) вернуть
)
end_dbquery = time.time() # debug
print(f"Время обработки запроса в БД: {end_dbquery - start_dbquery} сек") # debug

for doc in relevant_docs:
    print(f"RAG_relevant_docs: {doc[0].page_content}")
    print(f"Metadata: {doc[0].metadata}")
    print("-" * 40)

# DD from findings for assessment
findings_to_assess = "component_name: musl, component_version: 1.2.5-r10, description: You are using a component with a known vulnerability. Version 1.2.5-r10 of the musl component is affected by the vulnerability with an id of CVE-2025-26519 as identified by NVD. NEWLINE The purl of the affected component is: pkg:apk/alpine/musl@1.2.5-r10?arch=x86_64&distro=alpine-3.22.1. Vulnerability Description: musl libc 0.9.13 through 1.2.5 before 1.2.6 has an out-of-bounds write vulnerability when an attacker can trigger iconv conversion of untrusted EUC-KR text to UTF-8. duplicate: False, file_path: pkg:apk/alpine/musl@1.2.5-r10?arch=x86_64&distro=alpine-3.22.1, title: musl:1.2.5-r10 Affected By: CVE-2025-26519 (NVD), vulnerability_ids: CVE-2025-26519"

# LLM part
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "phi4-mini:3.8b-q4_K_M"

SYSTEM_PROMPT = """Your goal is find similarilies. 
If `Finding to classify` and `Context` has same component_name, component_version, CVE, path marks them as false-positive, because it was in previous.
Do not make assumptions beyond the provided context.
If there is any uncertainty, mark the finding as needs_review.
Answer concisely with fields in JSON:
- category: (one of "true_positive", "false_positive", "needs_review")
- confidence: (from 0 to 1, where 1 is very confident)
- explanation: (short similarities beetween provided Context and Finding)
"""

def call_llm(system_prompt, context, finding) -> dict:
    prompt = f"""
    Context:
    {context}

    Finding to classify:
    {finding}
    """

    r = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "system": system_prompt,
            "prompt": prompt,
            "temperature": 0.1,
            "stream": False
        },
        timeout=30
    )

    return r.json()["response"]
    # text = r.json()["response"]
    # return json.loads(text)

start_llm = time.time() # debug
res = call_llm(
        system_prompt=SYSTEM_PROMPT,
        context=relevant_docs,
        finding=findings_to_assess
    )
end_llm = time.time() # debug
print(f"Время обработки запроса у LLM: {end_llm - start_llm} сек") # debug

print(res)

# USER_PROMPT_TEMPLATE = """Context:
# {relevant_docs}

# Finding to classify:
# {findings_to_assess}

# Answer concisely with fields in JSON:
# - category: (one of "true_positive", "false_positive", "needs_review")
# - confidence: (from 0 to 1, where 1 is very confident)
# - explanation: (similarities beetween provided Context and Finding)
# """

# Create a ChatOpenAI model
# llm = OllamaLLM(
#     model="phi3:mini", 
#     base_url="http://localhost:11434",
#     temperature=0.1,
#     num_thread=5

#     # timeout=30,
#     # max_retries=0
# )

# # Define the messages for the model
# messages = [
#     SystemMessage(content=SYSTEM_PROMPT),
#     HumanMessage(content=USER_PROMPT_TEMPLATE),
# ]

# # Invoke the model with the combined input
# start = time.time() # debug

# result = llm.invoke(messages)
# end = time.time() # debug
# print(f"Время: {end - start} сек") # debug

# Display the full result and content only
# print("\n---LLM responce ---")
# print(result)