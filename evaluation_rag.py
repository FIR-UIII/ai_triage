import os

from langchain_chroma import Chroma
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_ollama import OllamaEmbeddings
from langchain_ollama import OllamaLLM


# Define the persistent directory
current_dir = os.path.dirname(os.path.abspath(__file__))
# persistent_directory = os.path.join(current_dir, "chroma_db")
persistent_directory = os.path.join(current_dir, "chroma_db_metadata")

# Define the embedding model
embeddings = OllamaEmbeddings(model="nomic-embed-text:latest", base_url="http://localhost:11434")

# Load the existing vector store with the embedding function
db = Chroma(collection_name="example_collection", embedding_function=embeddings, persist_directory=persistent_directory)

# Define question
# TODO: сделать динамический query по входящему finding
search_rag_query = "Какие уязвимости относятся к musl версии 1.2.5-r10?"

# Либо не делать запрос а брать по метаинфомации из векторного хранилища напрямую
relevant_docs = db.similarity_search_with_relevance_scores(
    query=search_rag_query,
    score_threshold=0.7,  # порог релевантности
    k=4  # сколько чанков (document) вернуть
)

for doc in relevant_docs:
    print(f"RAG_relevant_docs: {doc[0].page_content}")
    print(f"Metadata: {doc[0].metadata}")
    print("-" * 40)

# DD from findings for assessment
findings_to_assess = "component_name: musl, component_version: 1.2.5-r10, description: You are using a component with a known vulnerability. Version 1.2.5-r10 of the musl component is affected by the vulnerability with an id of CVE-2025-26519 as identified by NVD. NEWLINE The purl of the affected component is: pkg:apk/alpine/musl@1.2.5-r10?arch=x86_64&distro=alpine-3.22.1. Vulnerability Description: musl libc 0.9.13 through 1.2.5 before 1.2.6 has an out-of-bounds write vulnerability when an attacker can trigger iconv conversion of untrusted EUC-KR text to UTF-8. duplicate: False, file_path: pkg:apk/alpine/musl@1.2.5-r10?arch=x86_64&distro=alpine-3.22.1, title: musl:1.2.5-r10 Affected By: CVE-2025-26519 (NVD), vulnerability_ids: CVE-2025-26519"

SYSTEM_PROMPT = """You are an assistant that classifies a security finding based on provided previous context.
The provided context has findings all marked as false-positive.
Find and explain similarities beetween provided Context and Finding. 
If findings has same component_name, component_version, CVE, path marks as false-positive.
Do not make assumptions beyond the provided context.
If there is any uncertainty, mark the finding as needs_review.
"""

USER_PROMPT_TEMPLATE = """Context:
{relevant_docs}

Finding:
{findings_to_assess}

Answer concisely in JSON with fields:
- category (one of "true_positive", "false_positive", "needs_review")
- confidence: (from 0 to 1, where 1 is very confident)
- explanation: (similarities beetween provided Context and Finding)
"""

# Create a ChatOpenAI model
llm = OllamaLLM(
    model="phi3:mini", 
    base_url="http://localhost:11434",
    temperature=0.3,
    # timeout=30,
    # max_retries=0
)

# Define the messages for the model
messages = [
    SystemMessage(content=SYSTEM_PROMPT),
    HumanMessage(content=USER_PROMPT_TEMPLATE),
]

# Invoke the model with the combined input
result = llm.invoke(messages)

# Display the full result and content only
print("\n---LLM responce ---")
print(result)