import os

from langchain_text_splitters import CharacterTextSplitter, TextSplitter
from langchain_community.document_loaders import JSONLoader
from langchain_community.document_loaders import TextLoader
from langchain_chroma import Chroma
from langchain_ollama import OllamaEmbeddings 

# Define the directory containing the text file and the persistent directory
current_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(current_dir, "rag_findings.json")
persistent_directory = os.path.join(current_dir, "chroma_db")

# Read the text content from the file
# loader = JSONLoader(file_path, jq_schema=".", text_content=False) # проблема кодировки на русском языке

loader = TextLoader(file_path, encoding="utf-8")
documents = loader.load()
print(documents[0])

# Split the document into chunks via custom splitters
class CustomTextSplitter(TextSplitter):
    def split_text(self, text):
        return text.split("},") # кастомный разделитель чанка `},` можно придумать другой для входа

custom_splitter = CustomTextSplitter()
docs = custom_splitter.split_documents(documents)

# Display information about the split documents
print("\n--- Document Chunks Information ---")
print(f"Number of document chunks: {len(docs)}")
print(f"Sample chunk (doc):\n{docs[0].page_content}\n")

# Create embeddings (using qwen3-embedding:0.6b on local Ollama server)
print("\n--- Creating embeddings ---")
embeddings = OllamaEmbeddings(model="nomic-embed-text:latest", base_url="http://localhost:11434")
print("\n--- Finished creating embeddings ---")

# Create the vector store and persist it automatically
print("\n--- Creating vector store ---")
db = Chroma(collection_name="example_collection", embedding_function=embeddings, persist_directory=persistent_directory)
db.add_documents(docs) # добавление документов в векторное хранилище
print("\n--- Finished creating vector store ---")

# Check
res = db.search(query="libarchive", search_type="similarity")
print(res)
