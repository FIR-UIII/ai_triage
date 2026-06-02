# syntax=docker/dockerfile:1
FROM python:3.11-slim

WORKDIR /app

# System deps needed by some chromadb/onnxruntime native wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (layer is cached unless requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Optional: local GGUF backend via llama.cpp
# Usage: docker build --build-arg INCLUDE_LOCAL_LLM=true .
ARG INCLUDE_LOCAL_LLM=false
RUN if [ "$INCLUDE_LOCAL_LLM" = "true" ]; then \
        pip install --no-cache-dir --prefer-binary "llama-cpp-python==0.3.16"; \
    fi

# Pre-download the embedding model so the container works offline at runtime.
# Override with: docker build --build-arg EMBEDDING_MODEL=<hf-model-id> .
ARG EMBEDDING_MODEL=all-MiniLM-L6-v2
RUN TRANSFORMERS_OFFLINE=0 HF_HUB_OFFLINE=0 \
    python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('${EMBEDDING_MODEL}')" \
    && echo "Embedding model '${EMBEDDING_MODEL}' cached successfully"

# Copy application source (excludes paths listed in .dockerignore)
COPY . .

# Create runtime directories (volumes may override these at run-time)
RUN mkdir -p cache output log

# Persistent data – mount these as volumes to keep data between container runs:
#   /app/rag/chroma_db_metadata  – ChromaDB vector store
#   /app/llm                     – GGUF model files (local LLM mode only)
#   /app/cache                   – findings JSON cache
#   /app/output                  – triage result JSONL files
#   /app/log                     – log files
VOLUME ["/app/rag/chroma_db_metadata", "/app/llm", "/app/cache", "/app/output", "/app/log"]

ENTRYPOINT ["python", "main.py"]
CMD ["--help"]
