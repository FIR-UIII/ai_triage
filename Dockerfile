# syntax=docker/dockerfile:1

# ── Stage 1: builder (heavy deps, never shipped in final image) ───────────────
FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

# Isolate all packages in a venv so they're trivially copyable to runtime stage
RUN python -m venv /venv
ENV PATH="/venv/bin:$PATH"

COPY requirements.txt .

# CPU-only torch first – prevents sentence-transformers from pulling the ~2.5 GB CUDA variant
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

RUN pip install --no-cache-dir -r requirements.txt \
    && find /venv/lib/python3.11/site-packages -type d -name "tests" -exec rm -rf {} + 2>/dev/null; \
       find /venv/lib/python3.11/site-packages -type d -name "test"  -exec rm -rf {} + 2>/dev/null; \
       find /venv/lib/python3.11/site-packages -name "*.pyi" -delete 2>/dev/null; true

ARG INCLUDE_LOCAL_LLM=false
RUN if [ "$INCLUDE_LOCAL_LLM" = "true" ]; then \
        pip install --no-cache-dir --prefer-binary "llama-cpp-python==0.3.16"; \
    fi

# Pre-download embedding model into builder's HF cache
ARG EMBEDDING_MODEL=all-MiniLM-L6-v2
RUN TRANSFORMERS_OFFLINE=0 HF_HUB_OFFLINE=0 \
    python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('${EMBEDDING_MODEL}')" \
    && echo "Embedding model '${EMBEDDING_MODEL}' cached successfully"


# ── Stage 2: runtime (lean – fresh overlay, no builder artifacts) ─────────────
FROM python:3.11-slim

WORKDIR /app

# Copy the venv (packages) and HuggingFace model cache from builder
COPY --from=builder /venv /venv
COPY --from=builder /root/.cache /root/.cache

ENV PATH="/venv/bin:$PATH"

# Copy application source – this layer is now only ~3 MB
COPY . .

RUN mkdir -p cache output log

VOLUME ["/app/rag/chroma_db_metadata", "/app/llm", "/app/cache", "/app/output", "/app/log"]

CMD ["/bin/sh"]
