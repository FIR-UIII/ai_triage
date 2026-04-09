from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

"""
Класс для определения конфигурации приложения. Использует pydantic для валидации и загрузки из .env 
или переменных окружения.

Порядок приоритета значений (от высшего к низшему):
1. Реальные переменные окружения (export DD_API_URL=... или set в системе)
2. Значения из файла .env (через model_config)
3. Дефолты из Field(default=...) в классе Settings
"""
class Settings(BaseSettings):
    # DefectDojo
    dd_api_url: str = Field(..., validation_alias="DD_API_URL")
    dd_api_key: str = Field(..., validation_alias="DD_API_KEY")
    dd_verify_ssl: bool = Field(False, validation_alias="DD_VERIFY_SSL")

    # RAG / Vector store
    chroma_dir: str = Field("./rag/chroma_db_metadata", validation_alias="CHROMA_DIR")
    chroma_collection: str = Field("example_collection", validation_alias="CHROMA_COLLECTION")
    # SentenceTransformer model name for embeddings (must match model used when DB was created)
    embedding_model: str = Field("all-MiniLM-L6-v2", validation_alias="EMBEDDING_MODEL")
    # Threshold for semantic similarity: [0, 1], higher = stricter match
    similarity_threshold: float = Field(0.75, validation_alias="SIMILARITY_THRESHOLD")
    # Threshold for deduplication when adding new knowledge entries
    dedup_threshold: float = Field(0.92, validation_alias="DEDUP_THRESHOLD")

    # LLM
    llm_model_path: str = Field("./llm/Qwen3-4B.gguf", validation_alias="LLM_MODEL_PATH")
    llm_n_ctx: int = Field(8192, validation_alias="LLM_N_CTX")
    llm_n_threads: int = Field(8, validation_alias="LLM_N_THREADS")
    llm_temperature: float = Field(0.2, validation_alias="LLM_TEMPERATURE")
    # Optional: use OpenAI-compatible API instead of local llama.cpp
    llm_api_base_url: str = Field("", validation_alias="LLM_API_BASE_URL")
    llm_api_model: str = Field("default", validation_alias="LLM_API_MODEL")
    llm_api_key: str = Field("none", validation_alias="LLM_API_KEY")

    # Source code context
    code_context_max_chars: int = Field(0, validation_alias="CODE_CONTEXT_MAX_CHARS")
    code_context_lines: int = Field(50, validation_alias="CODE_CONTEXT_LINES")

    # App
    cache_dir: str = Field("./cache", validation_alias="CACHE_DIR")
    output_dir: str = Field("./output", validation_alias="OUTPUT_DIR")
    log_level: str = Field("INFO", validation_alias="LOG_LEVEL")
    # Optional: post triage results as comments back to DefectDojo
    post_comments: bool = Field(False, validation_alias="POST_COMMENTS")

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")
