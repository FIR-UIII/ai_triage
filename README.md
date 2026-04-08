# AI Triage

Автоматизированный триаж срабатываний безопасности из DefectDojo с использованием RAG + LLM.

Система последовательно проверяет каждую сработку по шести стадиям — от быстрых
детерминистических правил до анализа достижимости через CodeQL/Semgrep — и выносит
вердикт `false-positive` или `needs-review` с уверенностью и объяснением.




---

## Содержание

1. [Архитектура](#архитектура)
2. [Требования](#требования)
3. [Установка](#установка)
4. [Конфигурация (.env)](#конфигурация-env)
5. [LLM-бекенд](#llm-бекенд)
   - [Вариант A: локальный llama.cpp (GGUF)](#вариант-a-локальный-llamacpp-gguf)
   - [Вариант B: Ollama (Docker)](#вариант-b-ollama-docker)
   - [Вариант C: llama-server (llama.cpp HTTP)](#вариант-c-llama-server-llamacpp-http)
6. [Векторная база знаний (RAG / ChromaDB)](#векторная-база-знаний-rag--chromadb)
7. [CLI-команды](#cli-команды)
8. [Пайплайн триажа (6 стадий)](#пайплайн-триажа-6-стадий)
9. [Модуль обогащения знаний](#модуль-обогащения-знаний)
10. [Анализ достижимости (Reachability)](#анализ-достижимости-reachability)
11. [Детерминистические правила](#детерминистические-правила)
12. [Структура проекта](#структура-проекта)
13. [Формат выходных данных](#формат-выходных-данных)

---

## Архитектура

```
DefectDojo API
      │
      ▼
┌──────────────────────────────────────────┐
│              TriageEngine                │
│                                          │
│  Stage 1. Deterministic Rules            │
│  Stage 2. Exact Meta Match ──► ChromaDB  │
│  Stage 3. Semantic Similarity ─► ChromaDB│
│  Stage 4. LLM Analysis ────► LLM + RAG   │
│  Stage 5. Manual Review fallback         │
└──────────────────────────────────────────┘
      │
      ▼
  JSONL output  +  (опционально) комментарий в DefectDojo
```

---

## Требования

- Python 3.10+
- DefectDojo с доступом по API v2
- Один из LLM-бекендов (см. ниже)
- (Опционально) Semgrep или CodeQL для анализа достижимости

---

## Установка

```bash
git clone <repo>
cd ai_triage

python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux / macOS:
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
# Отредактировать .env: заполнить DD_API_URL, DD_API_KEY, путь к модели
```

---

## Конфигурация (.env)

Все параметры читаются из `.env` в корне проекта.

```dotenv
# ── DefectDojo ────────────────────────────────────────────────────────────────
DD_API_URL=https://ddojo.dev.example.local  # базовый URL без /api/v2
DD_API_KEY=your_token_here                  # Settings → API v2 key
DD_VERIFY_SSL=false                         # true если есть валидный сертификат

# ── ChromaDB (векторное хранилище) ───────────────────────────────────────────
CHROMA_DIR=./rag/chroma_db_metadata
CHROMA_COLLECTION=example_collection
SIMILARITY_THRESHOLD=0.75    # [0.0-1.0] порог для совпадения на Stage 3
DEDUP_THRESHOLD=0.92         # выше — запись считается дублём, не добавляется

# ── LLM — локальный llama.cpp (активен если LLM_API_BASE_URL пустой) ─────────
LLM_MODEL_PATH=./llm/Qwen3-4B.gguf
LLM_N_CTX=8192
LLM_N_THREADS=8
LLM_TEMPERATURE=0.2

# ── LLM — OpenAI-compatible API (если задан — llama.cpp игнорируется) ────────
# LLM_API_BASE_URL=http://localhost:11434/v1   # Ollama
# LLM_API_BASE_URL=http://localhost:8080/v1    # llama-server
# LLM_API_MODEL=qwen2.5:0.5b
# LLM_API_KEY=none

# ── Приложение ────────────────────────────────────────────────────────────────
CACHE_DIR=./cache
OUTPUT_DIR=./output
LOG_LEVEL=INFO           # DEBUG / INFO / WARNING
POST_COMMENTS=false      # true → писать результат как комментарий в DD
```

---

## LLM-бекенд

### Вариант A: локальный llama.cpp (GGUF)

Работает без интернета, без GPU. Бекенд по умолчанию.

```bash
mkdir -p ./llm
pip install huggingface_hub
hf --help # или huggingface-cli --help
huggingface-cli download Qwen/Qwen3-4B-GGUF qwen3-4b-q4_k_m.gguf --local-dir ./llm
```

`.env`:
```dotenv
LLM_MODEL_PATH=./llm/qwen3-4b-q4_k_m.gguf
LLM_N_CTX=8192
LLM_N_THREADS=8
# LLM_API_BASE_URL — оставить пустым
```

---

### Вариант B: Ollama (Docker)

```bash
docker run -d --cpus=8 -v llm:/root/.ollama -p 11434:11434 --name ollama ollama/ollama

docker exec -it ollama ollama pull qwen2.5:0.5b      # ~2.5 сек/запрос на CPU
docker exec -it ollama ollama pull qwen2.5:7b         # лучше качество
docker exec -it ollama ollama pull deepseek-coder-v2  # анализ кода

# Проверить: GET http://localhost:11434 → "Ollama is running"
```

`.env`:
```dotenv
LLM_API_BASE_URL=http://localhost:11434/v1
LLM_API_MODEL=qwen2.5:0.5b
LLM_API_KEY=none
```

Запуск строго на CPU:
```bash
docker run -d -e OLLAMA_NUM_GPU=0 --cpus=8 \
  -v llm:/root/.ollama -p 11434:11434 --name ollama ollama/ollama
```

---

### Вариант C: llama-server (llama.cpp HTTP)

Лучший вариант для параллельной обработки.

```bash
llama-server \
  -m /llm/qwen2.5-coder-7b-instruct-q4_k_m.gguf \
  --host 127.0.0.1 \
  --port 8080 \
  --temp 0.7 \
  --ctx-size 8192 \ # опционально указать окно контекста 
  -ngl 40
  --offline \
  --metrics

# Проверить: GET http://localhost:8080/health
```

`.env`:
```dotenv
LLM_API_BASE_URL=http://localhost:8080/v1
LLM_API_MODEL=default
LLM_API_KEY=none
```

---
## CLI-команды

## enrich - обогащение векторной базы знаний (RAG / ChromaDB)

### Первичное наполнение (вручную) - старый вариант

```bash
python legacy/create_rag_meta_chromadb.py
```

### Автоматическое наполнение из DefectDojo

```bash
python main.py enrich --product-id 298           # с записью в RAG
python main.py enrich --product-id 298 --dry-run # предпросмотр без записи в RAG

# Пример вывода:
```json
{
  "fetched": 42,
  "processed": 42,
  "added": 17,
  "skipped_duplicate": 23,
  "skipped_no_reason": 2,
  "errors": 0
}

# проверить что было внесено в RAG
python ./rag/check_db.py
```

### Добавление записи из кода

```python
from knowledge.vector_store import VectorStore
from core.models import KnowledgeEntry

store = VectorStore(
    collection_name="example_collection",
    persist_directory="./rag/chroma_db_metadata",
)
store.add_entry(KnowledgeEntry(
    id="manual_001",
    document="openssl с патчем вендора РедОС. Сканер не распознаёт буквенный суффикс версии.",
    cve="CVE-2019-1543",
    component_name="openssl",
    component_version="1:1.1.1zd-1.el7",
    test_id=298,
))
```

### `triage` — триаж сработок

```
Options:
  -t, --test-id    INT   триаж ID теста из DefectDojo [обязательный]
  -c, --cache      PATH  JSON-кеш (создаётся автоматически)
  -o, --output     PATH  Выходной JSONL [./output/triage_<id>.jsonl]
      --post-comments    Записывать результат как комментарий в DD
```

```bash
# Базовый запуск
python main.py triage --test-id 15540

# С автокомментированием в DefectDojo
python main.py triage --test-id 15540 --post-comments

# Из готового кеша (без обращения к API)
python main.py triage --test-id 15540 --cache ./cache/findings_15540.json

# Указать путь к результатам
python main.py triage --test-id 15540 --output ./results/sca_15540.jsonl

# Ожидаемое поведение в процессе выполнения
# Пишется лог без ошибок ERROR
tail -f /путь/к/вашему/лог-файлу.log # Get-Content -Path "C:\путь\к\вашему\лог-файлу.log" -Wait
  ...
  2026-04-08 09:09:11,741 [INFO] triage.engine: [3291534] Stage 1 match: [Rule:test_file] Фильтр по тестовым файлам: сработки внутри директорий test/spec не попадают в продакшн.
  2026-04-08 09:09:11,742 [INFO] triage.engine: [3291535] Triaging: app.rules.go.lang.security.audit.crypto.math-random-used

# Пишется результат работы с ключом triage_result, отображается результат в ключе verdict
{"id": 2858280, ... "triage_result": {"finding_id": 2858280, "action": "llm_analysis", "verdict": "false-positive", "confidence": 0.9, "explanation": "The use of `math/rand` in the provided code snippet is not for cryptographic purposes. It is used to calculate a delay for periodic bundle downloads, which is a common practice in non-cryptographic applications.", "similar_finding_ids": [], "dd_comment": "[LLM Triage] false-positive (confidence=0.90): The use of `math/rand` in the provided code snippet is not for cryptographic purposes. It is used to calculate a delay for periodic bundle downloads, which is a common practice in non-cryptographic applications.", "metadata": {}}

# на сервере модели LLM нет ошибок и есть логи обращений (на примере llama-server)
main: model loaded
main: server is listening on http://127.0.0.1:8080
srv  params_from_: Chat format: peg-native
slot get_availabl: id  3 | task -1 | selected slot by LRU, t_last = -1
srv  get_availabl: updating prompt cache
srv          load:  - looking for better prompt, base f_keep = -1.000, sim = 0.000
srv        update:  - cache state: 0 prompts, 0.000 MiB (limits: 8192.000 MiB, 28928 tokens, 8589934592 est)
srv  get_availabl: prompt cache update took 0.01 ms
slot launch_slot_: id  3 | task -1 | sampler chain: logits -> ?penalties -> ?dry -> ?top-n-sigma -> top-k -> ?typical -> top-p -> min-p -> ?xtc -> temp-ext -> dist
slot launch_slot_: id  3 | task 0 | processing task, is_child = 0
slot update_slots: id  3 | task 0 | new prompt, n_ctx_slot = 28928, n_keep = 0, task.n_tokens = 941
slot update_slots: id  3 | task 0 | n_tokens = 0, memory_seq_rm [0, end)
slot init_sampler: id  3 | task 0 | init sampler, took 0.07 ms, tokens: text = 941, total = 941
slot update_slots: id  3 | task 0 | prompt processing done, n_tokens = 941, batch.n_tokens = 941
slot print_timing: id  3 | task 0 |
prompt eval time =     799.11 ms /   941 tokens (    0.85 ms per token,  1177.56 tokens per second)
       eval time =    1488.62 ms /    76 tokens (   19.59 ms per token,    51.05 tokens per second)
      total time =    2287.73 ms /  1017 tokens
slot      release: id  3 | task 0 | stop processing: n_tokens = 1016, truncated = 0
srv  update_slots: all slots are idle
srv  log_server_r: done request: POST /v1/chat/completions 127.0.0.1 200
```

---

### `fetch` — скачать findings в файл

```
Options:
  -t, --test-id  INT   ID теста                           [required]
  -o, --output   PATH  Куда сохранить [./cache/findings_<id>.json]
```

```bash
python main.py fetch --test-id 15540
python main.py fetch --test-id 15540 --output ./data/raw.json

# С анализом кода
python main.py triage --test-id 15540 --repo C:/repos/iam
```

---

## Пайплайн триажа (6 стадий)

Каждая следующая стадия вызывается только если предыдущая не дала результата.

```
Finding
  │
  ▼ Stage 1 — Deterministic Rules               (без внешних вызовов)
  │   severity = Info/Low           → FP  conf 0.95
  │   файл в /test/ /spec/ /mock/   → FP  conf 0.88
  │   файл .md/.rst/.txt            → FP  conf 0.90
  │   "патч вендора" в notes        → FP  conf 0.87
  │   is_mitigated=True, active=False→ FP  conf 0.95
  │
  ▼ Stage 2 — Exact CVE + component match в ChromaDB
  │   CVE-2015-8930 + openssl → найдено → FP  conf 0.87
  │
  ▼ Stage 3 — Semantic similarity в ChromaDB
  │   score ≥ SIMILARITY_THRESHOLD  → FP  conf = score × 0.9
  │
  ▼ Stage 4 — LLM analysis с RAG-контекстом
  │   KB-записи → промпт → LLM → JSON {verdict, confidence, explanation}
  │
  ▼ Stage 5 — needs-review (ручной разбор)
```

---

## Модуль обогащения знаний

**Файл:** `knowledge/enrichment.py`

**Алгоритм:**
1. Загружает закрытые FP из DD (`false_p=True`, `active=False`)
2. Извлекает причину FP из `notes` (3 уровня):
   - **Regex** — паттерны: "патч от вендора", "ложная тревога", "исправление" и т.д.
   - **LLM fallback** — если regex ничего не нашёл
   - **Truncated raw note** — запасной вариант (первые 500 символов)
3. Строит документ: `{reason}. CVE: {cve}. Component: {name} {version}`
4. Проверяет дубликат через `find_duplicate(threshold=DEDUP_THRESHOLD)`
5. Добавляет только уникальные записи

---

## Анализ достижимости (Reachability) - процессе разработки

Применяется только к SAST-сработкам (поле `sast_source_file_path` заполнено).

### Semgrep

```bash
pip install semgrep && semgrep --version
```

```python
from analysis.reachability import SemgrepReachabilityAnalyzer

result = SemgrepReachabilityAnalyzer(config="auto").analyze(
    finding, source_root="/path/to/repo"
)
print(result.is_reachable, result.confidence, result.explanation)
```

### CodeQL

**Шаг 1.** Скачать CLI, добавить в PATH.

**Шаг 2.** Создать базу данных:

```bash
# Python
codeql database create ./codeql-db --language=python --source-root=.

# Java (требует компиляции)
codeql database create ./codeql-db --language=java \
  --command="mvn compile -DskipTests" --source-root=.

# JS / TS
codeql database create ./codeql-db --language=javascript --source-root=.

codeql database info ./codeql-db   # проверить
```

**Шаг 3.** Подключить в `main.py`:

```python
from analysis.reachability import (
    CodeQLReachabilityAnalyzer,
    SemgrepReachabilityAnalyzer,
    CompositeReachabilityAnalyzer,
)

# Один инструмент
reachability = CodeQLReachabilityAnalyzer(db_path="./codeql-db")

# Или комбинированный (голосует по confidence)
reachability = CompositeReachabilityAnalyzer([
    SemgrepReachabilityAnalyzer(),
    CodeQLReachabilityAnalyzer(db_path="./codeql-db"),
])

engine = TriageEngine(
    vector_store=store,
    llm_client=llm,
    dd_base_url=settings.dd_api_url,
    reachability_analyzer=reachability,
    source_root="/path/to/repo",
)
```

**Прямой вызов для отладки:**

```python
from analysis.reachability import CodeQLReachabilityAnalyzer

result = CodeQLReachabilityAnalyzer(db_path="./codeql-db").analyze(
    finding={"sast_sink_object": "executeQuery",
             "sast_source_file_path": "src/db/user.py"},
    source_root="./repo",
)
print(result.is_reachable)    # True / False
print(result.confidence)      # 0.0 – 1.0
print(result.flow_paths)      # список путей data-flow
```

---

## Детерминистические правила

**Файл:** `analysis/rules.py`

| Правило | Условие | Confidence |
|---|---|---|
| `severity_out_of_scope` | severity = Info / Low | 0.95 |
| `test_file` | путь содержит `/test/`, `/spec/`, `/mock/` | 0.88 |
| `documentation_file` | расширение `.md`, `.rst`, `.txt` | 0.90 |
| `vendor_backport` | в notes: "патч от вендора", "backported" | 0.87 |
| `already_mitigated` | `is_mitigated=True` и `active=False` | 0.95 |

Добавить своё правило:

```python
# analysis/rules.py

def _internal_tool(finding: Dict) -> bool:
    return "internal_tool" in (finding.get("file_path") or "")

RULES.append(Rule(
    name="internal_tool",
    description="Finding is in an internal tooling directory",
    check=_internal_tool,
    confidence=0.85,
))
```

---

## Структура проекта

```
ai_triage/
├── .env                           # секреты (gitignore)
├── .env.example                   # шаблон конфига
├── main.py                        # CLI: triage / enrich / fetch
├── config/settings.py             # pydantic-settings, читает .env
├── core/
│   ├── models.py                  # Finding, TriageResult, KnowledgeEntry
│   └── exceptions.py              # DDApiError, RAGError, LLMError, ...
├── integrations/defectdojo/
│   └── client.py                  # DD API v2 (retry, пагинация, fetch FPs)
├── knowledge/
│   ├── vector_store.py            # ChromaDB (cosine similarity)
│   └── enrichment.py              # Pipeline обогащения KB
├── analysis/
│   ├── rules.py                   # Детерминистические правила
│   ├── llm_analyzer.py            # LLM + RAG context
│   └── reachability.py            # Semgrep / CodeQL / Composite
├── llm_backend/
│   └── client.py                  # LlamaCppClient / OpenAICompatibleClient
├── triage/
│   └── engine.py                  # 6-stage pipeline (DI)
├── rag/
│   ├── chroma_db_metadata/        # файлы ChromaDB
│   └── create_rag_meta_chromadb.py
├── cache/                         # JSON-кеш (gitignore)
├── output/                        # JSONL результаты (gitignore)
├── llm/                           # GGUF-модели (gitignore)
└── samples/                       # примеры Ollama / langchain / llama-server
```

---

## Формат выходных данных

Каждая строка `.jsonl` — исходный finding + поле `triage_result`:

```json
{
  "id": 2982921,
  "title": "openssl:1:1.1.1zd-1.el7 Affected By: CVE-2019-1543",
  "severity": "High",
  "triage_result": {
    "finding_id": 2982921,
    "action": "rag_meta_match",
    "verdict": "false-positive",
    "confidence": 0.87,
    "explanation": "Exact CVE/component match in knowledge base (1 entries)",
    "similar_finding_ids": [2728961],
    "dd_comment": "[Auto-triage] Similar false-positive findings:\n  - https://.../finding/2728961: ...",
    "metadata": {}
  }
}
```

Значения `action`:

| action | Стадия | Описание |
|---|---|---|
| `deterministic_rule` | 1 | Сработало детерминистическое правило |
| `rag_meta_match` | 2 | Точное совпадение CVE + component в KB |
| `rag_similarity_match` | 3 | Семантически похожая запись в KB |
| `llm_analysis` | 4+5 | LLM вынес вердикт (с reachability или без) |
| `needs_review` | 6 | Нет решения — необходим ручной разбор |
