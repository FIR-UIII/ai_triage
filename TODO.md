# Протестировать модели
DeepSeek-Coder-6.7B-SecureCode https://huggingface.co/scthornton/deepseek-coder-6.7b-securecode
deepseek-ai/deepseek-coder-6.7b-instruct https://huggingface.co/deepseek-ai/deepseek-coder-6.7b-instruct
Qwen2.5-Coder 7B Instruct
CodeGemma 7B SecureCode / Instruct
https://huggingface.co/scthornton/llama-3.2-3b-securecode
https://huggingface.co/scthornton/qwen2.5-coder-7b-securecode

# добавить агента верификатора результатов
Модель может выдавать логические несоответствия. Нужно проверить только описание 
 {"finding_id": 3418021, "action": "llm_analysis", "verdict": "false-positive", "confidence": 0.9, "explanation": "The 'termsOfService' variable is used in an anchor tag with the 'href' attribute, but it is not clear if this variable is user-controlled or sanitized. Without additional context, it is difficult to determine if this is a true XSS vulnerability."}

# добавить анализ достижимости 
- сложная задача. Нужно научиться строить AST > CGD > DFD. Лучше сделать связку с уже имеющимся инструментами чтобы не создавать это самому.

# план развития
Обучить модель на продуктах АТОМ ИД
Проверсти триаж 

## Расшить модель RAG
добавить 
CWE
sink
source
sanitizer
framework
language
arguments

## Добавить UI и функционал загрузки результатов в DD через него

## Plan: Агентный анализ триажа
TL;DR — добавить уже один запрос к LLM для верификации ответа от LLM. Он также получает оригинальный finding и ответ. Его задача проверить нет ли противоречий.

verifier = run_llm(
   system_prompt=JUDGE_PROMPT,
   finding=finding,
   fp_analysis=fp_agent,
   security_analysis=security_agent
)

## Перейти на 3 уровневую проверку LLM 
FP search - TP search - Judge

> FP search
System prompt. You are an AppSec triage specialist.
Your task is to argue ONLY why this finding could be a false positive.
Расширить промпт анализатора
- search for sanitization
- identify unreachable sinks
- identify framework protections
- identify impossible exploit paths

You must be skeptical of the scanner.

Never claim exploitable unless absolutely unavoidable.
Output
{
  "position": "false_candidate",
  "arguments": [
    "input sanitized with html.EscapeString",
    "sink not reachable from user input"
  ],
  "confidence": 0.81
}


> TP search
Его задача выступить адвокатом дьявола и доказать что это верная сработка
System prompt
You are a senior security reviewer.
Your task is to argue why this finding could be a real vulnerability.

You must:
- search for exploitability
- identify bypasses
- identify weak sanitization
- identify user-controlled paths

You must be skeptical of false-positive assumptions.

Prioritize security risk over convenience.
Output
{
  "position": "needs_review",
  "arguments": [
    "sanitizer only covers HTML context",
    "SQL sink still reachable"
  ],
  "confidence": 0.74
}

> Judge agent

Смотрит:

finding
RAG
ответы обоих агентов

И выдает structured result.

Judge prompt
You are the final AppSec adjudicator.

Your task:
- compare both analyses
- identify contradictions
- evaluate evidence quality
- produce conservative security verdict

Rules:
- if exploitability evidence exists -> need-review
- if uncertainty exists -> need-review
- false only if strong evidence exists
Output
{
  "decision": "need-review",
  "reason": "Potential SQL injection path remains reachable",
  "agreement_score": 0.42
}

# Рекомендации по запуску LLM
1. Персистентный LLM-сервер вместо загрузки модели в процессе (нулевые изменения кода).
Приложение уже поддерживает OpenAI-совместимый режим (LLM_API_BASE_URL в settings.py:36), а в docker-compose.yml есть закомментированные блоки для llama-server и Ollama. Поднять на VM llama-server один раз:

llama-server -m ./llm/Qwen3-4B.gguf -c 4096 --threads <физ. ядра> --cache-reuse 256
и в .env задать LLM_API_BASE_URL=http://localhost:8080/v1. Эффект: модель загружена постоянно, --cache-reuse переиспользует общий префикс промпта между запросами, C++-сервер быстрее python-биндингов.

2. Отключить thinking у Qwen3. Варианты: добавить /no_think в системный промпт; в llama-server — флаг --reasoning-budget 0; либо взять не-думающую модель. Из вашего списка в TODO.md для CPU лучше всего по скорости Llama-3.2-3B-securecode или Qwen2.5-Coder-3B; 6.7–7B модели на CPU будут в ~1.7–2 раза медленнее 4B — при 12 ГБ RAM и CPU-only я бы их не брал, если скорость критична.

3. Ограничить генерацию. max_tokens=256–512 достаточно для ожидаемого JSON (verdict + confidence + explanation до 100 слов). Сейчас llama.cpp-путь не ограничен вообще.

4. Уменьшить n_ctx с 8192 до 4096 (если промпты реально влезают) — вдвое меньше KV-кэш, меньше давление на RAM. Плюс KV-квантизация в llama-server: -ctk q8_0 -ctv q8_0.

5. Потоки = число физических ядер VM. LLM_N_THREADS=8 захардкожен дефолтом — если у VM 4 vCPU, 8 потоков только вредят. И убедиться, что llama.cpp собран с AVX2/AVX-512 (готовый pip-wheel llama-cpp-python часто собран без нативных оптимизаций — llama-server из официальных релизов обычно быстрее).

6. Реструктурировать промпт под кэш префикса (единственный пункт, требующий правки кода): вынести статические правила в начало системного промпта, а RAG-контекст и код — в user-сообщение. Тогда --cache-reuse в llama-server избавит от пересчёта ~500 токенов правил на каждый запрос.

7. Пайплайн уже помогает — усилить его. Этапы 1–3 в triage/engine.py (правила, meta-match, similarity) отсекают находки до LLM. Чем богаче база знаний (enrich), тем меньше находок вообще доходит до Шага 4. Это самый дешёвый способ сократить суммарное время триажа.