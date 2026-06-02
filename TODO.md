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
