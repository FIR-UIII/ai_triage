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

# нужно сделать проверку чтобы вначале из раг брался файл по file_path, если нет то по title
"file_path": "/builds/source/gren-hrtech/record-team/record/podbor/backend/recruit-service/src/api/repository/ApplicationRepository.ts",
"title": "app.rules.javascript.database.rules_lgpl_javascript_database_rule-node-nosqli-injection",

triage\engine.py
    rule_key = finding.get("title", "")
    rag_context = self.store.search_by_rule(rule_key, n_results=3)

# Docker size fix
docker history ai-triage
IMAGE          CREATED              CREATED BY                                      SIZE      COMMENT
c1d84950b4c7   About a minute ago   CMD ["--help"]                                  0B        buildkit.dockerfile.v0
<missing>      About a minute ago   ENTRYPOINT ["python" "main.py"]                 0B        buildkit.dockerfile.v0
<missing>      About a minute ago   VOLUME [/app/rag/chroma_db_metadata /app/llm…   0B        buildkit.dockerfile.v0
<missing>      About a minute ago   RUN |2 INCLUDE_LOCAL_LLM=false EMBEDDING_MOD…   0B        buildkit.dockerfile.v0
<missing>      About a minute ago   COPY . . # buildkit                             10.6GB    buildkit.dockerfile.v0
<missing>      About a minute ago   RUN |2 INCLUDE_LOCAL_LLM=false EMBEDDING_MOD…   93.3MB    buildkit.dockerfile.v0
<missing>      About a minute ago   ARG EMBEDDING_MODEL=all-MiniLM-L6-v2            0B        buildkit.dockerfile.v0
<missing>      About a minute ago   RUN |1 INCLUDE_LOCAL_LLM=false /bin/sh -c if…   0B        buildkit.dockerfile.v0
<missing>      About a minute ago   ARG INCLUDE_LOCAL_LLM=false                     0B        buildkit.dockerfile.v0
<missing>      About a minute ago   RUN /bin/sh -c pip install --no-cache-dir -r…   641MB     buildkit.dockerfile.v0
<missing>      2 minutes ago        RUN /bin/sh -c pip install --no-cache-dir to…   868MB     buildkit.dockerfile.v0
<missing>      3 minutes ago        COPY requirements.txt . # buildkit              463B      buildkit.dockerfile.v0
<missing>      3 minutes ago        RUN /bin/sh -c apt-get update && apt-get ins…   175MB     buildkit.dockerfile.v0
<missing>      3 minutes ago        WORKDIR /app                                    0B        buildkit.dockerfile.v0
<missing>      5 days ago           CMD ["python3"]                                 0B        buildkit.dockerfile.v0
<missing>      5 days ago           RUN /bin/sh -c set -eux;  for src in idle3 p…   36B       buildkit.dockerfile.v0
<missing>      5 days ago           RUN /bin/sh -c set -eux;   savedAptMark="$(a…   42MB      buildkit.dockerfile.v0
<missing>      5 days ago           ENV PYTHON_SHA256=272179ddd9a2e41a0fc8e42e33…   0B        buildkit.dockerfile.v0
<missing>      5 days ago           ENV PYTHON_VERSION=3.11.15                      0B        buildkit.dockerfile.v0
<missing>      5 days ago           ENV GPG_KEY=A035C8C19219BA821ECEA86B64E628F8…   0B        buildkit.dockerfile.v0
<missing>      5 days ago           RUN /bin/sh -c set -eux;  apt-get update;  a…   3.81MB    buildkit.dockerfile.v0
<missing>      5 days ago           ENV LANG=C.UTF-8                                0B        buildkit.dockerfile.v0
<missing>      5 days ago           ENV PATH=/usr/local/bin:/usr/local/sbin:/usr…   0B        buildkit.dockerfile.v0
<missing>      6 days ago           # debian.sh --arch 'amd64' out/ 'trixie' '@1…   78.6MB    debuerreotype 0.17