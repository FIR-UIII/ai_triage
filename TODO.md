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
(.venv) PS C:\Users\Admin\Desktop\Project\ai_demo> docker build --no-cache -t ai-triage .
[+] Building 214.6s (22/22) FINISHED                                                                                                                                             
 => [internal] load build definition from Dockerfile                                                                                                                        0.0s
 => => transferring dockerfile: 2.12kB                                                                                                                                      0.0s
 => [internal] load .dockerignore                                                                                                                                           0.0s
 => => transferring context: 541B                                                                                                                                           0.0s
 => resolve image config for docker.io/docker/dockerfile:1                                                                                                                  1.0s
 => CACHED docker-image://docker.io/docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89                                             0.0s
 => [internal] load build definition from Dockerfile                                                                                                                        0.0s
 => [internal] load metadata for docker.io/library/python:3.11-slim                                                                                                         0.8s
 => [internal] load .dockerignore                                                                                                                                           0.0s
 => CACHED [builder 1/8] FROM docker.io/library/python:3.11-slim@sha256:b27df5841f3355e9473f9a516d38a6783b6c8dfeacaf2d14a240f443b368ddb6                                    0.0s
 => [internal] load build context                                                                                                                                          47.8s
 => => transferring context: 10.64GB                                                                                                                                       47.8s
 => CACHED [stage-1 2/6] WORKDIR /app                                                                                                                                       0.0s
 => [builder 2/8] RUN apt-get update && apt-get install -y --no-install-recommends gcc     && rm -rf /var/lib/apt/lists/*                                                  37.4s
 => [builder 3/8] RUN python -m venv /venv                                                                                                                                  9.4s
 => [builder 4/8] COPY requirements.txt .                                                                                                                                   0.3s 
 => [builder 5/8] RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu                                                                    34.7s 
 => [builder 6/8] RUN pip install --no-cache-dir -r requirements.txt     && find /venv/lib/python3.11/site-packages -type d -name "tests" -exec rm -rf {} + 2>/dev/null;   59.4s 
 => [builder 7/8] RUN if [ "false" = "true" ]; then         pip install --no-cache-dir --prefer-binary "llama-cpp-python==0.3.16";     fi                                   0.5s 
 => [builder 8/8] RUN TRANSFORMERS_OFFLINE=0 HF_HUB_OFFLINE=0     python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2  18.6s
 => [stage-1 3/6] COPY --from=builder /venv /venv                                                                                                                           3.3s
 => [stage-1 4/6] COPY --from=builder /root/.cache /root/.cache                                                                                                             0.2s
 => [stage-1 5/6] COPY . .                                                                                                                                                 17.8s
 => [stage-1 6/6] RUN mkdir -p cache output log                                                                                                                             0.3s
 => exporting to image                                                                                                                                                     26.1s
 => => exporting layers                                                                                                                                                    26.1s
 => => writing image sha256:cc3658ce648fcb0db6ecb19737c68dbad97daa58f0b11bf36ee79e13a5de8ef1                                                                                0.0s
 => => naming to docker.io/library/ai-triage                                                                                                                                0.0s

Use 'docker scan' to run Snyk tests against images to find vulnerabilities and learn how to fix them
(.venv) PS C:\Users\Admin\Desktop\Project\ai_demo> docker build --no-cache -t ai-triage .

Image history
0	CMD ["--help"]	0 Bytes
1	ENTRYPOINT ["python" "main.py"]	0 Bytes
2	VOLUME [/app/rag/chroma_db_metadata /app/llm /app/cache /app/output /app/log]	0 Bytes
3	RUN /bin/sh -c mkdir -p cache output log # buildkit	0 Bytes
4	COPY . . # buildkit	10.63 GB
5	ENV PATH=/venv/bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin	0 Bytes
6	COPY /root/.cache /root/.cache # buildkit	91.62 MB
7	COPY /venv /venv # buildkit	1.39 GB
8	WORKDIR /app	0 Bytes
9	CMD ["python3"]	0 Bytes
10	RUN /bin/sh -c set -eux; for src in idle3 pip3 pydoc3 python3 python3-config; do dst="$(echo "$src" | tr -d 3)"; [ -s "/usr/local/bin/$src" ]; [ ! -e "/usr/local/bin/$dst" ]; ln -svT "$src" "/usr/local/bin/$dst"; done # buildkit	36 Bytes
11	RUN /bin/sh -c set -eux; savedAptMark="$(apt-mark showmanual)"; apt-get update; apt-get install -y --no-install-recommends dpkg-dev gcc gnupg libbluetooth-dev libbz2-dev libc6-dev libdb-dev libffi-dev libgdbm-dev liblzma-dev libncursesw5-dev libreadline-dev libsqlite3-dev libssl-dev make tk-dev uuid-dev wget xz-utils zlib1g-dev ; wget -O python.tar.xz "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz"; echo "$PYTHON_SHA256 *python.tar.xz" | sha256sum -c -; wget -O python.tar.xz.asc "https://www.python.org/ftp/python/${PYTHON_VERSION%%[a-z]*}/Python-$PYTHON_VERSION.tar.xz.asc"; GNUPGHOME="$(mktemp -d)"; export GNUPGHOME; gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys "$GPG_KEY"; gpg --batch --verify python.tar.xz.asc python.tar.xz; gpgconf --kill all; rm -rf "$GNUPGHOME" python.tar.xz.asc; mkdir -p /usr/src/python; tar --extract --directory /usr/src/python --strip-components=1 --file python.tar.xz; rm python.tar.xz; cd /usr/src/python; gnuArch="$(dpkg-architecture --query DEB_BUILD_GNU_TYPE)"; ./configure --build="$gnuArch" --enable-loadable-sqlite-extensions --enable-optimizations --enable-option-checking=fatal --enable-shared $(test "${gnuArch%%-*}" != 'riscv64' && echo '--with-lto') --with-ensurepip ; nproc="$(nproc)"; EXTRA_CFLAGS="$(dpkg-buildflags --get CFLAGS)"; LDFLAGS="$(dpkg-buildflags --get LDFLAGS)"; LDFLAGS="${LDFLAGS:-} -Wl,--strip-all"; make -j "$nproc" "EXTRA_CFLAGS=${EXTRA_CFLAGS:-}" "LDFLAGS=${LDFLAGS:-}" ; rm python; make -j "$nproc" "EXTRA_CFLAGS=${EXTRA_CFLAGS:-}" "LDFLAGS=${LDFLAGS:-} -Wl,-rpath='\$\$ORIGIN/../lib'" python ; make install; cd /; rm -rf /usr/src/python; find /usr/local -depth \( \( -type d -a \( -name test -o -name tests -o -name idle_test \) \) -o \( -type f -a \( -name '*.pyc' -o -name '*.pyo' -o -name 'libpython*.a' \) \) \) -exec rm -rf '{}' + ; ldconfig; apt-mark auto '.*' > /dev/null; apt-mark manual $savedAptMark; find /usr/local -type f -executable -not \( -name '*tkinter*' \) -exec ldd '{}' ';' | awk '/=>/ { so = $(NF-1); if (index(so, "/usr/local/") == 1) { next }; gsub("^/(usr/)?", "", so); printf "*%s\n", so }' | sort -u | xargs -rt dpkg-query --search | awk 'sub(":$", "", $1) { print $1 }' | sort -u | xargs -r apt-mark manual ; apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; apt-get dist-clean; export PYTHONDONTWRITEBYTECODE=1; python3 --version; pip3 install --disable-pip-version-check --no-cache-dir --no-compile 'setuptools==79.0.1' 'wheel<0.46' ; pip3 --version # buildkit	42.04 MB
12	ENV PYTHON_SHA256=272179ddd9a2e41a0fc8e42e33dfbdca0b3711aa5abf372d3f2d51543d09b625	0 Bytes
13	ENV PYTHON_VERSION=3.11.15	0 Bytes
14	ENV GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D	0 Bytes
15	RUN /bin/sh -c set -eux; apt-get update; apt-get install -y --no-install-recommends ca-certificates netbase tzdata ; apt-get dist-clean # buildkit	3.81 MB
16	ENV LANG=C.UTF-8	0 Bytes
17	ENV PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin	0 Bytes
18	# debian.sh --arch 'amd64' out/ 'trixie' '@1782172800'	78.63 MB