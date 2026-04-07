Протестировать модели
DeepSeek-Coder-6.7B-SecureCode https://huggingface.co/scthornton/deepseek-coder-6.7b-securecode
deepseek-ai/deepseek-coder-6.7b-instruct https://huggingface.co/deepseek-ai/deepseek-coder-6.7b-instruct
Qwen2.5-Coder 7B Instruct
CodeGemma 7B SecureCode / Instruct
https://huggingface.co/scthornton/llama-3.2-3b-securecode
https://huggingface.co/scthornton/qwen2.5-coder-7b-securecode

- python .\rag\check_db.py добавить возможность вывода конкретной причина для правила python .\rag\check_db.py

- в лог нужно добавить какой файл был выбран для анализа и передан в LLM

- фильтрация для output добавить - например чтобы выводить только fp а need review не выводить

сократить кол-во строк кода из контекса для анализа LLM 
Что за запрос 2026-04-07 16:22:32,880 [DEBUG] urllib3.connectionpool: https://us.i.posthog.com:443 "POST /batch/ HTTP/1.1" 200 15

проверить работу на другом беке LLM через докер поднять и запустить

при запуске с параметрами 
# llama-server -m C:\Users\Admin\Desktop\Project\ai_demo\llm\qwen2.5-coder-7b-instruct-q4_k_m.gguf --host 127.0.0.1 --port 8080 -ngl 40
# env
LLM_API_BASE_URL=http://localhost:8080/v1
LLM_API_MODEL=default
LLM_API_KEY=none

Постоянно обрезается ответ
2026-04-07 16:58:51,656 [ERROR] analysis.llm_analyzer: LLM returned non-JSON response: Expecting value: line 1 column 1 (char 0) | raw=```json
{
  "verdict": "needs-review",
  "confidence": 0.5,
  "explanation": "The code snippet sets a field in a struct based on an environment variable, which is a common pattern. Without additional 

2026-04-07 17:00:18,777 [ERROR] analysis.llm_analyzer: LLM returned non-JSON response: Expecting value: line 1 column 1 (char 0) | raw=```json
{
  "verdict": "false-positive",
  "confidence": 0.9,
  "explanation": "The code snippet provided is part of a function that handles special values like 'Infinity'. The use of `strcpy` here is

  2026-04-07 17:00:15,391 [ERROR] analysis.llm_analyzer: LLM returned non-JSON response: Expecting value: line 1 column 1 (char 0) | raw=```json
{
  "verdict": "needs-review",
  "confidence": 0.5,
  "explanation": "The code snippet uses strcpy to copy the string \"sNaN\" into the buffer pointed to by cp. While this can lead to a buffer