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
- сложная задача. Нужно научиться строить AST > CGD > DFD. Лучше сделать связку с уже имеющимся инструментами чтобы не создавать это самому

# план развития
Обучить модель на продуктах АТОМ ИД
Проверсти триаж 
