# Протестировать модели
DeepSeek-Coder-6.7B-SecureCode https://huggingface.co/scthornton/deepseek-coder-6.7b-securecode
deepseek-ai/deepseek-coder-6.7b-instruct https://huggingface.co/deepseek-ai/deepseek-coder-6.7b-instruct
Qwen2.5-Coder 7B Instruct
CodeGemma 7B SecureCode / Instruct
https://huggingface.co/scthornton/llama-3.2-3b-securecode
https://huggingface.co/scthornton/qwen2.5-coder-7b-securecode

# фильтрация результатов
добавить флаг `--false-positive` `-fp` чтобы в output файл выводились только "verdict": "false-positive" т.е. фильтровать вывод. Остальные статусы не выводить

# бенчмарк
Цель сравнить статус как был закрыт finding по итогу окончания триажа когда были проведен ручной анализ кода человеком. Для этого добавить команду `bench` на вход команда должна примимать `--input`, `-i` файл для анализа файла (это файл output с результатами прошного анализа триажа) и `--test-id` как и ранее принимает test-id и скачивает результаты findings но уже окончательно размеченных сработок и по статусам выводит статистику:
- статус верно указан (если статусы false-positive совпадают): {кол-во верно определенных} {процент от общих сработок} 
- статус неверно выставлен (если статусы false-positive НЕ совпадают): {кол-во неверно определенных} {процент от общих размеченных сработок} 


# переписать логи DEBUG
убрать реализацию логов с выводом <function _DEBUG at 0x00000219909FC4A0> - нужно привести к ожидаемому виду через logger чтобы они писались

# план развития
Обучить модель на продуктах АТОМ ИД
Проверсти триаж 