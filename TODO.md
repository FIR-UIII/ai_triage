# Протестировать модели
DeepSeek-Coder-6.7B-SecureCode https://huggingface.co/scthornton/deepseek-coder-6.7b-securecode
deepseek-ai/deepseek-coder-6.7b-instruct https://huggingface.co/deepseek-ai/deepseek-coder-6.7b-instruct
Qwen2.5-Coder 7B Instruct
CodeGemma 7B SecureCode / Instruct
https://huggingface.co/scthornton/llama-3.2-3b-securecode
https://huggingface.co/scthornton/qwen2.5-coder-7b-securecode

# фильтрация результатов
добавить флаг `--fp` чтобы в output файл выводились только "verdict": "false-positive"

# бенчмарк
добавить команду `bench` на вход команда должна примимать `--input`, `-i` файл для анализа файла (это файл output с результатами прошного анализа триажа)
и `--test-id` как и ранее принимает test-id и скачивает результаты уже закрытые сработки отмеченные как false-positive но с другими параметрами - нужно создать отдельную функцию где 
  findings = self._paginate(
              f"{self.api_url}/api/v2/findings/",
              params= {
                  "test": test_id,
                  "active": False,
                  "false_p": True,
                  "out_of_scope": True
                  },
          )

# переписать логи DEBUG
убрать реализацию логов с выводом <function _DEBUG at 0x00000219909FC4A0> - нужно привести к ожидаемому виду через logger чтобы они писались