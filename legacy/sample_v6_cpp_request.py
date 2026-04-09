import requests

url = "http://localhost:8080/completion"

# Для Phi-4-mini-instruct шаблон может выглядеть так (проверьте документацию модели)
prompt = "<|user|>\nРасскажи о квантовой физике простыми словами.\n<|assistant|>\n"

payload = {
    "prompt": prompt,
    "n_predict": 200,
    "temperature": 0.1,
    "stop": ["<|user|>", "<|end|>"]  # Стоп-токены, чтобы не генерировать лишнее
}

response = requests.post(url, json=payload)
if response.status_code == 200:
    print(f'LLM answer: {response.json()["content"]}\n {"="*40}')
    print(f'All responce: {response.json()}')
else:
    print(f"Ошибка {response.status_code}: {response.text}")