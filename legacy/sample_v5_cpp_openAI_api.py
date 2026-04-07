from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",  # Важно: указываем путь до v1
    api_key="not-needed"                   # Для локального сервера ключ не нужен, но поле обязательно
)

response = client.chat.completions.create(
    model="phi-4-mini-instruct",           # Название модели (может быть любым, сервер его игнорирует)
    messages=[
        {"role": "system", "content": "Ты — полезный ассистент."},
        {"role": "user", "content": "Расскажи о квантовой физике простыми словами."}
    ],
    max_tokens=200,
    temperature=0.7
)

print(response.choices[0].message.content)