from llama_cpp import Llama

# import huggingface_hub
# # Скачивание модели (если еще не скачана)
# model_name = "matrixportalx/Phi-4-mini-instruct-Q4_K_M-GGUF"
# model_file = "phi-4-mini-instruct-q4_k_m.gguf"

# # Загружаем модель с Hugging Face Hub
# model_path = huggingface_hub.hf_hub_download(
#     repo_id=model_name,
#     filename=model_file
# )

# Инициализация модели
llm = Llama(
    model_path = "./llm/phi-4-mini-instruct-q4_k_m.gguf",
    chat_format="chatml",
    n_ctx=2048,  # Размер контекста (можно увеличить до 8192 или больше)
    n_threads=8,  # Количество потоков CPU
    verbose=True  # Показывать детали загрузки
)

output = llm.create_chat_completion(
    messages=[
        {
            "role": "system",
            "content": "You are a helpful assistant that outputs in JSON.",
        },
        {"role": "user", "content": "Расскажи о квантовой физике простыми словами"},
    ],
    response_format={
        "type": "json_object",
    },
    temperature=0,
)

print(f'LLM ответ: \n{output}')
# output = llm(
#     "Q: Name the planets in the solar system? A: ",
#     max_tokens=32, # Generate up to 32 tokens, set to None to generate up to the end of the context window
#     stop=["Q:", "\n"], # Stop generating just before the model would generate a new question
#     echo=True # Echo the prompt back in the output
# ) # Generate a completion, can also call create_completion
# print(output)

# title musl:1.2.5-r10 Affected By: CVE-2025-26519 (NVD), Заключение = Ложное срабатывание. Используемая версия alpine 3.22-main содержит исправление уязвимости. https://security.alpinelinux.org/vuln/CVE-2025-26519