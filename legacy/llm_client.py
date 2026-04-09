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
    model_path = "./llm/Qwen3-4B.gguf",
    chat_format="chatml",
    n_ctx=8192,  # Размер контекста (можно увеличить до 8192 или больше)
    n_threads=8,  # Количество потоков CPU
    verbose=False  # Показывать детали загрузки
)

def chatllm(system_prompt, user_prompt):
    output = llm.create_chat_completion(
        messages=[
            {
                "role": "system",
                "content": system_prompt,
            },
            {"role": "user", "content": user_prompt},
        ],
        response_format={
            "type": "json_object",
        },
        temperature=0.2,
    )
    return output['choices'][0]['message']['content']
