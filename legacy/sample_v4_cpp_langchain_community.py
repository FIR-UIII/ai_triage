from langchain_community.chat_models import ChatLlamaCpp

local_model = "C:/Users/Admin/Desktop/Project/ai_demo/llm/phi-4-mini-instruct-q4_k_m.gguf"

llm = ChatLlamaCpp(
    temperature=0.1,
    model_path=local_model,
    n_ctx=10000,
    # n_gpu_layers=8,
    # n_batch=300,  # Should be between 1 and n_ctx, consider the amount of VRAM in your GPU.
    max_tokens=512,
    # n_threads=multiprocessing.cpu_count() - 1,
    # verbose=True,
)

messages = [
    (
        "system",
        "You are a helpful assistant.",
    ),
    ("human", "Расскажи о квантовой физике простыми словами."),
]

ai_msg = llm.invoke(messages)

print(ai_msg.content)