"""
Модуль с интерфейсом к LLM-бэкендам.
"""

import logging
from abc import ABC, abstractmethod

from config.settings import Settings

logger = logging.getLogger(__name__)


class LLMClient(ABC):
    """
    Минимальный интерфейс для LLM-бэкендов с поддержкой чат-комплешн
    Оба параметра system_prompt и user_prompt всегда передаются
    """

    @abstractmethod
    def chat(self, system_prompt: str, user_prompt: str) -> str:
        """
        Отправляет запрос на чат-комплешн и получает ответ
        Возвращает сырую строку контента (ожидается, что это будет валидный JSON для
        структурированных подсказок, используемых в остальной части кода)
        """
        ...


class LlamaCppClient(LLMClient):
    """
    Класс LlamaCppClient реализует интерфейс LLMClient для локального бэкенда на основе llama.cpp.
    """

    def __init__(
        self,
        model_path: str, # путь к файлу модели
        n_ctx: int = 8192, # по умолчанию используем 8192 токенов контекста, что подходит для большинства современных моделей, но можно настроить в зависимости от конкретной модели и задач
        n_threads: int = 8, # по умолчанию используем 8 потоков, что обычно хорошо работает на современных CPU, но можно настроить в зависимости от конкретного железа
        temperature: float = 0.2, # хардкодим температуру для llama.cpp, так как она не влияет на качество в нашем случае и может только ухудшить его при слишком высоких значениях
    ):
        # Deferred import – llama_cpp is optional
        from llama_cpp import Llama

        self._llm = Llama(
            model_path=model_path,
            chat_format="chatml", # используем формат ChatML, который поддерживает системные и пользовательские сообщения, что идеально подходит для нашего сценария
            n_ctx=n_ctx,
            n_threads=n_threads,
            verbose=False, # отключаем лишний вывод в консоль, чтобы не засорять терминал
            n_gpu_layers=-1 # используем все доступные GPU-слои, если модель поддерживает GPU, иначе работаем на CPU
        )
        self.temperature = temperature
        logger.info("LlamaCppClient loaded: %s", model_path)

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        output = self._llm.create_chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
            temperature=self.temperature,
        )
        return output["choices"][0]["message"]["content"]


class OpenAICompatibleClient(LLMClient):
    """
    Класс OpenAICompatibleClient реализует интерфейс LLMClient для бэкенда, совместимого с OpenAI API.
    """

    def __init__(
        self,
        base_url: str, # базовый URL для OpenAI-совместимого API
        model: str = "default", # модель для использования
        api_key: str = "none", # API ключ для аутентификации
        temperature: float = 0.2, # температура для генерации текста
        max_tokens: int = 1024, # максимальное количество токенов в ответе
    ):
        # Deferred import – openai is optional
        from openai import OpenAI

        self._client = OpenAI(base_url=base_url, api_key=api_key)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        logger.info("OpenAICompatibleClient: %s model=%s", base_url, model)

    def chat(self, system_prompt: str, user_prompt: str) -> str:
        response = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            response_format={"type": "json_object"},
            temperature=self.temperature,
            max_tokens=self.max_tokens,
        )
        return response.choices[0].message.content


def build_llm_client(settings: Settings) -> LLMClient:
    """
    Функция для создания LLMClient
    """
    if settings.llm_api_base_url:
        return OpenAICompatibleClient(
            base_url=settings.llm_api_base_url,
            model=settings.llm_api_model,
            api_key=settings.llm_api_key,
            temperature=settings.llm_temperature,
        )
    return LlamaCppClient(
        model_path=settings.llm_model_path,
        n_ctx=settings.llm_n_ctx,
        n_threads=settings.llm_n_threads,
        temperature=settings.llm_temperature,
    )
