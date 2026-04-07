"""
LLM client abstraction layer.

Provides a common interface so the triage engine and enrichment pipelines
are decoupled from the specific LLM backend.

Supported backends:
  - LlamaCppClient        – local GGUF model via llama-cpp-python
  - OpenAICompatibleClient – any OpenAI-compatible API
                             (llama-server, Ollama OpenAI endpoint, vLLM, etc.)

Usage:
    from llm_backend.client import build_llm_client
    llm = build_llm_client(settings)
    result_json = llm.chat(system_prompt, user_prompt)
"""

import logging
from abc import ABC, abstractmethod

from config.settings import Settings

logger = logging.getLogger(__name__)


class LLMClient(ABC):
    """Minimal interface for chat-completion LLM backends.

    Both system_prompt and user_prompt are always passed; backends that do
    not support system messages should concatenate them.
    """

    @abstractmethod
    def chat(self, system_prompt: str, user_prompt: str) -> str:
        """Send a chat-completion request.

        Returns the raw content string (expected to be valid JSON for the
        structured prompts used elsewhere in the codebase).
        """
        ...


class LlamaCppClient(LLMClient):
    """Backend: local GGUF model via llama-cpp-python.

    Best for: offline / air-gapped environments without GPU.
    """

    def __init__(
        self,
        model_path: str,
        n_ctx: int = 8192,
        n_threads: int = 8,
        temperature: float = 0.2,
    ):
        # Deferred import – llama_cpp is optional
        from llama_cpp import Llama

        self._llm = Llama(
            model_path=model_path,
            chat_format="chatml",
            n_ctx=n_ctx,
            n_threads=n_threads,
            verbose=False,
            n_gpu_layers=-1
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
    """Backend: any OpenAI-compatible REST API.

    Works with:
      - llama-server (llama.cpp HTTP server)
      - Ollama  (http://localhost:11434/v1)
      - vLLM
      - LM Studio
      - Azure OpenAI

    Set LLM_API_BASE_URL and LLM_API_MODEL in your .env.
    """

    def __init__(
        self,
        base_url: str,
        model: str = "default",
        api_key: str = "none",
        temperature: float = 0.2,
        max_tokens: int = 1024,
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
    """Factory: pick the right backend based on settings.

    If LLM_API_BASE_URL is set → use OpenAI-compatible API.
    Otherwise → use local llama.cpp.
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
