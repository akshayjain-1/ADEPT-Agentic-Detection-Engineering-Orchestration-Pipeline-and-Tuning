"""Factory for the agent's local Ollama chat model."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel

    from adept.config.settings import Settings


def build_chat_model(settings: Settings) -> BaseChatModel:
    """Construct a ``ChatOllama`` chat model.

    Construction performs no network call (``validate_model_on_init`` is off),
    so a missing or unreachable Ollama host only fails when the model is first
    invoked. The agent-specific model overrides the shared Ollama model when set.
    The configured ``request_timeout`` bounds each call so a stalled generation
    cannot hang a turn indefinitely.
    """
    from langchain_ollama import ChatOllama

    return ChatOllama(
        model=settings.agent.model or settings.ollama.model,
        base_url=settings.ollama.base_url,
        temperature=settings.ollama.temperature,
        num_ctx=settings.ollama.num_ctx,
        client_kwargs={"timeout": settings.ollama.request_timeout},
        validate_model_on_init=False,
    )
