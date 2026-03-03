"""
SPARTAN v2.0 — LLM Client
Multi-provider abstraction: OpenAI, Anthropic, OpenRouter.
Supports streaming output.
"""

from __future__ import annotations

import sys
from typing import Iterator

from config.settings import (
    LLM_PROVIDER, LLM_MODEL, LLM_API_KEY,
    ANTHROPIC_KEY, ANTHROPIC_MODEL,
    OPENROUTER_KEY, OPENROUTER_MODEL,
    MAX_TOKENS, TEMPERATURE, STREAM_OUTPUT,
)


# ── Provider implementations ──────────────────────────────────────────────────

def _openai_chat(messages: list[dict], stream: bool) -> str:
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("openai package not installed. Run: pip install openai")

    client = OpenAI(api_key=LLM_API_KEY)
    if stream:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=messages,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            stream=True,
        )
        collected = []
        for chunk in response:
            delta = chunk.choices[0].delta
            if delta and delta.content:
                print(delta.content, end="", flush=True)
                collected.append(delta.content)
        print()  # newline after stream
        return "".join(collected)
    else:
        response = client.chat.completions.create(
            model=LLM_MODEL,
            messages=messages,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
        return response.choices[0].message.content or ""


def _anthropic_chat(messages: list[dict], stream: bool) -> str:
    try:
        import anthropic
    except ImportError:
        raise ImportError("anthropic package not installed. Run: pip install anthropic")

    client = anthropic.Anthropic(api_key=ANTHROPIC_KEY)

    # Extract system message if present
    system_msg = ""
    filtered_messages = []
    for m in messages:
        if m["role"] == "system":
            system_msg = m["content"]
        else:
            filtered_messages.append(m)

    kwargs: dict = {
        "model": ANTHROPIC_MODEL,
        "max_tokens": MAX_TOKENS,
        "messages": filtered_messages,
    }
    if system_msg:
        kwargs["system"] = system_msg

    if stream:
        collected = []
        with client.messages.stream(**kwargs) as s:
            for text in s.text_stream:
                print(text, end="", flush=True)
                collected.append(text)
        print()
        return "".join(collected)
    else:
        response = client.messages.create(**kwargs)
        return response.content[0].text if response.content else ""


def _openrouter_chat(messages: list[dict], stream: bool) -> str:
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("openai package not installed. Run: pip install openai")

    client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=OPENROUTER_KEY,
    )
    if stream:
        response = client.chat.completions.create(
            model=OPENROUTER_MODEL,
            messages=messages,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
            stream=True,
        )
        collected = []
        for chunk in response:
            delta = chunk.choices[0].delta
            if delta and delta.content:
                print(delta.content, end="", flush=True)
                collected.append(delta.content)
        print()
        return "".join(collected)
    else:
        response = client.chat.completions.create(
            model=OPENROUTER_MODEL,
            messages=messages,
            max_tokens=MAX_TOKENS,
            temperature=TEMPERATURE,
        )
        return response.choices[0].message.content or ""


# ── Public interface ──────────────────────────────────────────────────────────

def chat(messages: list[dict], stream: bool | None = None) -> str:
    """
    Send messages to the configured LLM provider.
    Returns the full response text.
    If stream=True, also prints tokens as they arrive.
    """
    use_stream = STREAM_OUTPUT if stream is None else stream

    provider = LLM_PROVIDER.lower()
    if provider == "openai":
        return _openai_chat(messages, use_stream)
    elif provider == "anthropic":
        return _anthropic_chat(messages, use_stream)
    elif provider == "openrouter":
        return _openrouter_chat(messages, use_stream)
    else:
        raise ValueError(f"Unknown LLM provider: {provider}. Set SPARTAN_LLM_PROVIDER to openai|anthropic|openrouter")


def get_active_model() -> str:
    """Return the currently configured model name."""
    provider = LLM_PROVIDER.lower()
    if provider == "openai":       return f"OpenAI / {LLM_MODEL}"
    elif provider == "anthropic":  return f"Anthropic / {ANTHROPIC_MODEL}"
    elif provider == "openrouter": return f"OpenRouter / {OPENROUTER_MODEL}"
    return f"{provider} / unknown"
