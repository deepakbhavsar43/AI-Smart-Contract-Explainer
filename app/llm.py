"""Minimal LLM provider layer over plain HTTPS (no SDKs).

Providers:
  * anthropic - Claude Messages API (paid API credit)
  * gemini    - Google Gemini via its OpenAI-compatible endpoint (has a free tier)
  * groq      - Groq via its OpenAI-compatible endpoint (has a free tier)
  * openai    - OpenAI, or ANY OpenAI-compatible server via OPENAI_BASE_URL
                (OpenRouter, a local Ollama at http://localhost:11434/v1, ...)

Every provider exposes `complete_json(system, user) -> dict`.
"""
from __future__ import annotations

import asyncio
import json
import re
from typing import Protocol

import httpx

from .config import PROVIDER_PRESETS, Settings


class LLMError(Exception):
    pass


class LLMProvider(Protocol):
    name: str
    model: str

    async def complete_json(self, system: str, user: str, max_tokens: int = 4000) -> dict: ...


def extract_json(text: str) -> dict:
    """Parse the first JSON object in a model reply (tolerates ``` fences / prose)."""
    text = (text or "").strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if fence:
        text = fence.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end == -1:
        raise LLMError("Model reply contained no JSON object")
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as exc:
        raise LLMError(f"Model reply was not valid JSON: {exc}") from exc


RETRY_STATUS = {429, 500, 502, 503, 529}


class _Base:
    name = "base"

    def __init__(self, client: httpx.AsyncClient, api_key: str, model: str, timeout: int, max_retries: int = 3):
        self.client = client
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries

    async def _post(self, url: str, headers: dict, payload: dict) -> dict:
        """POST with backoff on rate limits / overloads (free tiers hit 429 often)."""
        for attempt in range(self.max_retries + 1):
            try:
                r = await self.client.post(url, headers=headers, json=payload, timeout=self.timeout)
            except httpx.HTTPError as exc:
                if attempt < self.max_retries:
                    await asyncio.sleep(2 ** attempt)
                    continue
                raise LLMError(f"{self.name} request failed: {exc.__class__.__name__}") from exc
            if r.status_code == 200:
                return r.json()
            if r.status_code in RETRY_STATUS and attempt < self.max_retries:
                try:
                    wait = float(r.headers.get("retry-after", ""))
                except ValueError:
                    wait = 2 ** (attempt + 1)
                await asyncio.sleep(min(max(wait, 1.0), 30.0))
                continue
            hint = " (rate limit or quota reached)" if r.status_code == 429 else ""
            raise LLMError(f"{self.name} API error {r.status_code}{hint}: {r.text[:300]}")
        raise LLMError(f"{self.name}: retries exhausted")  # pragma: no cover

    async def _raw(self, system: str, user: str, max_tokens: int) -> str:  # pragma: no cover
        raise NotImplementedError

    async def complete_json(self, system: str, user: str, max_tokens: int = 4000) -> dict:
        last: Exception | None = None
        for attempt in range(2):
            prompt = user if attempt == 0 else user + "\n\nYour previous reply was not valid JSON. Reply with ONE JSON object only."
            try:
                return extract_json(await self._raw(system, prompt, max_tokens))
            except LLMError as exc:
                if "API error" in str(exc) or "request failed" in str(exc):
                    raise  # an HTTP failure will not be fixed by re-prompting
                last = exc
        raise LLMError(str(last))


class AnthropicProvider(_Base):
    name = "anthropic"
    URL = "https://api.anthropic.com/v1/messages"

    async def _raw(self, system: str, user: str, max_tokens: int) -> str:
        data = await self._post(
            self.URL,
            {"x-api-key": self.api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
            {
                "model": self.model,
                "max_tokens": max_tokens,
                "temperature": 0,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
        )
        return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


class OpenAICompatibleProvider(_Base):
    """OpenAI Chat Completions format: OpenAI, Gemini, Groq, OpenRouter, Ollama, ..."""

    def __init__(self, client, api_key, model, timeout, *, name: str, base_url: str,
                 json_mode: bool = True, token_multiplier: float = 1.0):
        super().__init__(client, api_key, model, timeout)
        self.name = name
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.json_mode = json_mode
        self.token_multiplier = token_multiplier

    async def _raw(self, system: str, user: str, max_tokens: int) -> str:
        payload = {
            "model": self.model,
            "max_tokens": int(max_tokens * self.token_multiplier),
            "temperature": 0,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        if self.json_mode:
            payload["response_format"] = {"type": "json_object"}
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        data = await self._post(self.url, headers, payload)
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"{self.name}: unexpected response shape") from exc


# kept for backwards compatibility with earlier imports
OpenAIProvider = OpenAICompatibleProvider


def build_provider(settings: Settings, client: httpx.AsyncClient) -> LLMProvider | None:
    p = settings.resolved_provider
    if p == "none":
        return None
    if p == "anthropic":
        return AnthropicProvider(client, settings.anthropic_api_key, settings.model, settings.llm_timeout_s)
    preset = PROVIDER_PRESETS[p]
    return OpenAICompatibleProvider(
        client,
        settings.api_key_for(p),
        settings.model,
        settings.llm_timeout_s,
        name=p,
        base_url=settings.base_url_for(p),
        json_mode=preset["json_mode"],
        token_multiplier=preset["token_multiplier"],
    )
