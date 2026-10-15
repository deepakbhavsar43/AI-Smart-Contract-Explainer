"""Runtime settings, read from environment variables (or a local .env file).

Secrets are never hardcoded and never returned by the API.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache

try:  # optional: load .env for local development
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass


# OpenAI-compatible providers. `concurrency` is a safe default for each free tier.
PROVIDER_PRESETS: dict[str, dict] = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o-mini",
        "json_mode": True,
        "token_multiplier": 1.0,
        "concurrency": 4,
        "key_required": True,
    },
    "gemini": {  # free tier: https://aistudio.google.com/apikey
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.5-flash",
        "json_mode": False,
        "token_multiplier": 2.0,  # leaves room for the model's built-in "thinking" tokens
        "concurrency": 2,
        "key_required": True,
    },
    "groq": {  # free tier: https://console.groq.com/keys
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
        "json_mode": False,
        "token_multiplier": 1.0,
        "concurrency": 1,  # free tier has a low tokens-per-minute limit
        "key_required": True,
    },
    "ollama": {  # free and local: https://ollama.com (run `ollama pull qwen2.5-coder:7b`)
        "base_url": "http://localhost:11434/v1",
        "model": "qwen2.5-coder:7b",
        "json_mode": True,
        "token_multiplier": 1.0,
        "concurrency": 1,
        "key_required": False,
    },
}
AUTO_ORDER = ["anthropic", "gemini", "groq", "openai"]  # first provider with a key wins


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    etherscan_api_key: str = ""
    llm_provider: str = "auto"  # auto | anthropic | gemini | groq | openai | ollama | none
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-5"
    api_keys: dict = field(default_factory=dict)  # provider -> key (OpenAI-compatible ones)
    models: dict = field(default_factory=dict)  # provider -> model override
    base_urls: dict = field(default_factory=dict)  # provider -> base url override
    llm_timeout_s: int = 90
    llm_max_functions: int = 40  # cap on functions sent to the LLM per analysis
    llm_concurrency: int | None = None  # None -> provider default
    max_source_bytes: int = 600_000
    rate_limit_per_hour: int = 30
    trust_proxy_headers: bool = True
    cors_origins: list[str] = field(default_factory=list)

    def api_key_for(self, provider: str) -> str:
        if provider == "anthropic":
            return self.anthropic_api_key
        return self.api_keys.get(provider, "")

    def base_url_for(self, provider: str) -> str:
        return self.base_urls.get(provider) or PROVIDER_PRESETS[provider]["base_url"]

    def _usable(self, provider: str) -> bool:
        if provider == "anthropic":
            return bool(self.anthropic_api_key)
        preset = PROVIDER_PRESETS.get(provider)
        return bool(preset) and (bool(self.api_key_for(provider)) or not preset["key_required"])

    @property
    def resolved_provider(self) -> str:
        p = self.llm_provider.lower().strip()
        if p == "none":
            return "none"
        if p != "auto":
            return p if self._usable(p) else "none"
        return next((c for c in AUTO_ORDER if self.api_key_for(c)), "none")

    @property
    def model(self) -> str:
        p = self.resolved_provider
        if p == "anthropic":
            return self.anthropic_model
        if p == "none":
            return ""
        return self.models.get(p) or PROVIDER_PRESETS[p]["model"]

    @property
    def concurrency(self) -> int:
        if self.llm_concurrency:
            return max(1, self.llm_concurrency)
        return PROVIDER_PRESETS.get(self.resolved_provider, {}).get("concurrency", 4)


@lru_cache
def get_settings() -> Settings:
    origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "").split(",") if o.strip()]
    providers = PROVIDER_PRESETS.keys()
    return Settings(
        etherscan_api_key=os.getenv("ETHERSCAN_API_KEY", ""),
        llm_provider=os.getenv("LLM_PROVIDER", "auto"),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", ""),
        anthropic_model=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5"),
        api_keys={p: os.getenv(f"{p.upper()}_API_KEY", "") for p in providers},
        models={p: os.getenv(f"{p.upper()}_MODEL", "") for p in providers},
        base_urls={p: os.getenv(f"{p.upper()}_BASE_URL", "") for p in providers},
        llm_timeout_s=_int("LLM_TIMEOUT_S", 90),
        llm_max_functions=_int("LLM_MAX_FUNCTIONS", 40),
        llm_concurrency=_int("LLM_CONCURRENCY", 0) or None,
        max_source_bytes=_int("MAX_SOURCE_BYTES", 600_000),
        rate_limit_per_hour=_int("RATE_LIMIT_PER_HOUR", 30),
        trust_proxy_headers=_bool("TRUST_PROXY_HEADERS", True),
        cors_origins=origins,
    )
