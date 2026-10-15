"""FastAPI entry point: JSON API under /api, static frontend at /."""
from __future__ import annotations

import hashlib
import json
import time
from collections import OrderedDict, defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .analyzer import analyze
from .config import get_settings
from .etherscan import CHAINS, EtherscanError, fetch_contract
from .llm import build_provider
from .report import to_markdown

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
SAMPLES = ROOT / "samples"


# --------------------------------------------------------------------------- app state

class LRUCache:
    def __init__(self, size: int = 64):
        self.size = size
        self.data: OrderedDict[str, dict] = OrderedDict()

    def get(self, key: str) -> dict | None:
        if key in self.data:
            self.data.move_to_end(key)
            return self.data[key]
        return None

    def put(self, key: str, value: dict) -> None:
        self.data[key] = value
        self.data.move_to_end(key)
        while len(self.data) > self.size:
            self.data.popitem(last=False)


class RateLimiter:
    """Sliding one-hour window per client IP (in-memory; fine for a single instance)."""

    def __init__(self, per_hour: int):
        self.per_hour = per_hour
        self.hits: dict[str, deque] = defaultdict(deque)

    def check(self, ip: str) -> bool:
        if self.per_hour <= 0:
            return True
        now = time.time()
        q = self.hits[ip]
        while q and now - q[0] > 3600:
            q.popleft()
        if len(q) >= self.per_hour:
            return False
        q.append(now)
        return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    app.state.settings = settings
    app.state.http = httpx.AsyncClient()
    app.state.provider = build_provider(settings, app.state.http)
    app.state.cache = LRUCache(64)
    app.state.limiter = RateLimiter(settings.rate_limit_per_hour)
    yield
    await app.state.http.aclose()


app = FastAPI(title="AI Smart Contract Explainer", version="1.0.0", lifespan=lifespan)

_settings = get_settings()
if _settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("X-Frame-Options", "DENY")
    return response


def client_ip(request: Request) -> str:
    if request.app.state.settings.trust_proxy_headers:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# --------------------------------------------------------------------------- schemas

class AnalyzeRequest(BaseModel):
    source: str | None = Field(default=None, description="Solidity source code")
    filename: str | None = Field(default=None, max_length=200)
    address: str | None = Field(default=None, max_length=64)
    chain: str = Field(default="mainnet", max_length=32)
    use_ai: bool = True


# --------------------------------------------------------------------------- routes

def _load_samples() -> list[dict]:
    index = SAMPLES / "index.json"
    return json.loads(index.read_text()) if index.exists() else []


@app.get("/api/health")
async def health():
    return {"status": "ok"}


@app.get("/api/config")
async def config(request: Request):
    s = request.app.state.settings
    provider = request.app.state.provider
    return {
        "ai_enabled": provider is not None,
        "ai_provider": getattr(provider, "name", None),
        "ai_model": getattr(provider, "model", None),
        "address_lookup": bool(s.etherscan_api_key),
        "chains": [{"key": k, "label": v[2]} for k, v in CHAINS.items()],
        "samples": [{k: v for k, v in smp.items() if k != "file"} for smp in _load_samples()],
        "max_source_bytes": s.max_source_bytes,
    }


@app.get("/api/samples/{sample_id}", response_class=PlainTextResponse)
async def sample_source(sample_id: str):
    for smp in _load_samples():
        if smp["id"] == sample_id and smp.get("file"):
            path = (SAMPLES / smp["file"]).resolve()
            if path.parent == SAMPLES.resolve() and path.exists():
                return path.read_text()
    raise HTTPException(404, "Sample not found")


@app.post("/api/analyze")
async def analyze_endpoint(body: AnalyzeRequest, request: Request):
    st = request.app.state
    s = st.settings
    if not (body.source and body.source.strip()) and not body.address:
        raise HTTPException(400, "Provide Solidity source code or a verified contract address.")

    meta_extra: dict = {}
    main_name = None
    if body.source and body.source.strip():
        if len(body.source.encode()) > s.max_source_bytes:
            raise HTTPException(413, f"Source is larger than {s.max_source_bytes // 1000} KB.")
        name = (body.filename or "Contract.sol").replace("\\", "/").split("/")[-1][:100] or "Contract.sol"
        files = [(name, body.source)]
        source_type = "code"
    else:
        cache_key = f"addr:{body.chain}:{(body.address or '').lower()}:{body.use_ai}"
        cached = st.cache.get(cache_key)
        if cached:
            return {**cached, "cached": True}
        if not st.limiter.check(client_ip(request)):
            raise HTTPException(429, "Rate limit reached. Please try again later.")
        try:
            fetched = await fetch_contract(st.http, body.address or "", body.chain, s.etherscan_api_key)
        except EtherscanError as exc:
            raise HTTPException(exc.status, str(exc)) from exc
        files = fetched.files
        if sum(len(c.encode()) for _, c in files) > s.max_source_bytes * 2:
            raise HTTPException(413, "This contract's verified source is too large for the demo.")
        main_name = fetched.name
        source_type = "address"
        meta_extra = {
            "address": fetched.address,
            "chain": fetched.chain,
            "chain_label": CHAINS[fetched.chain][2],
            "explorer_url": fetched.explorer_url,
            "compiler": fetched.compiler,
            "is_proxy": fetched.is_proxy,
            "implementation": fetched.implementation,
            "notes": fetched.notes,
        }

    provider = st.provider if body.use_ai else None
    digest = hashlib.sha256(json.dumps([files, main_name, provider is not None]).encode()).hexdigest()
    cached = st.cache.get(digest)
    if cached:
        return {**cached, "cached": True}
    if source_type == "code" and provider is not None and not st.limiter.check(client_ip(request)):
        raise HTTPException(429, "Rate limit reached. Please try again later, or turn off AI to run static checks only.")

    try:
        report = await analyze(
            files,
            provider=provider,
            source_type=source_type,
            main_name=main_name,
            meta_extra=meta_extra,
            max_llm_functions=s.llm_max_functions,
            concurrency=s.concurrency,
        )
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc

    report["markdown"] = to_markdown(report)
    st.cache.put(digest, report)
    if source_type == "address":
        st.cache.put(f"addr:{body.chain}:{(body.address or '').lower()}:{body.use_ai}", report)
    return report


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):  # pragma: no cover - last-resort guard
    return JSONResponse({"detail": "Unexpected server error."}, status_code=500)


# --------------------------------------------------------------------------- frontend

@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(FRONTEND / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND), name="static")
