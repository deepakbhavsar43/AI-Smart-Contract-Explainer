"""API + AI-merge tests. A fake LLM provider stands in for the real API (no network, no keys)."""
import asyncio
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.analyzer import analyze
from app.etherscan import parse_source_field, validate_address, EtherscanError
from app.llm import extract_json
from app.main import app

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


class FakeProvider:
    name = "fake"
    model = "fake-1"

    def __init__(self):
        self.calls = 0

    async def complete_json(self, system, user, max_tokens=4000):
        self.calls += 1
        if "Write the top of a review report" in user:
            return {
                "overview": "A savings bank for ETH.",
                "contract_type": "ETH vault",
                "roles": [{"role": "Depositor", "description": "Any user", "powers": ["Deposit and withdraw own ETH"]}],
                "key_function_ids": ["VulnerableBank.withdraw", "Nope.ghost"],
                "risk_summary": "Reentrancy in withdraw.",
                "top_fixes": ["Move the balance update before the call."],
            }
        return {
            "functions": [
                {"id": "VulnerableBank.withdraw", "summary": "Pays out the caller's balance.", "who_can_call": "Anyone",
                 "risks": [
                     {"title": "Reentrancy again", "severity": "high", "category": "reentrancy", "lines": [30, 31],
                      "explanation": "dup", "fix": "x"},
                     {"title": "Event after state", "severity": "low", "category": "logic", "lines": [999, 1000],
                      "explanation": "Lines are wrong on purpose.", "fix": "y"},
                 ]},
                {"id": "Ghost.fn", "summary": "hallucinated", "risks": []},
            ],
            "static_triage": [
                {"finding_id": "S1", "verdict": "confirmed", "reason": "Classic pattern."},
                {"finding_id": "S99", "verdict": "confirmed", "reason": "does not exist"},
            ],
        }


def test_ai_merge_validates_model_output():
    src = (SAMPLES / "VulnerableBank.sol").read_text()
    fake = FakeProvider()
    r = asyncio.run(analyze([("VulnerableBank.sol", src)], provider=fake))
    by_id = {f["id"]: f for f in r["functions"]}
    assert by_id["VulnerableBank.withdraw"]["summary"] == "Pays out the caller's balance."
    assert "Ghost.fn" not in by_id  # hallucinated id ignored
    # duplicate of a static category is dropped, logic risk kept with lines clamped to the function
    ai = [f for f in r["findings"] if f["source"] == "ai"]
    assert [f["title"] for f in ai] == ["Event after state"]
    w = by_id["VulnerableBank.withdraw"]
    assert ai[0]["lines"] == [w["start_line"], w["end_line"]] and ai[0]["line_note"]
    # triage applied only to real ids
    s1 = next(f for f in r["findings"] if f["id"] == "S1")
    assert s1["triage"]["verdict"] == "confirmed"
    assert r["key_functions"] == ["VulnerableBank.withdraw"]
    assert r["overview"]["text"] == "A savings bank for ETH."
    assert r["overview"]["overall_risk"] == "high"  # deterministic, from findings


def test_false_positive_triage_lowers_overall_risk():
    src = """contract T { mapping(address=>uint) b;
      function w() external { (bool ok,) = msg.sender.call{value: b[msg.sender]}(""); require(ok); b[msg.sender] = 0; } }"""

    class Dismiss(FakeProvider):
        async def complete_json(self, system, user, max_tokens=4000):
            if "Write the top" in user:
                return {}
            return {"functions": [], "static_triage": [{"finding_id": "S1", "verdict": "likely_false_positive", "reason": "test"}]}

    r = asyncio.run(analyze([("T.sol", src)], provider=Dismiss()))
    assert r["severity_counts"]["dismissed"] == 1
    assert r["overview"]["overall_risk"] == "low"


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


def test_config_and_samples(client):
    cfg = client.get("/api/config").json()
    assert {"ai_enabled", "chains", "samples"} <= cfg.keys()
    assert "file" not in cfg["samples"][0]
    assert "contract VulnerableBank" in client.get("/api/samples/vulnerable-bank").text
    assert client.get("/api/samples/..%2F..%2Fapp%2Fconfig").status_code == 404


def test_analyze_code_static_only(client):
    src = (SAMPLES / "UnprotectedVault.sol").read_text()
    res = client.post("/api/analyze", json={"source": src, "filename": "UnprotectedVault.sol", "use_ai": False})
    assert res.status_code == 200
    data = res.json()
    assert data["overview"]["overall_risk"] == "critical"
    assert data["markdown"].startswith("# Contract review: UnprotectedVault")
    assert data["meta"]["ai_enabled"] is False
    assert res.headers["x-content-type-options"] == "nosniff"


def test_analyze_validation(client):
    assert client.post("/api/analyze", json={}).status_code == 400
    assert client.post("/api/analyze", json={"source": "// nothing here"}).status_code == 422


def test_frontend_served(client):
    assert "Contract Explainer" in client.get("/").text
    assert client.get("/static/app.js").status_code == 200


def test_etherscan_source_shapes():
    plain = parse_source_field("contract A {}", "A")
    assert plain == [("A.sol", "contract A {}")]
    multi = parse_source_field(json.dumps({"A.sol": {"content": "contract A {}"}}), "A")
    assert multi == [("A.sol", "contract A {}")]
    std = "{" + json.dumps({"language": "Solidity", "sources": {"src/A.sol": {"content": "contract A {}"}}}) + "}"
    assert parse_source_field(std, "A") == [("src/A.sol", "contract A {}")]


def test_address_validation():
    assert validate_address(" 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 ")
    with pytest.raises(EtherscanError):
        validate_address("0x123")


def test_extract_json_tolerates_fences():
    assert extract_json('Sure!\n```json\n{"a": 1}\n```') == {"a": 1}


def test_anthropic_provider_request_and_parse():
    import httpx
    from app.llm import AnthropicProvider

    seen = {}

    def handler(request: httpx.Request):
        seen["headers"] = request.headers
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"content": [{"type": "text", "text": '{"ok": true}'}]})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await AnthropicProvider(c, "k", "claude-sonnet-5", 10).complete_json("sys", "user")

    assert asyncio.run(run()) == {"ok": True}
    assert seen["headers"]["x-api-key"] == "k"
    assert seen["body"]["model"] == "claude-sonnet-5" and seen["body"]["system"] == "sys"


def test_provider_selection_presets():
    from app.config import Settings

    s = Settings(api_keys={"gemini": "g"})
    assert s.resolved_provider == "gemini" and s.model == "gemini-2.5-flash" and s.concurrency == 2
    s = Settings(llm_provider="groq", api_keys={"groq": "q"}, models={"groq": "openai/gpt-oss-120b"})
    assert s.resolved_provider == "groq" and s.model == "openai/gpt-oss-120b"
    assert Settings(llm_provider="ollama").resolved_provider == "ollama"  # local, no key
    assert Settings(llm_provider="openai").resolved_provider == "none"  # key missing
    assert Settings(anthropic_api_key="a", api_keys={"gemini": "g"}).resolved_provider == "anthropic"


def test_openai_compatible_provider_retries_on_429():
    import httpx
    from app.llm import OpenAICompatibleProvider

    calls = []

    def handler(request: httpx.Request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429, headers={"retry-after": "0"}, text="slow down")
        return httpx.Response(200, json={"choices": [{"message": {"content": '```json\n{"ok": 1}\n```'}}]})

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            p = OpenAICompatibleProvider(c, "g", "gemini-2.5-flash", 10, name="gemini",
                                         base_url="https://generativelanguage.googleapis.com/v1beta/openai",
                                         json_mode=False, token_multiplier=2.0)
            return await p.complete_json("sys", "user", 1000)

    assert asyncio.run(run()) == {"ok": 1}
    assert len(calls) == 2
    body = json.loads(calls[1].content)
    assert str(calls[1].url) == "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    assert body["max_tokens"] == 2000 and "response_format" not in body
    assert calls[1].headers["authorization"] == "Bearer g"
