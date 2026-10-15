"""Fetch verified source code from Etherscan (API V2, one key for all chains)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import httpx

API_URL = "https://api.etherscan.io/v2/api"
ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

# key -> (chain id, explorer base url, label)
CHAINS: dict[str, tuple[int, str, str]] = {
    "mainnet": (1, "https://etherscan.io", "Ethereum Mainnet"),
    "sepolia": (11155111, "https://sepolia.etherscan.io", "Sepolia Testnet"),
    "polygon": (137, "https://polygonscan.com", "Polygon"),
    "arbitrum": (42161, "https://arbiscan.io", "Arbitrum One"),
    "optimism": (10, "https://optimistic.etherscan.io", "OP Mainnet"),
    "base": (8453, "https://basescan.org", "Base"),
    "bsc": (56, "https://bscscan.com", "BNB Smart Chain"),
}


class EtherscanError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


@dataclass
class FetchedContract:
    address: str
    chain: str
    name: str
    compiler: str
    files: list[tuple[str, str]]
    explorer_url: str
    is_proxy: bool = False
    implementation: str | None = None
    notes: list[str] = field(default_factory=list)


def validate_address(address: str) -> str:
    address = (address or "").strip()
    if not ADDRESS_RE.match(address):
        raise EtherscanError("That doesn't look like a contract address (expected 0x followed by 40 hex characters).")
    return address


def parse_source_field(raw: str, contract_name: str) -> list[tuple[str, str]]:
    """Etherscan returns source in three shapes: plain text, a JSON map of files,
    or Solidity standard-json input wrapped in an extra pair of braces."""
    raw = raw.strip()
    if raw.startswith("{{") and raw.endswith("}}"):
        data = json.loads(raw[1:-1])
        return [(p, v.get("content", "")) for p, v in data.get("sources", {}).items()]
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return [(f"{contract_name or 'Contract'}.sol", raw)]
        sources = data.get("sources", data)
        return [(p, v.get("content", "") if isinstance(v, dict) else str(v)) for p, v in sources.items()]
    return [(f"{contract_name or 'Contract'}.sol", raw)]


async def _get_source(client: httpx.AsyncClient, address: str, chain: str, api_key: str) -> dict:
    chain_id = CHAINS[chain][0]
    params = {
        "chainid": chain_id,
        "module": "contract",
        "action": "getsourcecode",
        "address": address,
        "apikey": api_key,
    }
    try:
        resp = await client.get(API_URL, params=params, timeout=20)
    except httpx.HTTPError as exc:
        raise EtherscanError(f"Could not reach Etherscan: {exc.__class__.__name__}", 502) from exc
    if resp.status_code != 200:
        raise EtherscanError(f"Etherscan returned HTTP {resp.status_code}", 502)
    data = resp.json()
    result = data.get("result")
    if data.get("status") != "1" or not isinstance(result, list) or not result:
        msg = result if isinstance(result, str) else data.get("message", "unknown error")
        status = 429 if "rate limit" in str(msg).lower() else 502
        raise EtherscanError(f"Etherscan error: {msg}", status)
    return result[0]


async def fetch_contract(
    client: httpx.AsyncClient, address: str, chain: str, api_key: str, follow_proxy: bool = True
) -> FetchedContract:
    if chain not in CHAINS:
        raise EtherscanError(f"Unsupported network '{chain}'.")
    if not api_key:
        raise EtherscanError(
            "Address lookup needs an Etherscan API key on the server (ETHERSCAN_API_KEY). Paste the Solidity code instead.",
            503,
        )
    address = validate_address(address)
    explorer = CHAINS[chain][1]
    item = await _get_source(client, address, chain, api_key)
    source = item.get("SourceCode") or ""
    if not source.strip():
        raise EtherscanError(f"No verified source code found for {address} on {CHAINS[chain][2]}.", 404)

    fetched = FetchedContract(
        address=address,
        chain=chain,
        name=item.get("ContractName", "") or "Contract",
        compiler=item.get("CompilerVersion", ""),
        files=parse_source_field(source, item.get("ContractName", "")),
        explorer_url=f"{explorer}/address/{address}#code",
    )

    impl = (item.get("Implementation") or "").strip()
    if follow_proxy and item.get("Proxy") == "1" and ADDRESS_RE.match(impl):
        try:
            impl_item = await fetch_contract(client, impl, chain, api_key, follow_proxy=False)
        except EtherscanError as exc:
            fetched.notes.append(f"This is a proxy; its implementation {impl} could not be fetched ({exc}).")
            fetched.is_proxy = True
            return fetched
        impl_item.is_proxy = True
        impl_item.implementation = impl
        impl_item.notes.append(
            f"{address} is a proxy ({fetched.name}). The report analyzes its current implementation "
            f"{impl_item.name} at {impl}. The proxy admin can swap this logic at any time."
        )
        impl_item.address = address
        impl_item.explorer_url = fetched.explorer_url
        return impl_item
    return fetched
