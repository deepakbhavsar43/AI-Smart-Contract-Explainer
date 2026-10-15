"""Deterministic, rule-based risk checks.

These run before (and independently of) the LLM so the core findings are
reproducible and cannot be hallucinated. The LLM later triages them
(confirmed / likely false positive) and explains them in plain English.

Covered:
  * reentrancy               - external call followed by a state write, no guard
  * access-control           - sensitive state-changing function callable by anyone
  * owner-powers             - privileged functions that can mint / drain / pause / blacklist / upgrade
  * tx-origin                - tx.origin used for authorization
  * unchecked-call           - low-level call / send whose return value is ignored
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .parser import FunctionInfo, ParsedSource

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    function_id: str
    function_name: str
    contract: str
    file: str
    lines: list[int]
    explanation: str
    fix: str
    source: str = "static"
    rule: str = ""
    triage: dict | None = None
    extra: dict = field(default_factory=dict)


# --------------------------------------------------------------------------- helpers

GUARD_MODIFIER_RE = re.compile(r"(nonreentrant|noreentran|reentrancyguard|^lock$|^mutex$|^nonreentrantview$)", re.I)
INIT_MODIFIER_RE = re.compile(r"^(initializer|reinitializer|onlyinitializing)$", re.I)
ACCESS_MODIFIER_RE = re.compile(
    r"^(only\w*|auth|requiresauth|restricted|isauthorized|authorized|ownable|admin\w*|\w*owner\w*|\w*role\w*|\w*governance\w*|\w*guardian\w*|\w*operator\w*|\w*minter\w*|\w*keeper\w*|\w*controller\w*)$",
    re.I,
)
NON_ACCESS_MODIFIERS = re.compile(r"^(when\w*|nonreentrant\w*|lock|initializer|reinitializer|onlyinitializing|validaddress|\w*valid\w*)$", re.I)

SENDER_CMP_RE = re.compile(
    r"(?:msg\.sender|_msgSender\(\))\s*(?:==|!=)\s*([A-Za-z_$][\w$]*)"
    r"|([A-Za-z_$][\w$]*)(?:\s*\(\s*\))?\s*(?:==|!=)\s*(?:msg\.sender|_msgSender\(\))"
)
BODY_ACCESS_RE = re.compile(
    r"(_checkOwner\s*\(|_checkRole\s*\(|hasRole\s*\(|_onlyOwner\s*\(|onlyOwner\s*\(|isOwner\s*\(|_isAdmin\s*\("
    r"|wards\s*\[\s*msg\.sender\s*\]|authorized\s*\[\s*msg\.sender\s*\]|isAuthorized\s*\(|_authorizeUpgrade\s*\(|auth\s*\(\s*msg\.sender)",
)
TX_ORIGIN_AUTH_RE = re.compile(r"(tx\.origin\s*(==|!=)|(==|!=)\s*tx\.origin)")

LOW_LEVEL_CALL_RE = re.compile(r"\.\s*call\s*(\{[^}]*\})?\s*\(")
VALUE_CALL_RE = re.compile(r"\.\s*call\s*(\{[^}]*value[^}]*\}|\.value\s*\()")
LEGACY_VALUE_CALL_RE = re.compile(r"\.\s*call\s*\.\s*value\s*\(")
DELEGATECALL_RE = re.compile(r"\.\s*delegatecall\s*\(")
TOKEN_CALL_RE = re.compile(r"(\.\s*(safeTransferFrom|safeTransfer|transferFrom|safeMint)\s*\(|\b_safeMint\s*\(|\b_safeTransfer\s*\()")
DOT_TRANSFER_RE = re.compile(r"\.\s*transfer\s*\(")
SEND_RE = re.compile(r"\.\s*send\s*\(")
SELFDESTRUCT_RE = re.compile(r"\b(selfdestruct|suicide)\s*\(")

SENSITIVE_NAME_RE = re.compile(
    r"^_?(set|update|change|configure|grant|revoke|pause|unpause|mint|blacklist|blocklist|whitelist|allowlist|"
    r"upgrade|kill|destroy|enable|disable|toggle|withdraw|rescue|sweep|drain|emergency|transferOwnership|"
    r"renounce|freeze|unfreeze|ban|addOwner|removeOwner|addAdmin|removeAdmin|addMinter|removeMinter)",
    re.I,
)
PRIVILEGED_VAR_RE = re.compile(r"(owner|admin|governance|governor|implementation|operator|minter|authority|guardian|controller|treasury)", re.I)
FUNDS_OUT_NAME_RE = re.compile(r"^_?(withdraw|rescue|sweep|drain|emergency|claim|collect|skim|payout)", re.I)
INIT_NAME_RE = re.compile(r"^_?(initiali[sz]e|init)\w*$", re.I)


def _lines(fn: FunctionInfo, start_rel: int, end_rel: int | None = None) -> list[int]:
    a = fn.line_at(start_rel)
    b = fn.line_at(end_rel) if end_rel is not None else a
    return [min(a, b), max(a, b)]


def _has_guard(fn: FunctionInfo) -> bool:
    return any(GUARD_MODIFIER_RE.search(m) for m in fn.modifiers)


def access_modifiers(fn: FunctionInfo) -> list[str]:
    return [m for m in fn.modifiers if ACCESS_MODIFIER_RE.match(m) and not NON_ACCESS_MODIFIERS.match(m)]


def is_access_controlled(fn: FunctionInfo, state_vars: set[str] | None = None) -> bool:
    """True if a modifier or an in-body check restricts the caller.

    `msg.sender == x` only counts when x is a state variable or looks like a privileged
    role (owner/admin/...); comparing against a parameter (e.g. ERC-20 `src`) is not auth.
    """
    if access_modifiers(fn) or BODY_ACCESS_RE.search(fn.body_masked):
        return True
    for m in SENDER_CMP_RE.finditer(fn.body_masked):
        other = m.group(1) or m.group(2)
        if other in {"address", "tx"}:
            continue
        if state_vars is None or other in state_vars or PRIVILEGED_VAR_RE.search(other):
            return True
    return False


def state_writes(fn: FunctionInfo, state_vars: set[str]) -> list[tuple[str, int]]:
    """(var_name, rel_offset) for each detected write to a state variable."""
    body = fn.masked
    start = max(fn.body_offset, 0)
    hits: list[tuple[str, int]] = []
    if not state_vars:
        return hits
    idx = r"(?:\s*\[[^\[\]]*(?:\[[^\[\]]*\][^\[\]]*)*\])*(?:\s*\.\s*[A-Za-z_]\w*(?:\s*\[[^\[\]]*\])*)*"
    names = "|".join(sorted((re.escape(v) for v in state_vars), key=len, reverse=True))
    patterns = [
        rf"(?<![\w.$])({names}){idx}\s*(?:=(?![=>])|\+=|-=|\*=|/=|%=|\|=|&=|\^=|<<=|>>=|\+\+|--)",
        rf"(?:\+\+|--)\s*({names})\b",
        rf"\bdelete\s+({names})\b",
        rf"(?<![\w.$])({names}){idx}\s*\.\s*(?:push|pop)\s*\(",
    ]
    for pat in patterns:
        for m in re.finditer(pat, body[start:]):
            hits.append((m.group(1), start + m.start()))
    hits.sort(key=lambda h: h[1])
    return hits


def external_calls(fn: FunctionInfo) -> list[tuple[str, int, int]]:
    """(kind, rel_start, rel_end) of external calls in the body.

    kind: 'value-call' | 'call' | 'delegatecall' | 'token' | 'transfer' | 'send'
    """
    body = fn.masked
    start = max(fn.body_offset, 0)
    seg = body[start:]
    out: list[tuple[str, int, int]] = []
    for m in LOW_LEVEL_CALL_RE.finditer(seg):
        stmt = seg[m.start() : m.start() + 120]
        kind = "value-call" if VALUE_CALL_RE.search(stmt[:60]) else "call"
        out.append((kind, start + m.start(), start + m.end()))
    for m in LEGACY_VALUE_CALL_RE.finditer(seg):
        out.append(("value-call", start + m.start(), start + m.end()))
    for m in DELEGATECALL_RE.finditer(seg):
        out.append(("delegatecall", start + m.start(), start + m.end()))
    for m in TOKEN_CALL_RE.finditer(seg):
        out.append(("token", start + m.start(), start + m.end()))
    for m in DOT_TRANSFER_RE.finditer(seg):
        close = _paren_close(seg, m.end() - 1)
        args = seg[m.end() : close]
        # token.transfer(to, amount) -> external token call; addr.transfer(amount) -> 2300-gas ETH send
        out.append(("token" if "," in args else "transfer", start + m.start(), start + m.end()))
    for m in SEND_RE.finditer(seg):
        out.append(("send", start + m.start(), start + m.end()))
    out.sort(key=lambda c: c[1])
    return out


def _paren_close(text: str, open_idx: int) -> int:
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return len(text)


def _statement_prefix(text: str, pos: int) -> str:
    """Text of the current statement up to pos."""
    cut = max(text.rfind(";", 0, pos), text.rfind("{", 0, pos), text.rfind("}", 0, pos))
    return text[cut + 1 : pos]


# --------------------------------------------------------------------------- rules

class _Builder:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self._n = 0

    def add(self, fn: FunctionInfo, **kw) -> None:
        self._n += 1
        self.findings.append(
            Finding(
                id=f"S{self._n}",
                function_id=fn.id,
                function_name=fn.name,
                contract=fn.contract,
                file=fn.file,
                **kw,
            )
        )


def run_static_checks(parsed: ParsedSource, functions: list[FunctionInfo]) -> list[Finding]:
    b = _Builder()
    for fn in functions:
        if not fn.has_body or fn.kind == "modifier":
            continue
        svars = parsed.state_var_names(fn.contract)
        _check_reentrancy(b, fn, svars)
        _check_tx_origin(b, fn)
        _check_unchecked_calls(b, fn)
        if fn.kind == "constructor":
            continue
        if fn.is_externally_callable and fn.is_state_changing:
            if is_access_controlled(fn, svars):
                _check_owner_powers(b, fn)
            elif not TX_ORIGIN_AUTH_RE.search(fn.masked):  # tx.origin auth is reported separately

                _check_missing_access_control(b, fn, svars)
    b.findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.file, f.lines[0]))
    return b.findings


def _check_reentrancy(b: _Builder, fn: FunctionInfo, svars: set[str]) -> None:
    if _has_guard(fn) or not fn.is_state_changing:
        return
    calls = [c for c in external_calls(fn) if c[0] in {"value-call", "call", "token", "delegatecall"}]
    if not calls:
        return
    writes = state_writes(fn, svars)
    for kind, c_start, c_end in calls:
        later = [w for w in writes if w[1] > c_end]
        if not later:
            continue
        var, w_off = later[0]
        strong = kind in {"value-call", "call"}
        b.add(
            fn,
            title=f"Possible reentrancy: `{var}` is updated after an external call",
            severity="high" if strong else "medium",
            category="reentrancy",
            lines=_lines(fn, c_start, w_off),
            rule="reentrancy-state-write-after-call",
            explanation=(
                f"`{fn.name}` makes an external call (line {fn.line_at(c_start)}) before updating state "
                f"variable `{var}` (line {fn.line_at(w_off)}). The callee can re-enter this contract while "
                f"`{var}` still holds its old value - the classic pattern behind the DAO hack."
                + ("" if strong else " The call goes through a token/NFT transfer, which can trigger receiver hooks (ERC-777/721/1155).")
            ),
            fix=(
                "Follow checks-effects-interactions: update state before the external call, "
                "and/or add OpenZeppelin `ReentrancyGuard` (`nonReentrant`) to this function."
            ),
        )
        return  # one reentrancy finding per function is enough


def _check_tx_origin(b: _Builder, fn: FunctionInfo) -> None:
    m = TX_ORIGIN_AUTH_RE.search(fn.masked)
    if not m:
        return
    b.add(
        fn,
        title="Authorization uses `tx.origin`",
        severity="high",
        category="access-control",
        lines=_lines(fn, m.start()),
        rule="tx-origin-auth",
        explanation=(
            "`tx.origin` is the wallet that started the transaction, not the immediate caller. A malicious "
            "contract the owner interacts with can call this function and pass the check (phishing attack)."
        ),
        fix="Use `msg.sender` for authorization (e.g. OpenZeppelin `Ownable` / `AccessControl`).",
    )


def _check_unchecked_calls(b: _Builder, fn: FunctionInfo) -> None:
    seg_start = max(fn.body_offset, 0)
    for kind, c_start, _ in external_calls(fn):
        if kind not in {"value-call", "call", "send", "delegatecall"}:
            continue
        prefix = _statement_prefix(fn.masked, c_start)
        if re.search(r"(=|\brequire\s*\(|\bassert\s*\(|\bif\s*\(|\breturn\b|\(\s*bool)", prefix):
            continue
        if c_start < seg_start:
            continue
        what = "send" if kind == "send" else "low-level call"
        b.add(
            fn,
            title=f"Return value of {what} is not checked",
            severity="medium",
            category="unchecked-call",
            lines=_lines(fn, c_start),
            rule="unchecked-low-level-call",
            explanation=(
                f"A {what} returns `false` instead of reverting when it fails. Ignoring the result lets the "
                "function continue as if the transfer succeeded, which can silently lose funds or corrupt accounting."
            ),
            fix="Capture and check the result: `(bool ok, ) = to.call{value: amt}(\"\"); require(ok, \"transfer failed\");`",
        )


def _check_missing_access_control(b: _Builder, fn: FunctionInfo, svars: set[str]) -> None:
    body = fn.body_masked
    writes = state_writes(fn, svars)
    user_scoped = bool(re.search(r"\[\s*(msg\.sender|_msgSender\(\))\s*\]", body))

    m = SELFDESTRUCT_RE.search(fn.masked)
    if m:
        b.add(
            fn,
            title="Anyone can destroy the contract (`selfdestruct` without access control)",
            severity="critical",
            category="access-control",
            lines=_lines(fn, m.start()),
            rule="unprotected-selfdestruct",
            explanation=f"`{fn.name}` is {fn.visibility} and has no owner/role check, yet it calls `selfdestruct`. Any account can call it and wipe the contract, sending its ETH to an arbitrary address.",
            fix="Remove `selfdestruct`, or restrict the function with `onlyOwner` / a role and a timelock.",
        )
        return

    for var, off in writes:
        if PRIVILEGED_VAR_RE.search(var):
            b.add(
                fn,
                title=f"Anyone can change privileged variable `{var}`",
                severity="critical",
                category="access-control",
                lines=_lines(fn, off),
                rule="unprotected-privileged-write",
                explanation=f"`{fn.name}` is {fn.visibility} with no access check and writes `{var}`. Any account can take over this role and every power attached to it.",
                fix="Add an access check (`onlyOwner`, `onlyRole(...)`, or `require(msg.sender == owner)`). For initializers, use OpenZeppelin `initializer`.",
            )
            return

    if INIT_NAME_RE.match(fn.name) and not any(INIT_MODIFIER_RE.match(m) for m in fn.modifiers):
        if not re.search(r"require\s*\(\s*!\s*\w*init", body, re.I) and not re.search(r"\binitiali[sz]ed\b", body):
            b.add(
                fn,
                title="Initializer can be called by anyone, more than once",
                severity="high",
                category="access-control",
                lines=[fn.start_line, fn.start_line],
                rule="unprotected-initializer",
                explanation=f"`{fn.name}` looks like an initializer but has no `initializer` modifier or 'already initialized' check, so anyone could (re)initialize the contract.",
                fix="Use OpenZeppelin `Initializable` with the `initializer` modifier, and initialize atomically at deployment.",
            )
            return

    m = DELEGATECALL_RE.search(body)
    if m:
        b.add(
            fn,
            title="Unrestricted `delegatecall`",
            severity="high",
            category="access-control",
            lines=_lines(fn, fn.body_offset + m.start()),
            rule="unprotected-delegatecall",
            explanation=f"`{fn.name}` can be called by anyone and performs a `delegatecall`, which runs foreign code with this contract's storage and balance.",
            fix="Restrict the function to a trusted role and only delegate to a fixed, audited target.",
        )
        return

    calls = [c for c in external_calls(fn) if c[0] in {"value-call", "call", "transfer", "send", "token"}]
    if calls and FUNDS_OUT_NAME_RE.match(fn.name) and not user_scoped and "msg.sender" not in body:
        sweeps_excess = bool(re.search(r"balanceOf\s*\(\s*address\s*\(\s*this\s*\)\s*\)\s*(\.\s*sub\s*\(|-)", body))
        b.add(
            fn,
            title=f"Anyone can move funds via `{fn.name}`",
            severity="medium" if sweeps_excess else "high",
            category="access-control",
            lines=_lines(fn, calls[0][1]),
            rule="unprotected-funds-transfer",
            explanation=f"`{fn.name}` sends ETH/tokens out of the contract, has no access check, and does not tie the amount to the caller's own balance.",
            fix="Restrict it (`onlyOwner` / role) or make it pay out only the caller's own recorded balance.",
        )
        return

    if SENSITIVE_NAME_RE.match(fn.name) and writes and not user_scoped:
        if fn.name.lower().startswith("mint") and re.search(r"msg\.value|balanceOf\s*\(\s*address\s*\(\s*this", body):
            return  # deposit-backed mint (e.g. AMM LP tokens / wrappers)
        var, off = writes[0]
        b.add(
            fn,
            title=f"`{fn.name}` changes contract settings without access control",
            severity="medium",
            category="access-control",
            lines=_lines(fn, off),
            rule="sensitive-function-no-access-control",
            explanation=f"`{fn.name}` is {fn.visibility}, has no owner/role check and writes `{var}`. Its name suggests an admin action; if so, anyone can call it.",
            fix="If this is meant to be an admin action, add `onlyOwner` / `onlyRole(...)`. If it is intentionally public, document why.",
        )


OWNER_POWER_RULES: list[tuple[str, re.Pattern, re.Pattern | None, str, str, str]] = [
    # (key, name pattern, body pattern, severity, title, explanation)
    ("selfdestruct", re.compile(r"$^"), SELFDESTRUCT_RE, "high",
     "Privileged role can destroy the contract",
     "The restricted caller can `selfdestruct` the contract, removing its code and sweeping its ETH."),
    ("upgrade", re.compile(r"^_?(upgrade|setImplementation|changeImplementation)", re.I), None, "medium",
     "Privileged role can upgrade the contract logic",
     "The restricted caller can replace the contract's logic, i.e. change any rule (including balances) at will."),
    ("mint", re.compile(r"^_?mint", re.I), re.compile(r"\b_mint\s*\(|totalSupply\s*\+="), "medium",
     "Privileged role can mint new tokens",
     "The restricted caller can create new tokens, diluting holders. Check whether supply is capped."),
    ("blacklist", re.compile(r"(blacklist|blocklist|denylist|freeze|^_?ban)", re.I), None, "medium",
     "Privileged role can block or freeze accounts",
     "The restricted caller can stop specific addresses from using their funds."),
    ("fee", re.compile(r"^_?(set|update|change)\w*(fee|tax|rate|commission)", re.I), None, "medium",
     "Privileged role can change fees",
     "The restricted caller can change fees/taxes. Without an upper bound this can be used to confiscate transfers."),
    ("withdraw", re.compile(r"^_?(withdraw|rescue|sweep|drain|emergency|recover)", re.I), re.compile(r"address\s*\(\s*this\s*\)\s*\.\s*balance"), "medium",
     "Privileged role can withdraw contract funds",
     "The restricted caller can move funds held by the contract. Confirm this cannot include user deposits."),
    ("pause", re.compile(r"^_?(pause|unpause)", re.I), re.compile(r"\b_pause\s*\("), "low",
     "Privileged role can pause the contract",
     "The restricted caller can halt key functionality (e.g. transfers) for all users."),
    ("arbitrary-call", re.compile(r"^_?(execute|exec|call|multicall|proxyCall)$", re.I), DELEGATECALL_RE, "high",
     "Privileged role can execute arbitrary calls",
     "The restricted caller can make the contract call any target with any data - effectively full control of its assets."),
]

OWNER_FIX = (
    "Put this power behind a multisig and a timelock, emit events for every change, and add hard limits "
    "(e.g. a supply cap or max fee) where possible. Document it clearly for users."
)


def _check_owner_powers(b: _Builder, fn: FunctionInfo) -> None:
    mods = access_modifiers(fn) or ["a sender check in the function body"]
    body = fn.body_masked
    for key, name_re, body_re, sev, title, expl in OWNER_POWER_RULES:
        hit_name = bool(name_re.search(fn.name))
        body_m = body_re.search(body) if body_re else None
        if not (hit_name or body_m):
            continue
        if key == "mint" and re.search(r"\b(cap|maxSupply|MAX_SUPPLY|supplyCap)\b", body):
            sev = "low"
        if key == "fee" and re.search(r"require\s*\([^;]*<=?", body):
            sev = "low"
        line = fn.line_at(fn.body_offset + body_m.start()) if body_m else fn.start_line
        b.add(
            fn,
            title=f"{title} (`{fn.name}`)",
            severity=sev,
            category="owner-powers",
            lines=[line, line],
            rule=f"owner-power-{key}",
            explanation=f"{expl} Restricted by: {', '.join(mods)}.",
            fix=OWNER_FIX,
        )
        return
