"""Lightweight Solidity splitter.

Splits source into contracts -> functions/modifiers/state variables while keeping
exact line numbers, so every finding can cite real lines.

It is deliberately not a full compiler front-end: comments and string literals are
masked out (replaced with spaces, newlines preserved) and the structure is found
by brace matching on the masked text. This copes with every Solidity version and
with flattened files, and never executes or compiles anything.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field

IDENT = r"[A-Za-z_$][\w$]*"
VISIBILITIES = {"public", "external", "internal", "private"}
MUTABILITIES = {"view", "pure", "payable", "constant"}
NON_MODIFIER_WORDS = VISIBILITIES | MUTABILITIES | {"virtual", "override", "returns", "nonpayable"}
SKIP_MEMBER_KEYWORDS = {"struct", "enum", "event", "error", "using", "type", "pragma", "import"}


# --------------------------------------------------------------------------- masking

def mask_source(src: str) -> str:
    """Replace comments and string literal contents with spaces (newlines kept).

    Offsets in the masked text map 1:1 to the original source.
    """
    out = list(src)
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif c in "\"'":
            quote = c
            j = i + 1
            while j < n and src[j] != quote and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            # keep the quotes, blank the content
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
        else:
            i += 1
    return "".join(out)


def match_brace(text: str, open_idx: int, open_ch: str = "{", close_ch: str = "}") -> int:
    """Index of the bracket closing text[open_idx]; len(text)-1 if unbalanced."""
    depth = 0
    for i in range(open_idx, len(text)):
        ch = text[i]
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def split_top_level(text: str, sep: str = ",") -> list[str]:
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


# --------------------------------------------------------------------------- data

@dataclass
class SourceFile:
    path: str
    content: str
    masked: str = ""
    _nl: list[int] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        self.content = self.content.replace("\r\n", "\n").replace("\r", "\n")
        self.masked = mask_source(self.content)
        self._nl = [i for i, ch in enumerate(self.content) if ch == "\n"]

    def line_of(self, offset: int) -> int:
        """1-based line number of a character offset."""
        return bisect.bisect_left(self._nl, offset) + 1

    @property
    def line_count(self) -> int:
        return len(self._nl) + 1

    def lines(self, start: int, end: int) -> list[str]:
        all_lines = self.content.split("\n")
        return all_lines[start - 1 : end]


@dataclass
class StateVar:
    name: str
    type: str
    line: int
    constant: bool = False


@dataclass
class FunctionInfo:
    id: str
    contract: str
    name: str
    kind: str  # function | constructor | modifier | fallback | receive
    file: str
    start_line: int
    end_line: int
    signature: str
    params: str
    visibility: str
    mutability: str  # view | pure | payable | nonpayable
    modifiers: list[str]
    has_body: bool
    start_offset: int  # offset of the declaration in the file
    masked: str  # masked text of the whole declaration (header + body)
    body_offset: int  # offset (relative to start_offset) of the opening brace, -1 if no body
    source: SourceFile = field(repr=False, default=None)  # type: ignore[assignment]

    @property
    def code(self) -> str:
        return "\n".join(self.source.lines(self.start_line, self.end_line))

    @property
    def body_masked(self) -> str:
        return self.masked[self.body_offset :] if self.body_offset >= 0 else ""

    @property
    def is_state_changing(self) -> bool:
        return self.mutability not in {"view", "pure", "constant"}

    @property
    def is_externally_callable(self) -> bool:
        return self.kind in {"function", "fallback", "receive"} and self.visibility in {"public", "external"}

    def line_at(self, rel_offset: int) -> int:
        """Line number for an offset relative to the declaration start."""
        return self.source.line_of(self.start_offset + rel_offset)


@dataclass
class ContractInfo:
    name: str
    kind: str  # contract | abstract | interface | library
    file: str
    start_line: int
    end_line: int
    bases: list[str]
    state_vars: list[StateVar] = field(default_factory=list)
    functions: list[FunctionInfo] = field(default_factory=list)


@dataclass
class ParsedSource:
    files: list[SourceFile]
    contracts: list[ContractInfo]

    def contract(self, name: str) -> ContractInfo | None:
        for c in reversed(self.contracts):  # last definition wins in flattened files
            if c.name == name:
                return c
        return None

    def lineage(self, name: str) -> list[ContractInfo]:
        """Contract + all resolvable ancestors (C3-ish order: self first)."""
        seen: list[ContractInfo] = []
        stack = [name]
        while stack:
            cur = self.contract(stack.pop(0))
            if cur is None or cur in seen:
                continue
            seen.append(cur)
            stack.extend(cur.bases)
        return seen

    def state_var_names(self, contract_name: str) -> set[str]:
        names: set[str] = set()
        for c in self.lineage(contract_name):
            names.update(v.name for v in c.state_vars if not v.constant)
        return names


# --------------------------------------------------------------------------- parsing

CONTRACT_RE = re.compile(
    rf"\b(abstract\s+contract|contract|interface|library)\s+({IDENT})([^{{;]*)\{{"
)


def parse_sources(files: list[tuple[str, str]]) -> ParsedSource:
    sfiles = [SourceFile(path, content) for path, content in files]
    contracts: list[ContractInfo] = []
    for sf in sfiles:
        contracts.extend(_parse_file(sf))
    return ParsedSource(files=sfiles, contracts=contracts)


def _parse_file(sf: SourceFile) -> list[ContractInfo]:
    m_text = sf.masked
    out: list[ContractInfo] = []
    pos = 0
    while True:
        m = CONTRACT_RE.search(m_text, pos)
        if not m:
            break
        open_idx = m.end() - 1
        close_idx = match_brace(m_text, open_idx)
        kind_raw = m.group(1)
        kind = "abstract" if kind_raw.startswith("abstract") else kind_raw
        bases = _parse_bases(m.group(3))
        c = ContractInfo(
            name=m.group(2),
            kind=kind,
            file=sf.path,
            start_line=sf.line_of(m.start()),
            end_line=sf.line_of(close_idx),
            bases=bases,
        )
        _parse_members(sf, c, open_idx + 1, close_idx)
        out.append(c)
        pos = close_idx + 1
    return out


def _parse_bases(tail: str) -> list[str]:
    tail = tail.strip()
    if not tail.startswith("is"):
        return []
    tail = tail[2:]
    bases = []
    for part in split_top_level(tail):
        mm = re.match(rf"\s*({IDENT}(?:\.{IDENT})*)", part)
        if mm:
            bases.append(mm.group(1).split(".")[-1])
    return bases


def _parse_members(sf: SourceFile, c: ContractInfo, start: int, end: int) -> None:
    text = sf.masked
    i = start
    seg_start = start
    counters: dict[str, int] = {}
    while i < end:
        ch = text[i]
        if ch == "{":
            close = match_brace(text, i)
            _handle_member(sf, c, seg_start, i, close, counters)
            i = close + 1
            seg_start = i
            continue
        if ch == ";":
            _handle_member(sf, c, seg_start, -1, i, counters)
            i += 1
            seg_start = i
            continue
        i += 1


def _handle_member(sf, c, seg_start, brace_idx, seg_end, counters) -> None:
    text = sf.masked
    raw = text[seg_start : seg_end + 1]
    stripped = raw.lstrip()
    if not stripped.strip(" ;}\n\t"):
        return
    lead = len(raw) - len(stripped)
    decl_start = seg_start + lead
    first = re.match(rf"({IDENT})", stripped)
    if not first:
        return
    kw = first.group(1)

    if kw in {"function", "constructor", "modifier", "fallback", "receive"}:
        # `function(uint) external returns (uint) handler;` is a function-typed state var
        if kw == "function" and re.match(r"function\s*\(", stripped):
            _maybe_state_var(sf, c, stripped, decl_start)
            return
        fn = _parse_function(sf, c, kw, decl_start, brace_idx, seg_end, counters)
        if fn:
            c.functions.append(fn)
        return
    if kw in SKIP_MEMBER_KEYWORDS:
        return
    if brace_idx == -1:
        _maybe_state_var(sf, c, stripped, decl_start)


def _parse_function(sf, c, kw, decl_start, brace_idx, seg_end, counters) -> FunctionInfo | None:
    text = sf.masked
    header_end = brace_idx if brace_idx != -1 else seg_end
    header = text[decl_start:header_end]

    if kw in {"function", "modifier"}:
        mm = re.match(rf"{kw}\s+({IDENT})", header)
        if not mm:
            return None
        name = mm.group(1)
    else:
        name = kw

    p_open = header.find("(")
    if p_open == -1:  # e.g. `modifier onlyOwner {` (parens optional for modifiers)
        params, rest = "", header[len(kw) :].replace(name, "", 1)
    else:
        p_close = match_brace(header, p_open, "(", ")")
        params = " ".join(header[p_open + 1 : p_close].split())
        rest = header[p_close + 1 :]

    # drop `returns (...)` and `override(A, B)` argument lists
    rm = re.search(r"\breturns\s*\(", rest)
    if rm:
        rc = match_brace(rest, rm.end() - 1, "(", ")")
        rest = rest[: rm.start()] + " " + rest[rc + 1 :]
    rest = re.sub(r"\boverride\s*\([^)]*\)", " override ", rest)

    visibility, mutability, modifiers = "", "nonpayable", []
    for tok in re.finditer(rf"({IDENT}(?:\.{IDENT})*)\s*(\([^)]*\))?", rest):
        word = tok.group(1)
        if word in VISIBILITIES:
            visibility = word
        elif word in MUTABILITIES:
            mutability = "view" if word == "constant" else word
        elif word in NON_MODIFIER_WORDS:
            continue
        else:
            modifiers.append(word)

    if not visibility:
        visibility = {
            "fallback": "external",
            "receive": "external",
            "modifier": "internal",
            "constructor": "public",
        }.get(kw, "public")  # pre-0.5 default
    if kw == "constructor" and modifiers and modifiers[0] == name:
        modifiers = modifiers[1:]

    if kw == "function" and name == c.name:  # pre-0.4.22 constructor syntax
        kw = "constructor"

    key = f"{c.name}.{name}"
    counters[key] = counters.get(key, 0) + 1
    fid = key if counters[key] == 1 else f"{key}#{counters[key]}"

    signature = " ".join(sf.content[decl_start:header_end].split())
    return FunctionInfo(
        id=fid,
        contract=c.name,
        name=name,
        kind=kw,
        file=sf.path,
        start_line=sf.line_of(decl_start),
        end_line=sf.line_of(seg_end),
        signature=signature,
        params=params,
        visibility=visibility,
        mutability=mutability,
        modifiers=modifiers,
        has_body=brace_idx != -1,
        start_offset=decl_start,
        masked=text[decl_start : seg_end + 1],
        body_offset=(brace_idx - decl_start) if brace_idx != -1 else -1,
        source=sf,
    )


def _maybe_state_var(sf, c, stripped: str, decl_start: int) -> None:
    decl = stripped.rstrip().rstrip(";")
    # cut initializer at a top-level '=' that isn't part of '=>' / '=='
    depth, cut = 0, len(decl)
    for idx, ch in enumerate(decl):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "=" and depth == 0:
            nxt = decl[idx + 1] if idx + 1 < len(decl) else ""
            prev = decl[idx - 1] if idx else ""
            if nxt not in "=>" and prev not in "=!<>":
                cut = idx
                break
    decl = decl[:cut].strip()
    words = re.findall(IDENT, re.sub(r"\([^()]*(\([^()]*\)[^()]*)*\)", " ", decl))
    if len(words) < 2:
        return
    name = words[-1]
    if name in NON_MODIFIER_WORDS or name in {"immutable", "constant"}:
        return
    constant = bool(re.search(r"\b(constant|immutable)\b", decl))
    c.state_vars.append(
        StateVar(name=name, type=" ".join(decl.split()[:1]), line=sf.line_of(decl_start), constant=constant)
    )


def pick_main_contract(parsed: ParsedSource, preferred: str | None = None) -> ContractInfo | None:
    if preferred:
        c = parsed.contract(preferred)
        if c:
            return c
    concrete = [c for c in parsed.contracts if c.kind in {"contract", "abstract"}]
    if not concrete:
        return parsed.contracts[-1] if parsed.contracts else None
    # prefer a contract that nobody else inherits from (the most-derived one)
    inherited = {b for c in parsed.contracts for b in c.bases}
    leaves = [c for c in concrete if c.name not in inherited and c.kind == "contract"]
    pool = leaves or concrete
    return pool[-1]
