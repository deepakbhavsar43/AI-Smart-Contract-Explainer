"""Render an analysis report as Markdown (for download / sharing)."""
from __future__ import annotations

SEV_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}


def to_markdown(r: dict) -> str:
    m, o = r["meta"], r["overview"]
    out: list[str] = [f"# Contract review: {m['name']}", ""]
    if m.get("address"):
        out.append(f"**Address:** [{m['address']}]({m.get('explorer_url', '')}) on {m.get('chain_label', m.get('chain', ''))}  ")
    out += [
        f"**Type:** {m['contract_type']}  ",
        f"**Overall risk:** {o['overall_risk'].upper()}  ",
        f"**Generated:** {m['analyzed_at']}"
        + (f" with {m['ai_provider']} `{m['ai_model']}`" if m.get("ai_enabled") else " (static analysis only)"),
        "",
        f"> {r['disclaimer']}",
        "",
    ]
    for note in m.get("notes", []):
        out.append(f"> Note: {note}")
    out += ["", "## Overview", "", o["text"], "", o["risk_summary"], ""]

    counts = r["severity_counts"]
    out += ["| Critical | High | Medium | Low | Info | Dismissed |", "|---|---|---|---|---|---|",
            f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} | {counts['info']} | {counts['dismissed']} |", ""]

    if r["roles"]:
        out += ["## Roles and permissions", ""]
        for role in r["roles"]:
            out.append(f"**{role['role']}** - {role.get('description', '')}")
            out += [f"- {p}" for p in role.get("powers", [])]
            out.append("")

    fns = {f["id"]: f for f in r["functions"]}
    if r["key_functions"]:
        out += ["## Key functions", "", "| Function | Who can call | What it does |", "|---|---|---|"]
        for fid in r["key_functions"]:
            f = fns[fid]
            summary = f["summary"].replace("|", "\\|").replace("\n", " ")
            out.append(f"| `{f['contract']}.{f['name']}` (L{f['start_line']}) | {f.get('who_can_call_ai') or f['who_can_call']} | {summary} |")
        out.append("")

    out += ["## Risks", ""]
    if not r["findings"]:
        out += ["No issues were flagged.", ""]
    for f in r["findings"]:
        tri = f.get("triage") or {}
        dismissed = tri.get("verdict") == "likely_false_positive"
        src = "Rule-based check" if f["source"] == "static" else "AI review"
        title = f"~~{f['title']}~~ (likely false positive)" if dismissed else f["title"]
        out += [
            f"### [{SEV_LABEL[f['severity']]}] {title}",
            "",
            f"*{src}* - `{f['contract']}.{f['function_name']}` - {f['file']} lines {f['lines'][0]}-{f['lines'][1]}",
            "",
            f["explanation"],
            "",
            f"**Suggested fix:** {f['fix']}",
            "",
        ]
        if tri:
            out += [f"*AI triage: {tri['verdict'].replace('_', ' ')} - {tri.get('reason', '')}*", ""]

    if r["fixes"]:
        out += ["## Suggested fixes (prioritized)", ""]
        out += [f"{i}. {fx}" for i, fx in enumerate(r["fixes"], 1)]
        out.append("")
    return "\n".join(out)
