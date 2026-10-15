# Case study: AI Smart Contract Explainer

## Problem

Before anyone deposits into a protocol, buys a token, or signs off on a code review, someone has to read the contract. Solidity is dense, verified sources on Etherscan often span dozens of files, and the riskiest issues (reentrancy, missing access checks, owner powers that can mint or freeze funds) hide in a few lines. Professional audits take weeks and cost tens of thousands of dollars, so most contracts never get one, and reviewers spend hours on the first pass alone.

## Approach

A review assistant that does the first pass in under a minute and always shows its evidence:

1. **Fetch and split.** Pull verified source from Etherscan (multi-file and proxy aware) or accept pasted code. A purpose-built splitter masks comments and strings, then breaks the code into contracts, functions, modifiers and state variables with exact line numbers.
2. **Deterministic checks first.** Rule-based detectors for reentrancy, missing access control, unchecked owner powers, `tx.origin` auth and unchecked calls. These are reproducible and can't be hallucinated.
3. **LLM second.** Functions are batched to Claude with numbered code and the rule-based hits. The model writes plain-English summaries, states who can call each function, adds logic risks the rules can't see, and **triages each rule-based finding** as confirmed or a likely false positive.
4. **Validate everything the model says.** Unknown function ids are dropped, cited lines outside the function are clamped and labelled, duplicate findings are merged, and the overall risk score is computed from findings rather than chosen by the model.
5. **Report.** Overview, roles and permissions, key functions, ranked risks with suggested fixes, and a source viewer that highlights the cited lines. Exports to Markdown and JSON.

## Stack

FastAPI · Python · httpx · Gemini / Groq free tiers or Claude (any OpenAI-compatible API) · Etherscan API V2 · vanilla HTML/CSS/JS frontend · Docker · Render · pytest.

## Result

- Correctly flags the planted bugs in four test contracts (reentrancy, five access-control failures, four classes of owner power) and reports the fixed contract as clean. All of this is covered by 24 automated tests.
- Runs on real-world code (Uniswap V2 Pair/Factory, WETH9, OpenZeppelin ERC-20/Ownable) without parser failures, and correctly identifies their privileged roles.
- Works without an API key (static-only mode), so the demo never breaks and costs stay predictable. Per-IP rate limiting, function caps and caching keep AI spend bounded.
- _Add after deployment: live link, average analysis time, and 1–2 screenshots of AI output on a public contract._

## What I'd do next

Slither integration for compiler-level data flow, cross-function reentrancy, diff mode ("what changed between two versions"), and a GitHub Action that comments the report on pull requests.

> Positioned as a reviewer's assistant that speeds up reading and triage. It is not a substitute for a professional audit.
