/* Contract Explainer frontend - plain JS, no build step.
 * All user/contract text is inserted with textContent (never innerHTML) to avoid XSS. */
(() => {
  "use strict";

  const $ = (sel) => document.querySelector(sel);
  const SEVERITIES = ["critical", "high", "medium", "low", "info"];
  const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };
  const CATEGORY_LABEL = {
    "reentrancy": "Reentrancy",
    "access-control": "Access control",
    "owner-powers": "Owner powers",
    "unchecked-call": "Unchecked call",
    "tx-origin": "tx.origin",
    "logic": "Logic",
    "other": "Other",
  };

  const state = {
    config: null,
    mode: "address",
    filename: "",
    report: null,
    tab: "overview",
    filters: { severity: "all", source: "all", showDismissed: false },
    sourcePath: null,
    progressTimer: null,
  };

  /* ------------------------------------------------------------------ dom helper */
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === "class") el.className = v;
        else if (k === "text") el.textContent = v;
        else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
        else if (k === "dataset") Object.assign(el.dataset, v);
        else el.setAttribute(k, v === true ? "" : v);
      }
    }
    for (const c of children.flat(Infinity)) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  /** Render text with `inline code` spans (safe: only creates text nodes and <code>). */
  function rich(text) {
    const frag = document.createDocumentFragment();
    String(text || "").split(/(`[^`]+`)/g).forEach((part) => {
      if (part.startsWith("`") && part.endsWith("`") && part.length > 2) frag.append(h("code", null, part.slice(1, -1)));
      else if (part) frag.append(document.createTextNode(part));
    });
    return frag;
  }

  /* ------------------------------------------------------------------ theme */
  $("#theme-toggle").addEventListener("click", () => {
    const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("theme", next); } catch (e) { /* ignore */ }
  });

  /* ------------------------------------------------------------------ input tabs */
  function setMode(mode) {
    state.mode = mode;
    document.querySelectorAll(".input-card .tab").forEach((t) => {
      const on = t.dataset.tab === mode;
      t.classList.toggle("active", on);
      t.setAttribute("aria-selected", String(on));
    });
    $("#panel-address").classList.toggle("hidden", mode !== "address");
    $("#panel-code").classList.toggle("hidden", mode !== "code");
  }
  document.querySelectorAll(".input-card .tab").forEach((t) => t.addEventListener("click", () => setMode(t.dataset.tab)));

  $("#file-input").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const max = (state.config && state.config.max_source_bytes) || 600000;
    if (file.size > max) return showError(`That file is larger than ${Math.round(max / 1000)} KB.`);
    const reader = new FileReader();
    reader.onload = () => {
      $("#source").value = String(reader.result || "");
      state.filename = file.name;
      $("#file-name").textContent = file.name;
      clearActiveChips();
    };
    reader.readAsText(file);
    e.target.value = "";
  });
  $("#source").addEventListener("input", () => {
    if (state.filename) { state.filename = ""; $("#file-name").textContent = ""; clearActiveChips(); }
  });

  function clearActiveChips() { document.querySelectorAll(".chip.active").forEach((c) => c.classList.remove("active")); }

  /* ------------------------------------------------------------------ config + samples */
  async function loadConfig() {
    try {
      const res = await fetch("/api/config");
      state.config = await res.json();
    } catch (e) {
      state.config = { ai_enabled: false, address_lookup: false, chains: [{ key: "mainnet", label: "Ethereum Mainnet" }], samples: [] };
    }
    const cfg = state.config;
    const pill = $("#ai-status");
    if (cfg.ai_enabled) {
      pill.className = "pill pill-ok";
      pill.textContent = `AI on · ${cfg.ai_model}`;
    } else {
      pill.className = "pill pill-muted";
      pill.textContent = "AI off · static checks only";
      $("#use-ai").checked = false;
      $("#use-ai").disabled = true;
    }
    const sel = $("#chain");
    sel.replaceChildren(...cfg.chains.map((c) => h("option", { value: c.key }, c.label)));
    if (!cfg.address_lookup) {
      $("#address-hint").textContent = "Address lookup is not configured on this server (no Etherscan key). Paste the Solidity code instead.";
      $("#address-hint").classList.add("alert", "alert-info");
    }

    const codeChips = $("#samples-code");
    const addrChips = $("#samples-address");
    cfg.samples.forEach((s) => {
      const chip = h("button", { class: "chip", type: "button", title: s.hint || "" },
        s.label, s.hint ? h("span", { class: "chip-hint" }, s.hint) : null);
      chip.addEventListener("click", () => useSample(s, chip));
      (s.kind === "code" ? codeChips : addrChips).append(chip);
    });
  }

  async function useSample(s, chip) {
    clearActiveChips();
    chip.classList.add("active");
    hideError();
    if (s.kind === "address") {
      setMode("address");
      $("#address").value = s.address;
      $("#chain").value = s.chain || "mainnet";
      return;
    }
    setMode("code");
    try {
      const res = await fetch(`/api/samples/${encodeURIComponent(s.id)}`);
      if (!res.ok) throw new Error("Could not load sample");
      $("#source").value = await res.text();
      state.filename = (s.label || "Sample").replace(/[^\w]+/g, "") + ".sol";
      $("#file-name").textContent = s.label;
    } catch (e) {
      showError(e.message);
    }
  }

  /* ------------------------------------------------------------------ errors */
  function showError(msg) { const el = $("#error"); el.textContent = msg; el.classList.remove("hidden"); }
  function hideError() { $("#error").classList.add("hidden"); }

  /* ------------------------------------------------------------------ progress */
  function startProgress(useAI) {
    const steps = [];
    if (state.mode === "address") steps.push("Fetching verified source from the explorer");
    steps.push("Splitting the code into contracts and functions");
    steps.push("Running rule-based risk checks");
    if (useAI) steps.push("AI is reviewing each function");
    steps.push("Writing the report");
    const list = $("#progress-steps");
    list.replaceChildren(...steps.map((s) => h("li", null, h("span", { class: "dot", "aria-hidden": "true" }), s)));
    $("#progress").classList.remove("hidden");
    let i = 0;
    const items = [...list.children];
    items[0].classList.add("active");
    const delays = useAI ? 1600 : 450;
    state.progressTimer = setInterval(() => {
      if (i >= items.length - 2) return; // hold on the second-to-last step until the server answers
      items[i].classList.replace("active", "done");
      i += 1;
      items[i].classList.add("active");
    }, delays);
  }
  function stopProgress() {
    clearInterval(state.progressTimer);
    $("#progress").classList.add("hidden");
  }

  /* ------------------------------------------------------------------ submit */
  $("#analyze-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    hideError();
    const useAI = $("#use-ai").checked;
    const payload = { use_ai: useAI };
    if (state.mode === "address") {
      const address = $("#address").value.trim();
      if (!/^0x[a-fA-F0-9]{40}$/.test(address)) return showError("Enter a contract address: 0x followed by 40 hex characters.");
      payload.address = address;
      payload.chain = $("#chain").value;
    } else {
      const source = $("#source").value;
      if (!source.trim()) return showError("Paste some Solidity code, upload a .sol file, or pick a sample.");
      payload.source = source;
      payload.filename = state.filename || "Contract.sol";
    }

    const btn = $("#analyze-btn");
    btn.disabled = true;
    btn.querySelector(".btn-label").textContent = "Analyzing…";
    $("#report").classList.add("hidden");
    startProgress(useAI && state.config && state.config.ai_enabled);
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : `Request failed (${res.status})`);
      state.report = data;
      state.tab = "overview";
      state.filters = { severity: "all", source: "all", showDismissed: false };
      state.sourcePath = null;
      renderReport();
      $("#report").scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (err) {
      showError(err.message || "Something went wrong.");
    } finally {
      stopProgress();
      btn.disabled = false;
      btn.querySelector(".btn-label").textContent = "Analyze contract";
    }
  });

  /* ------------------------------------------------------------------ report */
  function activeFindings(r) {
    return r.findings.filter((f) => !(f.triage && f.triage.verdict === "likely_false_positive"));
  }

  function renderReport() {
    const r = state.report;
    const root = $("#report");
    root.classList.remove("hidden");
    const m = r.meta;
    const counts = r.severity_counts;
    const findingsActive = activeFindings(r);

    const sub = h("div", { class: "report-sub" },
      h("span", null, m.contract_type),
      m.address ? [h("span", { "aria-hidden": "true" }, "·"),
        h("a", { class: "mono", href: m.explorer_url, target: "_blank", rel: "noopener noreferrer" }, m.address)] : null,
      m.chain_label ? [h("span", { "aria-hidden": "true" }, "·"), h("span", null, m.chain_label)] : null,
      m.compiler ? [h("span", { "aria-hidden": "true" }, "·"), h("span", null, m.compiler)] : null,
    );

    const risk = r.overview.overall_risk;
    const head = h("section", { class: "card report-head-card" },
      h("div", { class: "report-head" },
        h("div", { class: "report-title" },
          h("div", null, h("h2", null, m.name), sub),
          h("div", { class: `risk-badge sev sev-${risk}`, title: r.overview.overall_risk_basis },
            h("span", { class: "k" }, "Overall risk"), h("span", { class: "v" }, risk)),
        ),
        h("div", { class: "stats" },
          stat(r.functions.filter((f) => f.kind !== "modifier").length, "Functions"),
          ...["critical", "high", "medium", "low"].map((s) => stat(counts[s], SEV_LABEL[s], `sev sev-${s}`)),
          counts.dismissed ? stat(counts.dismissed, "Dismissed by AI") : null,
        ),
        h("div", { class: "notice" }, h("strong", null, "Assistant, not an audit. "), r.disclaimer.replace(/^This report[^.]*\.\s*/, "")),
        !m.ai_enabled ? h("div", { class: "notice" }, h("strong", null, "AI layer off. "),
          "Summaries are rule-based. Turn on AI (server needs an API key) for plain-English explanations, extra risks and false-positive triage.") : null,
        ...(m.notes || []).map((n) => h("div", { class: "notice" }, h("strong", null, "Note. "), n)),
        h("div", { class: "export" },
          h("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: downloadMarkdown }, "Download Markdown"),
          h("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: downloadJSON }, "Download JSON"),
          h("button", { class: "btn btn-ghost btn-sm", type: "button", onclick: copySummary }, "Copy summary"),
        ),
      ),
      h("div", { class: "tabs report-tabs", role: "tablist" },
        reportTab("overview", "Overview"),
        reportTab("risks", "Risks", findingsActive.length),
        reportTab("functions", "Functions", r.functions.filter((f) => f.kind !== "modifier").length),
        reportTab("source", "Source"),
      ),
    );
    root.replaceChildren(head, h("div", { class: "report-body", id: "report-body" }));
    renderTab();
  }

  function stat(v, k, cls) {
    return h("div", { class: `stat ${cls || ""}` }, h("div", { class: "v" }, String(v)), h("div", { class: "k" }, k));
  }

  function reportTab(key, label, count) {
    return h("button", {
      class: `tab${state.tab === key ? " active" : ""}`, role: "tab", type: "button",
      "aria-selected": String(state.tab === key), dataset: { rtab: key },
      onclick: () => switchTab(key),
    }, label, count !== undefined ? h("span", { class: "count" }, String(count)) : null);
  }

  function switchTab(key) {
    state.tab = key;
    document.querySelectorAll(".report-tabs .tab").forEach((t) => {
      const on = t.dataset.rtab === key;
      t.classList.toggle("active", on);
      t.setAttribute("aria-selected", String(on));
    });
    renderTab();
  }

  function renderTab() {
    const body = $("#report-body");
    const view = { overview: viewOverview, risks: viewRisks, functions: viewFunctions, source: viewSource }[state.tab];
    body.replaceChildren(view(state.report));
  }

  /* ---------- overview */
  function viewOverview(r) {
    const fns = Object.fromEntries(r.functions.map((f) => [f.id, f]));
    const left = h("div", { class: "stack" },
      h("section", { class: "card section" }, h("h3", null, "What this contract does"), h("p", null, rich(r.overview.text))),
      h("section", { class: "card section" },
        h("h3", null, "Risk summary"),
        h("p", null, rich(r.overview.risk_summary)),
        r.fixes.length ? [h("h3", null, "Suggested fixes"), h("ol", { class: "fixes" }, r.fixes.map((f) => h("li", null, rich(f))))] : null,
      ),
    );
    const right = h("div", { class: "stack" },
      h("section", { class: "card section" },
        h("h3", null, "Roles and permissions"),
        r.roles.length
          ? h("div", { class: "roles" }, r.roles.map((role) => h("div", { class: "role" },
              h("h4", null, role.role),
              role.description ? h("p", null, rich(role.description)) : null,
              h("ul", null, (role.powers || []).map((p) => h("li", null, rich(p)))))))
          : h("p", null, "No privileged roles detected. Every external function is open to anyone, or access is enforced elsewhere."),
      ),
      h("section", { class: "card section" },
        h("h3", null, "Key functions"),
        h("div", { class: "keyfns" }, r.key_functions.map((id) => {
          const f = fns[id];
          if (!f) return null;
          return h("div", { class: "keyfn" },
            h("div", null,
              h("button", { class: "loc", type: "button", onclick: () => openFunction(id) }, `${f.name}()`),
              h("div", { class: "who" }, f.who_can_call_ai || f.who_can_call)),
            h("div", { class: "desc" }, rich(f.summary)));
        })),
      ),
    );
    return h("div", { class: "grid-2" }, left, right);
  }

  /* ---------- risks */
  function viewRisks(r) {
    const f = state.filters;
    const wrap = h("div");
    const counts = {};
    r.findings.forEach((x) => { counts[x.severity] = (counts[x.severity] || 0) + 1; });
    const sevChips = ["all", ...SEVERITIES.filter((s) => counts[s])].map((s) =>
      h("button", { class: `chip${f.severity === s ? " active" : ""}`, type: "button",
        onclick: () => { f.severity = s; renderTab(); } }, s === "all" ? "All" : `${SEV_LABEL[s]} (${counts[s]})`));
    const srcChips = [["all", "Any source"], ["static", "Rule-based"], ["ai", "AI"]].map(([k, label]) =>
      h("button", { class: `chip${f.source === k ? " active" : ""}`, type: "button",
        onclick: () => { f.source = k; renderTab(); } }, label));
    const dismissed = r.severity_counts.dismissed;
    wrap.append(h("div", { class: "filters" }, sevChips, h("span", { class: "muted small" }, "·"), srcChips,
      dismissed ? h("button", { class: `chip${f.showDismissed ? " active" : ""}`, type: "button",
        onclick: () => { f.showDismissed = !f.showDismissed; renderTab(); } }, `Show dismissed (${dismissed})`) : null));

    const list = r.findings.filter((x) =>
      (f.severity === "all" || x.severity === f.severity) &&
      (f.source === "all" || x.source === f.source) &&
      (f.showDismissed || !(x.triage && x.triage.verdict === "likely_false_positive")));

    if (!list.length) {
      wrap.append(h("div", { class: "card empty" },
        h("strong", null, r.findings.length ? "No findings match these filters" : "No risks flagged"),
        r.findings.length ? "Try another filter." : "The rule-based checks and AI review found nothing notable. That is not a guarantee: logic bugs can still exist."));
      return wrap;
    }
    wrap.append(h("div", { class: "findings" }, list.map((x) => findingCard(r, x))));
    return wrap;
  }

  function findingCard(r, x) {
    const tri = x.triage;
    const dismissed = tri && tri.verdict === "likely_false_positive";
    const triTag = tri ? h("span", { class: `tag ${tri.verdict === "confirmed" ? "tag-ok" : "tag-warn"}` },
      tri.verdict === "confirmed" ? "AI confirmed" : tri.verdict === "likely_false_positive" ? "AI: likely false positive" : "AI: needs review") : null;
    const lineLabel = x.lines[0] === x.lines[1] ? `L${x.lines[0]}` : `L${x.lines[0]}–${x.lines[1]}`;
    const fn = r.functions.find((f) => f.id === x.function_id);
    return h("article", { class: `card finding sev sev-${x.severity}${dismissed ? " dismissed" : ""}` },
      h("div", { class: "finding-head" },
        h("span", { class: "sev-badge" }, SEV_LABEL[x.severity]),
        h("h4", null, rich(x.title))),
      h("div", { class: "tags" },
        h("span", { class: `tag${x.source === "ai" ? " tag-ai" : ""}` }, x.source === "ai" ? "AI review" : "Rule-based"),
        h("span", { class: "tag" }, CATEGORY_LABEL[x.category] || x.category),
        triTag,
        h("button", { class: "loc", type: "button", title: "Show in source", onclick: () => jumpToSource(x.file, x.lines[0]) },
          `${x.contract}.${x.function_name} · ${lineLabel}`)),
      h("p", null, rich(x.explanation)),
      x.line_note ? h("p", { class: "muted small" }, x.line_note) : null,
      x.fix ? h("div", { class: "fix" }, h("b", null, "Suggested fix: "), rich(x.fix)) : null,
      tri && tri.reason ? h("div", { class: "triage" }, `AI triage: ${tri.reason}`) : null,
      fn ? h("details", { class: "snippet" }, h("summary", null, "Show code"),
        codeView(r, x.file, fn.start_line, fn.end_line, new Map(range(x.lines[0], x.lines[1]).map((n) => [n, x.severity])))) : null,
    );
  }

  /* ---------- functions */
  function viewFunctions(r) {
    const card = h("section", { class: "card fn-list" });
    const groups = new Map();
    r.functions.filter((f) => f.kind !== "modifier").forEach((f) => {
      const key = f.is_dependency ? "Dependencies" : f.contract;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(f);
    });
    const findingsByFn = new Map();
    activeFindings(r).forEach((x) => {
      if (!findingsByFn.has(x.function_id)) findingsByFn.set(x.function_id, []);
      findingsByFn.get(x.function_id).push(x);
    });
    for (const [group, fns] of groups) {
      const contract = r.contracts.find((c) => c.name === group);
      card.append(h("div", { class: "group-label" }, group,
        contract && contract.bases.length ? h("span", { class: "muted" }, `  is ${contract.bases.join(", ")}`) : null));
      fns.forEach((f) => {
        const fx = findingsByFn.get(f.id) || [];
        const worst = SEVERITIES.find((s) => fx.some((x) => x.severity === s));
        const hl = new Map();
        fx.forEach((x) => range(x.lines[0], x.lines[1]).forEach((n) => hl.set(n, x.severity)));
        const det = h("details", { class: "fn", id: `fn-${cssId(f.id)}` },
          h("summary", null,
            h("div", null,
              h("div", { class: "fn-name" }, f.contract !== group ? h("span", { class: "ctr" }, `${f.contract}.`) : null, `${f.name}()`),
              h("div", { class: "badges" },
                h("span", { class: "mini" }, f.kind === "function" ? f.visibility : f.kind),
                f.mutability !== "nonpayable" ? h("span", { class: "mini" }, f.mutability) : null,
                f.modifiers.map((mo) => h("span", { class: "mini" }, mo)),
                f.ai_analyzed ? h("span", { class: "mini" }, "AI") : null)),
            h("div", null,
              h("div", { class: "fn-desc" }, rich(f.summary)),
              h("div", { class: `fn-who` }, `Who can call: ${f.who_can_call_ai || f.who_can_call}`)),
            h("div", { class: `fn-risk ${worst ? `sev sev-${worst}` : ""}` },
              worst ? h("span", { class: "sev-badge" }, `${fx.length} ${fx.length === 1 ? "risk" : "risks"}`) : h("span", { class: "muted small" }, "—")),
          ),
          h("div", { class: "fn-body" }));
        det.addEventListener("toggle", () => {
          const body = det.querySelector(".fn-body");
          if (det.open && !body.firstChild) body.append(codeView(r, f.file, f.start_line, f.end_line, hl));
        }, { once: false });
        card.append(det);
      });
    }
    return card;
  }

  function openFunction(id) {
    switchTab("functions");
    const el = document.getElementById(`fn-${cssId(id)}`);
    if (el) { el.open = true; el.scrollIntoView({ behavior: "smooth", block: "center" }); }
  }

  /* ---------- source */
  function viewSource(r) {
    const files = r.sources;
    if (!state.sourcePath || !files.some((s) => s.path === state.sourcePath)) {
      const main = r.contracts.find((c) => c.is_main);
      state.sourcePath = main ? main.file : files[0].path;
    }
    const file = files.find((s) => s.path === state.sourcePath);
    const hl = new Map();
    activeFindings(r).filter((x) => x.file === file.path).forEach((x) =>
      range(x.lines[0], x.lines[1]).forEach((n) => { if (!hl.has(n)) hl.set(n, x.severity); }));
    const select = files.length > 1 ? h("select", { "aria-label": "Source file", onchange: (e) => { state.sourcePath = e.target.value; renderTab(); } },
      files.map((s) => h("option", { value: s.path, selected: s.path === file.path }, s.path))) : h("span", { class: "mono small" }, file.path);
    const skipped = r.meta.files_skipped && r.meta.files_skipped.length
      ? h("span", { class: "muted small" }, `${r.meta.files_skipped.length} other file(s) (interfaces/libraries) not shown`) : null;
    return h("section", { class: "card section" },
      h("div", { class: "source-bar" }, select, h("span", { class: "muted small" }, `${file.lines} lines · highlighted lines have findings`), skipped),
      codeView(r, file.path, 1, file.lines, hl, true));
  }

  function jumpToSource(path, line) {
    state.sourcePath = path;
    switchTab("source");
    requestAnimationFrame(() => {
      const el = document.getElementById(`src-L${line}`);
      if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
    });
  }

  /* ------------------------------------------------------------------ code rendering */
  const KEYWORDS = new Set(("pragma solidity contract interface library abstract is function modifier constructor fallback receive " +
    "event error emit struct enum mapping returns return if else for while do break continue new delete require revert assert " +
    "using import from as public private internal external view pure payable virtual override constant immutable memory storage " +
    "calldata indexed anonymous unchecked try catch assembly let true false this super msg tx block selfdestruct type").split(" "));
  const TYPE_RE = /^(u?int\d*|bytes\d*|address|bool|string|byte|u?fixed[\dx]*)$/;
  const TOKEN_RE = /(\/\/.*$)|(\/\*)|("(?:\\.|[^"\\])*"?|'(?:\\.|[^'\\])*'?)|(\b0x[0-9a-fA-F]+\b|\b\d[\d_]*(?:\.\d+)?(?:e\d+)?\b)|([A-Za-z_$][\w$]*)/g;

  function tokenizeLine(text, st) {
    const out = [];
    let i = 0;
    if (st.inComment) {
      const end = text.indexOf("*/");
      if (end === -1) return [["co", text]];
      out.push(["co", text.slice(0, end + 2)]);
      i = end + 2;
      st.inComment = false;
    }
    TOKEN_RE.lastIndex = i;
    let m;
    while ((m = TOKEN_RE.exec(text))) {
      if (m.index > i) out.push([null, text.slice(i, m.index)]);
      if (m[1]) { out.push(["co", m[1]]); i = text.length; break; }
      if (m[2]) {
        const end = text.indexOf("*/", m.index + 2);
        if (end === -1) { out.push(["co", text.slice(m.index)]); st.inComment = true; i = text.length; break; }
        out.push(["co", text.slice(m.index, end + 2)]);
        i = end + 2; TOKEN_RE.lastIndex = i; continue;
      }
      if (m[3]) out.push(["st", m[3]]);
      else if (m[4]) out.push(["nu", m[4]]);
      else if (m[5]) out.push([KEYWORDS.has(m[5]) ? "kw" : TYPE_RE.test(m[5]) ? "ty" : null, m[5]]);
      i = m.index + m[0].length;
    }
    if (i < text.length) out.push([null, text.slice(i)]);
    return out;
  }

  function codeView(r, path, start, end, highlights, withIds) {
    const file = r.sources.find((s) => s.path === path);
    if (!file) return h("p", { class: "muted small" }, "Source not available.");
    const lines = file.content.split("\n");
    const st = { inComment: false };
    // warm up comment state for slices that start mid-file
    for (let n = 1; n < start; n++) tokenizeLine(lines[n - 1] || "", st);
    const box = h("div", { class: "code", role: "region", "aria-label": `${path} lines ${start} to ${end}`, tabindex: "0" });
    const frag = document.createDocumentFragment();
    for (let n = start; n <= Math.min(end, lines.length); n++) {
      const sev = highlights && highlights.get(n);
      const tx = h("span", { class: "tx" });
      tokenizeLine(lines[n - 1], st).forEach(([cls, t]) => tx.append(cls ? h("span", { class: `tk-${cls}` }, t) : document.createTextNode(t)));
      frag.append(h("div", { class: `ln${sev ? ` hl hl-${sev}` : ""}`, id: withIds ? `src-L${n}` : null },
        h("span", { class: "no" }, String(n)), tx));
    }
    box.append(frag);
    return box;
  }

  /* ------------------------------------------------------------------ exports */
  function slug() { return (state.report.meta.name || "contract").replace(/[^\w-]+/g, "_"); }
  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = h("a", { href: url, download: name });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function downloadMarkdown() { download(`${slug()}-review.md`, state.report.markdown, "text/markdown"); }
  function downloadJSON() {
    const { markdown, ...rest } = state.report;
    download(`${slug()}-review.json`, JSON.stringify(rest, null, 2), "application/json");
  }
  async function copySummary(e) {
    const r = state.report;
    const c = r.severity_counts;
    const text = `${r.meta.name} (${r.meta.contract_type}) - overall risk: ${r.overview.overall_risk.toUpperCase()}\n` +
      `Findings: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low\n\n${r.overview.text}\n\n${r.overview.risk_summary}\n\n` +
      "Automated review assistant output - not a professional audit.";
    const btn = e.currentTarget;
    try { await navigator.clipboard.writeText(text); btn.textContent = "Copied"; }
    catch (err) { btn.textContent = "Copy failed"; }
    setTimeout(() => { btn.textContent = "Copy summary"; }, 1600);
  }

  /* ------------------------------------------------------------------ utils */
  function range(a, b) { const out = []; for (let i = a; i <= b; i++) out.push(i); return out; }
  function cssId(s) { return String(s).replace(/[^\w-]/g, "_"); }

  loadConfig();
})();
