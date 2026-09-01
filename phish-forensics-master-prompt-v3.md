# Phish Forensics — Master Build Prompt
**Explainable Phishing Triage & Auto-Incident-Report Copilot for Gmail**
**Target: SIH 2026, Problem Statement PS-02 — Django backend, free-tier only**

---

## How to use this document

This is the single source of truth for a CLI coding agent (Antigravity CLI, Claude Code, etc.) building this project. Read it fully before writing any code. Build in the exact order given in Section 10. Do not substitute paid services for anything listed as free-tier. Do not let the LLM produce risk verdicts — it only explains and drafts text. If any instruction here is ambiguous, prefer the most literal reading over the most convenient one.

---

## 1. What we're building

An email arrives from `security@paypa1-login.com`, subject "Your account will be suspended!", linking to `http://paypa1-login.com/verify`. A person has seconds to decide whether to trust it.

Phish Forensics answers that question with **evidence, not a bare verdict**: it scores the email's risk, lists every indicator that fired and why, lets the user ask follow-up questions to an LLM-powered assistant that maintains context across the conversation and explains the result (never changes it), and generates a complete incident report with zero manual write-up. It's accessible two ways: a Chrome extension sitting inside Gmail (fetching mail via the Gmail API), and a standalone dashboard with a paste/upload fallback.

**The four pillars this project must deliver, all working together, not as separate demos:**
1. **Gemini API** — powers the LLM chatbot, maintaining conversational context across a series of follow-up queries about a single analyzed email.
2. **Gmail API** — fetches the actual mail content (headers, body, attachments) for analysis.
3. **Chrome extension** — sits inside Gmail, detects the open email, and surfaces the analysis and chat sidebar in-context.
4. **DuckDB** — holds the reference data (known brand domains, known threat patterns) that the integrity checks query against, plus the history of every analysis performed.

**The one rule that must never be broken:** the risk verdict is always computed by deterministic code (Section 4). The LLM (Section 6) is only allowed to explain that verdict conversationally and draft report text from it. If any code path asks the LLM "is this phishing?" as a source of truth, that's a bug.

---

## 2. Non-negotiable constraints

1. **Free tier only** — every service, API, and library used must run without a paid plan or billing account. Section 9 names the specific free-tier choice for each component; don't substitute a paid alternative.
2. **Deterministic verdict, LLM explains only** — see above.
3. **Demo must survive zero connectivity to Gmail** — the `.eml` paste/upload path (Section 7.3) must work completely independently of Gmail OAuth, and must be built and tested before the OAuth path is considered done.
4. **No bare scores** — any screen that shows a risk score must also show the indicators and evidence behind it.
5. **DuckDB is the system of record for integrity-check reference data** — not a log-only afterthought. Detection modules query DuckDB tables at check time (Section 5).

---

## 3. Problem statement (source, verbatim context)

> An employee receives a mail from `security@paypa1-login.com`, subject "Your account will be suspended!", pointing to `http://paypa1-login.com/verify` — and has seconds to decide whether to trust it. Build a system that analyses the message and answers that question with evidence rather than a bare verdict, scoring the risk and listing every indicator that fired.

Required analysis dimensions: sender address, domain, URL, urgency language, suspicious keywords, domain similarity to known brands, links, attachments.

Bonus objective: auto-generate a shareable incident report — verdict, evidence, indicators of compromise, recommended action — with zero manual write-up.

---

## 4. Detection engine (deterministic — build first, no LLM involvement)

### 4.1 Data contracts

**EmailInput** — normalized input every analyzer receives:
```python
{
  "message_id": str,
  "from_address": str,
  "from_display_name": str,
  "reply_to": str | None,
  "subject": str,
  "body_text": str,
  "body_html": str | None,
  "headers_raw": str,
  "urls": list[str],
  "attachments": [{"filename": str, "content_type": str, "size_bytes": int}]
}
```

**Indicator** — every analyzer emits a list of these:
```python
{
  "module": str,          # e.g. "sender_domain"
  "indicator": str,       # e.g. "domain_typosquat"
  "evidence": str,        # human-readable, specific: "Domain 'paypa1-login.com' visually mimics 'paypal.com'"
  "weight": float,        # 0.0–1.0
  "confidence": float     # 0.0–1.0
}
```

**AnalysisResult** — final output of `/api/analyze`:
```python
{
  "message_id": str,
  "risk_score": int,              # 0–100
  "classification": str,           # LOW_RISK | MEDIUM_RISK | HIGH_RISK
  "indicators": list[Indicator],   # sorted by weight, descending
  "iocs": {
    "sender_address": str,
    "domains": list[str],
    "urls": list[str],
    "attachment_hashes": list[str]
  },
  "recommended_action": str,       # BLOCK_SENDER | QUARANTINE | USER_AWARENESS_NOTE
  "analyzed_at": str               # ISO-8601
}
```

### 4.2 Analyzer modules

| Module (`detection/`) | Checks | Weight | Data source |
|---|---|---|---|
| `sender_domain.py` | Typosquat via Levenshtein distance (≤2) + visual-confusable map (`1↔l`, `0↔o`, `rn↔m`, `vv↔w`, `cl↔d`) | 0.9 | **DuckDB** `known_brand_domains` table (Section 5.2) |
| | Domain age via RDAP (`https://rdap.org/domain/{domain}`) — flag if <30 days | 0.6 | External RDAP call |
| | Domain age — flag if <90 days | 0.3 | External RDAP call |
| | Display-name vs actual sender-domain mismatch | 0.5 | In-memory comparison |
| `url_analysis.py` | Redirect-chain unwinding (max 5 hops, 3s timeout each) | — | — |
| | IP-literal URL in host position | 0.8 | In-memory regex |
| | Suspicious TLD (`.tk`, `.ml`, `.ga`, `.cf`, `.gq`, etc.) | 0.4 | In-memory static list |
| | Brand name in subdomain, not in true registrable domain (via `tldextract`) | 0.85 | **DuckDB** `known_brand_domains` table |
| | Shortened-URL expansion before re-analysis | — | — |
| `content_nlp.py` | Urgency phrase match (~40 phrases, e.g. "act now", "account will be suspended") | 0.3 per match, capped at 0.6 | In-memory static list |
| | Credential-request phrasing ("enter your password", "confirm your PIN") | 0.7 | In-memory static list |
| | Grammar/spelling anomaly ratio (via `pyspellchecker`) | 0–0.3 scaled | Local library |
| `header_forensics.py` | SPF/DKIM/DMARC fail (parsed from Gmail's `Authentication-Results` header — no external lookup needed) | 0.7 each | Header parsing |
| | SPF/DKIM/DMARC all "none" (unauthenticated) | 0.4 | Header parsing |
| | Reply-To vs From domain mismatch | 0.5 | In-memory comparison |
| | Received-header hop count anomaly | 0.2 | Header parsing |
| `attachment_link.py` | Extension spoofing (`invoice.pdf.exe` pattern) | 0.9 | In-memory regex |
| | Macro-enabled extensions (`.docm`, `.xlsm`, `.pptm`) | 0.5 | In-memory static list |
| | Direct executable/script extensions (`.exe`, `.scr`, `.bat`, `.js`, `.vbs`, `.jar`) | 0.85 | In-memory static list |

### 4.3 Risk aggregation (`aggregator.py`)

Use **noisy-OR**, not weighted sum:

```
risk_score = min(100, round(100 * (1 - Π(1 - weight_i * confidence_i))))
```

This caps naturally at 100, avoids double-counting overlapping weak signals, and is defensible as: "each indicator independently raises the probability of a real threat; the aggregate is the combined probability that at least one is genuine." Put this explanation in a docstring on the function.

Classification bands: `0–29 → LOW_RISK`, `30–69 → MEDIUM_RISK`, `70–100 → HIGH_RISK`.

Recommended action: `HIGH_RISK → BLOCK_SENDER`, `MEDIUM_RISK → QUARANTINE`, `LOW_RISK (with ≥1 indicator) → USER_AWARENESS_NOTE`, `LOW_RISK (0 indicators) → no action`.

---

## 5. Storage — DuckDB (system of record for integrity checks + history)

### 5.1 Why DuckDB is central, not a log-only afterthought

Two earlier design options were considered:

- **(Rejected) Static JSON files read in-memory by analyzers** — simpler, but DuckDB would only ever store analysis *outputs*, never participate in the actual detection decision.
- **(Adopted) DuckDB-backed reference tables** — brand and threat-pattern data is loaded into DuckDB tables once (via a seed script), and analyzers query DuckDB directly at check time. This makes DuckDB the genuine system of record for "what counts as a known-good or known-bad signal," not just a results log. It also means the brand/threat list can be updated at runtime (`INSERT`/`UPDATE`) without redeploying code, and the `threat_patterns` table doubles as the RAG corpus source (Section 6.1) — no separate JSON file to keep in sync.

### 5.2 Schema

```sql
-- Reference data for integrity checks (seeded once, queried at detection time)
CREATE TABLE known_brand_domains (
  brand VARCHAR,
  legitimate_domain VARCHAR,
  logo_keywords VARCHAR       -- comma-separated
);

CREATE TABLE threat_patterns (
  pattern_id VARCHAR PRIMARY KEY,
  description VARCHAR,
  embedding BLOB              -- populated after embedding at seed time; doubles as RAG corpus
);

-- Analysis history (written on every /api/analyze call)
CREATE TABLE analyses (
  message_id VARCHAR PRIMARY KEY,
  from_address VARCHAR,
  subject VARCHAR,
  risk_score INTEGER,
  classification VARCHAR,
  indicators_json VARCHAR,
  iocs_json VARCHAR,
  recommended_action VARCHAR,
  analyzed_at TIMESTAMP,
  embedding BLOB              -- for RAG retrieval over past incidents
);

CREATE TABLE chat_sessions (   -- optional, stretch goal
  message_id VARCHAR,
  turn_index INTEGER,
  role VARCHAR,
  content VARCHAR,
  created_at TIMESTAMP
);
```

### 5.3 Seeding

- `storage/seed_duckdb.py` — a one-time script run at project setup: reads `known_brand_domains_seed.json` (~200 entries) and `threat_patterns_seed.json` (~30–50 entries), inserts into the respective tables, and computes+stores embeddings for `threat_patterns` at seed time.
- After seeding, the raw JSON seed files are not read again at runtime — `sender_domain.py`, `url_analysis.py`, and the RAG layer all query DuckDB directly via `storage/duckdb_client.py`.
- Single file-based DuckDB (`phish_forensics.db`), one connection opened at Django startup, accessed only through `storage/duckdb_client.py` — no raw connections opened elsewhere.

### 5.4 Dashboard queries (`/api/dashboard`)
- Top sender domains flagged, risk-score trend by day, most common fired indicators — all computed from the `analyses` table.

---

## 6. RAG + LLM layer

### 6.1 RAG corpora
- `known_brand_domains` (DuckDB) — used directly by `sender_domain.py`/`url_analysis.py` for exact/fuzzy matching, not embeddings.
- `threat_patterns` (DuckDB, embedded at seed time) — used for semantic RAG retrieval.
- Past-incident corpus — every analysis's `subject + top 3 indicators` embedded and stored in the `analyses.embedding` column on write.

### 6.2 Embeddings (`rag/embeddings.py`)
- `sentence-transformers/all-MiniLM-L6-v2`, loaded once at Django startup (module-level singleton) — never reloaded per request.
- Retrieval (`rag/retrieval.py`): cosine similarity in Python/numpy over DuckDB-stored embeddings (`threat_patterns` + `analyses` tables), top-k = 3 combined. Brute-force loop is fine at this scale — no vector index needed.

### 6.3 LLM provider (`llm/`) — Gemini primary

- **Default/primary: Gemini API**, model `gemini-2.0-flash` (free tier). Python SDK: `google-generativeai`.
- **Fallback: Groq**, `llama-3.3-70b-versatile` (free tier) — used automatically if the Gemini call fails or the free-tier rate limit is hit, so a demo doesn't stall on a single provider's quota.
- One interface (`client.py`) with a `generate(prompt, context)` method; `gemini_client.py` and `groq_client.py` both implement it. Provider order (Gemini → Groq fallback) is configured via a Django setting, not hardcoded inline in view logic.

### 6.4 Context maintenance across a series of queries

This is a specific requirement: the chatbot must maintain context across multiple follow-up questions about the same analyzed email, not treat each question as a stateless call.

- Conversation history keyed by `message_id`, held as an in-process list of `{role, content}` turns (`{"user": "...", "assistant": "..."}`) for the duration of the session — sufficient for a hackathon demo.
- On every `/api/chat` call: retrieve the full turn history for that `message_id`, append it to the prompt (Section 6.5's `{session_history}` field), then append the new turn (both the user's question and Gemini's answer) back into the history after the call completes.
- Optional stretch goal: persist history in the `chat_sessions` DuckDB table so it survives a server restart — not required for the demo to work, but trivial to add given the table already exists in the schema.

### 6.5 Prompts (`llm/prompts.py`)

**Chat/explanation:**
```
System: You are a security analyst assistant. You are given a structured phishing
analysis result and must explain it in plain language to a non-technical employee.
Never invent indicators not in the provided JSON. Never change the risk verdict —
only explain it. Keep responses under 150 words unless asked for detail.

Context:
- Analysis result JSON: {analysis_result}
- Retrieved similar past incidents / threat patterns: {rag_snippets}
- Conversation history: {session_history}

User question: {user_message}
```

**Incident report:**
```
System: You are drafting a formal security incident report from structured data.
Use ONLY the fields provided. Do not add speculative details. Output sections:
Verdict, Evidence Summary, Indicators of Compromise, Recommended Action.

Analysis result JSON: {analysis_result}
```

---

## 7. Gmail integration

### 7.1 Google Cloud setup (one-time, free)
1. Create a Google Cloud project, enable the Gmail API.
2. OAuth consent screen: External, add scope `https://www.googleapis.com/auth/gmail.readonly`, leave in **Testing** mode, add test-user Gmail accounts. This avoids Google's verification review entirely and stays free indefinitely for the listed test users.
3. Load the extension unpacked (`chrome://extensions` → Developer mode → Load unpacked) to get its 32-character Item ID.
4. Create an OAuth client of type **Chrome Extension**, using that Item ID.
5. Separately, enable the Gemini API (Google AI Studio) and generate a free API key for `google-generativeai` — no billing account required for the free tier.

### 7.2 Extension (`extension/`)

`manifest.json` must include:
```json
{
  "permissions": ["identity", "activeTab", "storage"],
  "host_permissions": [
    "https://mail.google.com/*",
    "https://gmail.googleapis.com/*",
    "http://localhost:8000/*",
    "http://127.0.0.1:8000/*"
  ],
  "oauth2": {
    "client_id": "YOUR_CLIENT_ID.apps.googleusercontent.com",
    "scopes": ["https://www.googleapis.com/auth/gmail.readonly"]
  },
  "background": { "service_worker": "background.js" },
  "content_scripts": [{
    "matches": ["https://mail.google.com/*"],
    "js": ["content-script.js"],
    "css": ["sidebar/sidebar.css"],
    "run_at": "document_idle"
  }]
}
```

- `background.js` — requests the token via `chrome.identity.getAuthToken`; on a 401 from any API call, calls `removeCachedAuthToken` then retries once. This retry logic is required, not optional — an expired token mid-demo must not break the flow.
- `content-script.js` — injects a sidebar into the open Gmail message view; detects the currently-open email and extracts its identifying info (message ID, visible subject/sender) from the DOM.
- **The extension does not call the Gmail API directly.** It sends the OAuth token + message ID to the Django backend, which performs the actual Gmail API fetch via `google-api-python-client`. This keeps detection, storage, and LLM logic centralized in Django.

### 7.3 `.eml` fallback (mandatory, build alongside OAuth, not after)
- `gmail_integration/eml_parser.py` parses a `.eml` file via Python's `email` module into the exact `EmailInput` contract.
- A paste/upload screen in the React dashboard hits the same `/api/analyze` endpoint as the Gmail path. Both paths must produce an identical `AnalysisResult` shape.

---

## 8. Bonus feature — Incident report

- `/api/report` takes an `AnalysisResult` + Gemini-drafted narrative sections (Section 6.5's report prompt) and renders a PDF via `weasyprint`.
- Report sections map 1:1 to the prompt: Verdict, Evidence Summary, Indicators of Compromise, Recommended Action.
- One-click export from the chat sidebar UI — zero manual write-up required.

---

## 9. Tech stack (all free-tier)

| Layer | Choice | Why |
|---|---|---|
| Backend | Django + Django REST Framework | Natural fit for RAG, DuckDB, email parsing, LLM SDKs — one runtime, no separate microservice |
| Detection libs | `python-Levenshtein`, `tldextract`, stdlib `email` | Free, mature |
| Domain lookup | RDAP (`rdap.org`) | Free, no key, no rate-limit issues (vs raw WHOIS) |
| Storage + integrity reference data | DuckDB, embedded | No server, no cost; holds both reference tables and history |
| Embeddings | `sentence-transformers` (`all-MiniLM-L6-v2`), local | Free, no API cost |
| LLM (primary) | **Gemini API** (`gemini-2.0-flash`) | Free tier, maintains multi-turn context well, official Python SDK |
| LLM (fallback) | Groq (`llama-3.3-70b-versatile`) | Free tier, used if Gemini quota/errors hit |
| PDF report | `weasyprint` (HTML/CSS → PDF) | Free, easy to style |
| Frontend | React.js | Dashboard + fallback UI |
| Extension | Chrome Manifest V3, unpacked (no Web Store fee needed) | Free for dev + demo |
| Dev tunnel (if needed) | ngrok free tier | For OAuth redirect during dev, if not using `chrome.identity` exclusively |

---

## 10. Repo structure

```
phish-forensics/
├── backend/
│   ├── manage.py
│   ├── config/                  # settings, urls, wsgi/asgi
│   ├── detection/                # sender_domain.py, url_analysis.py, content_nlp.py,
│   │                              # header_forensics.py, attachment_link.py, aggregator.py
│   ├── rag/                      # embeddings.py, retrieval.py
│   ├── llm/                      # client.py, gemini_client.py, groq_client.py, prompts.py
│   ├── storage/                  # duckdb_client.py, seed_duckdb.py,
│   │                              # known_brand_domains_seed.json, threat_patterns_seed.json
│   ├── gmail_integration/        # oauth.py, gmail_api.py, eml_parser.py
│   ├── api/                      # DRF views/serializers/urls
│   └── requirements.txt
├── dashboard/                    # React.js
├── extension/                    # manifest.json, background.js, content-script.js, sidebar/
└── docs/
    └── this-file.md
```

---

## 11. Build order (do not reorder without reason)

1. Detection engine — all 5 analyzers + `aggregator.py`, unit-tested against hardcoded sample emails using in-memory placeholder data. No Django, no DB yet.
2. DuckDB schema + `seed_duckdb.py` — seed `known_brand_domains` and `threat_patterns` tables; wire `storage/duckdb_client.py`.
3. Update `sender_domain.py` and `url_analysis.py` to query DuckDB instead of in-memory placeholders.
4. Django project + `/api/analyze` DRF view, accepting `EmailInput` JSON directly; write results to the `analyses` table.
5. `.eml` parser → `EmailInput` mapping. This unblocks safe end-to-end testing immediately.
6. React dashboard: upload/paste `.eml` → full evidence-breakdown view. This alone is a demoable MVP.
7. Embeddings for `threat_patterns` (at seed time) and `analyses` (on write); retrieval wired for RAG.
8. LLM client — Gemini primary, Groq fallback — + `/api/chat` with session-history context and RAG snippets injected into the prompt. Test explicitly with a 2–3 turn conversation to confirm context is maintained.
9. `/api/report` + PDF generation via `weasyprint`.
10. Chrome extension: content script sidebar + OAuth via `chrome.identity`, wired to the same backend.
11. Dashboard analytics view (`/api/dashboard`).
12. Full rehearsal using the `.eml` fallback as the primary demo path if time is short — never depend on live OAuth working on stage.

---

## 12. Judging alignment — keep coming back to this

- Every risk score must trace to explicit fired indicators with evidence text. Never a bare number.
- The LLM (Gemini) never produces the verdict — only explains it and drafts the report, with conversational context maintained across follow-up questions.
- The incident report requires zero manual write-up.
- DuckDB is demonstrably the source of the integrity-check reference data, not just a history log — be ready to show a query against `known_brand_domains` live if asked.
- Be ready to explain the noisy-OR formula in one sentence if a judge asks.
- Everything demoed must run on infrastructure that cost nothing to set up.
