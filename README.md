# Phish Forensics — Explainable Phishing Triage & Auto-Incident-Report Copilot

Built for **SIH 2026 Problem Statement PS-02**.

Phish Forensics is an end-to-end explainable security triage system integrated with Gmail and standalone web dashboard. It analyzes incoming emails across 5 deterministic forensic dimensions, calculates risk scores via **noisy-OR combination**, maintains LLM-grounded interactive explanations, and auto-generates formal incident dossiers with zero manual write-up.

---

## 🛡️ Key Features

1. **Deterministic Forensics Engine (Zero-LLM Verdict)**
   - **Sender & Domain Analysis:** Levenshtein edit distance + visual confusable matrix (`1<->l`, `0<->o`, `rn<->m`, `cl<->d`), display name brand impersonation mismatch, and RDAP registration age checks.
   - **URL Forensics:** Redirect unwinding (HEAD queries), IP-literal host detection, high-abuse TLD filters (`.tk`, `.xyz`, etc.), and brand-in-subdomain extraction via `tldextract`.
   - **Content NLP:** Static urgency phrase dictionary (capped weights), credential-harvesting intent regexes, and token anomaly analysis.
   - **Header Forensics:** Gmail `Authentication-Results` SPF/DKIM/DMARC evaluation, `Reply-To` vs `From` domain mismatches, and relay hop count anomalies.
   - **Attachment Forensics:** Double extension concealment regex (`invoice.pdf.exe`) and executable/macro file detection.

2. **Noisy-OR Risk Scoring Aggregator**
   $$\text{risk\_score} = \min\left(100, \text{round}\left(100 \times \left(1 - \prod_i (1 - w_i \times c_i)\right)\right)\right)$$
   - Avoids double counting weak signals and naturally caps at 100%.

3. **In-Process RAG Layer (DuckDB + Sentence Transformers)**
   - Curated threat pattern corpus + automated embedding of past incidents into local DuckDB for semantic incident retrieval.

4. **Interactive LLM Security Assistant**
   - Groq (`llama-3.3-70b-versatile`) / Gemini (`gemini-2.0-flash`) grounded purely on deterministic indicators.

5. **Auto-Incident Report Generation (PDF / HTML)**
   - One-click exportable incident report containing executive summary, evidence table, IOCs, and remediation actions.

6. **Dual Triage Interfaces**
   - **Manifest V3 Chrome Extension:** Floating sidebar inside Gmail DOM.
   - **React.js Dashboard:** `.eml` drag-and-drop / manual triage, threat intelligence logs, and DuckDB incident registry.

---

## 🚀 Quick Start Guide

### 1. Backend Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r backend/requirements.txt

# Run server
cd backend
python manage.py runserver 0.0.0.0:8000
```

### 2. Frontend React Dashboard
```bash
cd dashboard
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

### 3. Chrome Extension
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** (top right).
3. Click **Load unpacked** and select the `/extension` directory.
