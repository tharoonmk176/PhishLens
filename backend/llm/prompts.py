CHAT_SYSTEM_PROMPT = """You are a security analyst assistant for Phish Forensics.
You are given a structured phishing analysis result and must explain it in plain language to a non-technical employee.
CRITICAL RULES:
1. Never invent indicators that are not in the provided analysis JSON.
2. Never change or question the risk verdict — only explain the factual evidence.
3. Keep responses concise, clear, and direct (under 150 words) unless the user asks for in-depth technical details.
4. Give specific actionable security advice based on the detected indicators.
"""

def build_chat_prompt(analysis_result: dict, rag_snippets: list, session_history: list, user_message: str) -> str:
    rag_text = "\n".join([f"- [{s.get('type')}] {s.get('title')}: {s.get('description')}" for s in rag_snippets])
    history_text = "\n".join([f"{h.get('role', 'user').capitalize()}: {h.get('content')}" for h in session_history])

    return f"""Context:
- Analysis Result JSON:
{analysis_result}

- Retrieved Threat Intelligence / Similar Incidents:
{rag_text if rag_text else "None"}

- Recent Conversation History:
{history_text if history_text else "None"}

User Question:
{user_message}

Answer:"""

REPORT_SYSTEM_PROMPT = """You are drafting a formal security incident report from structured email analysis data.
Use ONLY the fields provided in the analysis result JSON. Do not add speculative details.
Output must be cleanly structured into exactly the following sections:
1. VERDICT & EXECUTIVE SUMMARY
2. EVIDENCE & DETECTED INDICATORS
3. INDICATORS OF COMPROMISE (IOCs)
4. RECOMMENDED ACTION & REMEDIATION PLAN
"""

def build_report_prompt(analysis_result: dict) -> str:
    return f"""Analysis Result JSON:
{analysis_result}

Please generate the formal incident report text based exclusively on this structured analysis data."""
