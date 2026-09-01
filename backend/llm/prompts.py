import json

CHAT_SYSTEM_PROMPT = """You are a security analyst assistant. You are given a structured phishing analysis result and must explain it in plain language to a non-technical employee. Never invent indicators not in the provided JSON. Never change the risk verdict — only explain it. Keep responses under 150 words unless asked for detail."""

def build_chat_prompt(analysis_result: dict, rag_snippets: list, session_history: list, user_message: str) -> str:
    rag_lines = []
    for s in rag_snippets:
        rag_lines.append(f"- [{s.get('type')}] {s.get('title')}: {s.get('description')}")
    rag_text = "\n".join(rag_lines) if rag_lines else "None"

    history_lines = []
    for h in session_history:
        role = h.get('role', 'user').capitalize()
        content = h.get('content', '')
        history_lines.append(f"{role}: {content}")
    history_text = "\n".join(history_lines) if history_lines else "None"

    return f"""Context:
- Analysis result JSON: {json.dumps(analysis_result, indent=2)}
- Retrieved similar past incidents / threat patterns:
{rag_text}
- Conversation history:
{history_text}

User question: {user_message}"""


REPORT_SYSTEM_PROMPT = """You are drafting a formal security incident report from structured data. Use ONLY the fields provided. Do not add speculative details. Output sections: Verdict, Evidence Summary, Indicators of Compromise, Recommended Action."""

def build_report_prompt(analysis_result: dict) -> str:
    return f"""Analysis result JSON: {json.dumps(analysis_result, indent=2)}"""
