import pytest
from llm.prompts import CHAT_SYSTEM_PROMPT, build_chat_prompt, REPORT_SYSTEM_PROMPT, build_report_prompt
from llm.client import get_llm_client, MockLlmClient

def test_prompt_formatting_and_session_history():
    analysis_result = {
        "message_id": "msg-101",
        "risk_score": 88,
        "classification": "HIGH_RISK",
        "indicators": [
            {"module": "sender_domain", "indicator": "domain_typosquat", "evidence": "paypa1-login.com mimics paypal.com", "weight": 0.9, "confidence": 0.95}
        ]
    }
    rag_snippets = [
        {"type": "threat_pattern", "title": "THREAT_001", "description": "Urgent Account Suspension Panic"}
    ]
    session_history = [
        {"role": "user", "content": "Why is this email dangerous?"},
        {"role": "assistant", "content": "It uses a lookalike domain paypa1-login.com to impersonate PayPal."}
    ]
    user_follow_up = "What should I do if I already clicked the link?"

    prompt = build_chat_prompt(analysis_result, rag_snippets, session_history, user_follow_up)

    assert "paypa1-login.com" in prompt
    assert "THREAT_001" in prompt
    assert "Why is this email dangerous?" in prompt
    assert "What should I do if I already clicked the link?" in prompt

def test_multi_turn_llm_generation():
    client = get_llm_client()
    system_prompt = CHAT_SYSTEM_PROMPT
    user_prompt = "Explain why this email is flagged as high risk."
    
    response = client.generate(system_prompt, user_prompt)
    assert len(response) > 20
    assert isinstance(response, str)

def test_report_prompt_and_generation():
    analysis_result = {
        "message_id": "msg-report-01",
        "risk_score": 92,
        "classification": "HIGH_RISK",
        "indicators": [
            {"module": "attachment_link", "indicator": "double_extension_spoofing", "evidence": "invoice.pdf.exe detected", "weight": 0.9, "confidence": 0.98}
        ],
        "iocs": {"sender_address": "bad@evil.com", "domains": ["evil.com"], "urls": [], "attachment_hashes": []},
        "recommended_action": "BLOCK_SENDER"
    }
    prompt = build_report_prompt(analysis_result)
    assert "double_extension_spoofing" in prompt
    assert "BLOCK_SENDER" in prompt

    client = get_llm_client()
    report_text = client.generate(REPORT_SYSTEM_PROMPT, prompt)
    assert len(report_text) > 30
