import pytest
import json
from rest_framework.test import APIClient

@pytest.fixture
def client():
    return APIClient()

def test_api_analyze_endpoint(client):
    payload = {
        "message_id": "api_test_001",
        "from_address": "security@paypa1-login.com",
        "from_display_name": "PayPal Security",
        "subject": "Your account will be suspended within 24 hours!",
        "body_text": "Dear customer, your account will be suspended. Enter your password at http://paypa1-login.com/verify to prevent termination.",
        "urls": ["http://paypa1-login.com/verify"],
        "attachments": [{"filename": "invoice.pdf.exe", "content_type": "application/octet-stream", "size_bytes": 500}]
    }
    response = client.post("/api/analyze", data=json.dumps(payload), content_type="application/json")
    assert response.status_code == 200
    data = response.json()
    assert data["message_id"] == "api_test_001"
    assert data["risk_score"] >= 70
    assert data["classification"] == "HIGH_RISK"
    assert data["recommended_action"] == "BLOCK_SENDER"
    assert len(data["indicators"]) >= 3
    assert "sender_address" in data["iocs"]

def test_api_analyze_eml_endpoint(client):
    raw_eml = """From: security@paypa1-login.com
Subject: Final Notice: Account Suspension
Content-Type: text/plain; charset="utf-8"

Immediate action required. Please verify at http://paypa1-login.com/verify
"""
    response = client.post("/api/analyze-eml", data={"raw_eml": raw_eml})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 70
    assert data["classification"] == "HIGH_RISK"
    assert "extracted_email" in data

def test_api_chat_endpoint_multi_turn(client):
    # 1. Analyze an email first
    analyze_payload = {
        "message_id": "chat_test_002",
        "from_address": "security@paypa1-login.com",
        "subject": "Security Warning",
        "body_text": "Enter password to verify account at http://paypa1-login.com/verify",
        "urls": ["http://paypa1-login.com/verify"]
    }
    client.post("/api/analyze", data=json.dumps(analyze_payload), content_type="application/json")

    # 2. Turn 1
    chat_payload_1 = {
        "message_id": "chat_test_002",
        "user_message": "Why was this email flagged?"
    }
    resp1 = client.post("/api/chat", data=json.dumps(chat_payload_1), content_type="application/json")
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert "reply" in data1
    assert len(data1["reply"]) > 10

    # 3. Turn 2 (contextual follow-up)
    chat_payload_2 = {
        "message_id": "chat_test_002",
        "user_message": "What specific link was malicious?"
    }
    resp2 = client.post("/api/chat", data=json.dumps(chat_payload_2), content_type="application/json")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert "reply" in data2

def test_api_report_endpoint_json_and_pdf(client):
    # Analyze an email first
    analyze_payload = {
        "message_id": "report_test_003",
        "from_address": "security@paypa1-login.com",
        "subject": "Critical Incident",
        "body_text": "Account suspended immediately. Verify password.",
        "urls": ["http://paypa1-login.com/verify"]
    }
    client.post("/api/analyze", data=json.dumps(analyze_payload), content_type="application/json")

    # JSON report
    resp_json = client.get("/api/report?message_id=report_test_003&format=json")
    assert resp_json.status_code == 200
    data = resp_json.json()
    assert "report_narrative" in data
    assert "analysis_result" in data

    # PDF report
    resp_pdf = client.get("/api/report?message_id=report_test_003&format=pdf")
    assert resp_pdf.status_code == 200
    assert resp_pdf["Content-Type"] == "application/pdf"
    assert len(resp_pdf.content) > 100

def test_api_history_and_dashboard_endpoints(client):
    resp_hist = client.get("/api/history")
    assert resp_hist.status_code == 200
    history = resp_hist.json()
    assert isinstance(history, list)

    resp_dash = client.get("/api/dashboard")
    assert resp_dash.status_code == 200
    dash = resp_dash.json()
    assert "total_analyzed" in dash
    assert "classifications" in dash
    assert "top_indicators" in dash
