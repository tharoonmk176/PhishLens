import pytest
from detection.models import EmailInput, AttachmentInfo
from detection.aggregator import RiskAggregator

def test_phishing_email_detection():
    # PS-02 Problem statement case:
    # An employee receives a mail from security@paypa1-login.com, subject "Your account will be suspended!", pointing to http://paypa1-login.com/verify
    aggregator = RiskAggregator()
    email_input = EmailInput(
        message_id="test-ps02-001",
        from_address="security@paypa1-login.com",
        from_display_name="PayPal Security",
        subject="Your account will be suspended!",
        body_text="Dear customer, your account will be suspended within 24 hours. Please enter your password to confirm identity at http://paypa1-login.com/verify",
        urls=["http://paypa1-login.com/verify"],
        attachments=[AttachmentInfo(filename="invoice.pdf.exe", content_type="application/x-dosexec", size_bytes=1024)]
    )

    result = aggregator.evaluate(email_input)
    assert result.risk_score >= 70, f"Expected HIGH_RISK score >= 70, got {result.risk_score}"
    assert result.classification == "HIGH_RISK"
    assert result.recommended_action == "BLOCK_SENDER"

    # Check fired indicators
    indicator_names = [ind.indicator for ind in result.indicators]
    assert "domain_typosquat" in indicator_names or "brand_keyword_in_unauthorized_domain" in indicator_names
    assert "urgency_language" in indicator_names
    assert "credential_harvesting_phrasing" in indicator_names
    assert "double_extension_spoofing" in indicator_names

def test_legitimate_email():
    aggregator = RiskAggregator()
    email_input = EmailInput(
        message_id="test-legit-002",
        from_address="service@paypal.com",
        from_display_name="PayPal Team",
        subject="Your monthly statement is ready",
        body_text="Hi User, your monthly transaction statement is available in your account dashboard. Thank you for using PayPal.",
        urls=["https://www.paypal.com/signin"],
        attachments=[]
    )
    result = aggregator.evaluate(email_input)
    assert result.risk_score < 30, f"Expected LOW_RISK score < 30, got {result.risk_score}"
    assert result.classification == "LOW_RISK"
