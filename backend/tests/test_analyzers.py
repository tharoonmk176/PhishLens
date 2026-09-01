import pytest
from detection.models import EmailInput, AttachmentInfo
from detection.sender_domain import SenderDomainAnalyzer
from detection.url_analysis import UrlAnalyzer
from detection.content_nlp import ContentNlpAnalyzer
from detection.header_forensics import HeaderForensicsAnalyzer
from detection.attachment_link import AttachmentLinkAnalyzer
from detection.aggregator import RiskAggregator

def test_sender_domain_typosquat():
    analyzer = SenderDomainAnalyzer()
    
    # 1. Typosquat paypal -> paypa1
    email_input = EmailInput(
        message_id="test-1",
        from_address="support@paypa1-login.com",
        from_display_name="PayPal",
        subject="Alert",
        body_text="Verify your account"
    )
    indicators = analyzer.analyze(email_input)
    ind_names = [i.indicator for i in indicators]
    assert any(name in ["domain_typosquat", "brand_keyword_in_unauthorized_domain"] for name in ind_names)
    assert any(i.weight >= 0.85 for i in indicators)

def test_sender_domain_display_name_mismatch():
    analyzer = SenderDomainAnalyzer()
    email_input = EmailInput(
        message_id="test-2",
        from_address="attacker@random-domain-123.com",
        from_display_name="Microsoft Security Team",
        subject="Password Reset",
        body_text="Reset now"
    )
    indicators = analyzer.analyze(email_input)
    ind_names = [i.indicator for i in indicators]
    assert "display_name_brand_mismatch" in ind_names

def test_url_analyzer_checks():
    analyzer = UrlAnalyzer()
    
    # 1. IP literal URL
    # 2. Suspicious TLD
    # 3. Brand in subdomain
    # 4. Insecure HTTP login
    email_input = EmailInput(
        message_id="test-3",
        from_address="test@test.com",
        subject="Check this",
        body_text="Go to http://192.168.1.1/login and https://paypal.com.attacker-controlled.xyz/verify and http://scam.tk/signin"
    )
    indicators = analyzer.analyze(email_input)
    ind_names = [i.indicator for i in indicators]
    assert "ip_literal_url" in ind_names
    assert "suspicious_tld" in ind_names
    assert "brand_in_subdomain" in ind_names
    assert "insecure_login_url" in ind_names

def test_content_nlp_analyzer():
    analyzer = ContentNlpAnalyzer()
    email_input = EmailInput(
        message_id="test-4",
        from_address="test@test.com",
        subject="Your account will be suspended within 24 hours!",
        body_text="Dear user, immediate action required. Enter your password and confirm your PIN immediately."
    )
    indicators = analyzer.analyze(email_input)
    ind_names = [i.indicator for i in indicators]
    assert "urgency_language" in ind_names
    assert "credential_harvesting_phrasing" in ind_names

def test_header_forensics_analyzer():
    analyzer = HeaderForensicsAnalyzer()
    headers_fail = """From: security@paypal.com
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of security@paypal.com does not designate 1.2.3.4 as permitted sender);
       dkim=fail header.i=@paypal.com;
       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com
Received: from mail.relay1.com
Received: from mail.relay2.com
Received: from mail.relay3.com
Received: from mail.relay4.com
Received: from mail.relay5.com
Received: from mail.relay6.com
Received: from mail.relay7.com
Received: from mail.relay8.com
"""
    email_input = EmailInput(
        message_id="test-5",
        from_address="security@paypal.com",
        reply_to="attacker@evil.com",
        headers_raw=headers_fail
    )
    indicators = analyzer.analyze(email_input)
    ind_names = [i.indicator for i in indicators]
    assert "spf_auth_failure" in ind_names
    assert "dkim_auth_failure" in ind_names
    assert "dmarc_auth_failure" in ind_names
    assert "reply_to_domain_mismatch" in ind_names
    assert "excessive_received_hops" in ind_names

def test_attachment_link_analyzer():
    analyzer = AttachmentLinkAnalyzer()
    email_input = EmailInput(
        message_id="test-6",
        from_address="test@test.com",
        attachments=[
            AttachmentInfo(filename="invoice.pdf.exe", content_type="application/octet-stream", size_bytes=100),
            AttachmentInfo(filename="receipt.docm", content_type="application/msword", size_bytes=200),
            AttachmentInfo(filename="payload.scr", content_type="application/octet-stream", size_bytes=300),
        ]
    )
    indicators = analyzer.analyze(email_input)
    ind_names = [i.indicator for i in indicators]
    assert "double_extension_spoofing" in ind_names
    assert "macro_enabled_document" in ind_names
    assert "executable_attachment" in ind_names

def test_noisy_or_aggregator():
    agg = RiskAggregator()
    # 0 indicators -> score 0
    score_0 = agg.compute_noisy_or_score([])
    assert score_0 == 0

    # High risk email
    email_ps02 = EmailInput(
        message_id="ps02",
        from_address="security@paypa1-login.com",
        subject="Your account will be suspended!",
        body_text="Enter your password at http://paypa1-login.com/verify within 24 hours",
        urls=["http://paypa1-login.com/verify"]
    )
    res = agg.evaluate(email_ps02)
    assert res.risk_score >= 70
    assert res.classification == "HIGH_RISK"
    assert res.recommended_action == "BLOCK_SENDER"
