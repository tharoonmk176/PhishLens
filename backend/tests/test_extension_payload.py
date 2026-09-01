import pytest
from detection.models import EmailInput
from detection.aggregator import RiskAggregator

def test_extension_scraped_phishing_payload():
    # Simulating what Gmail DOM scrape extracts from a phishing email
    aggregator = RiskAggregator()
    email_input = EmailInput(
        message_id="gmail_dom_1725170000000",
        from_address="service@paypa1-security.com",
        from_display_name="PayPal Alerts",
        subject="Your PayPal account will be suspended within 24 hours",
        body_text="Dear member, we detected suspicious activity. Please verify your password immediately to avoid termination: http://paypa1-security.com/signin",
        urls=["http://paypa1-security.com/signin"],
        attachments=[]
    )
    result = aggregator.evaluate(email_input)
    
    # Assert that score is high and indicators fired
    assert result.risk_score >= 70, f"Expected >= 70, got {result.risk_score}"
    assert result.classification == "HIGH_RISK"
    assert len(result.indicators) >= 2
    
    indicators = [ind.indicator for ind in result.indicators]
    assert "domain_typosquat" in indicators or "brand_keyword_in_unauthorized_domain" in indicators
    assert "urgency_language" in indicators
