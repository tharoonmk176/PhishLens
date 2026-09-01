import pytest
from gmail_integration.eml_parser import EmlParser

def test_eml_parser_simple():
    raw_eml = b"""From: "PayPal Security" <security@paypa1-login.com>
To: victim@example.com
Reply-To: collector@paypa1-login.com
Subject: Urgent: Your account will be suspended!
Message-ID: <12345@paypa1-login.com>
Content-Type: text/plain; charset="utf-8"

Dear customer, your account will be suspended within 24 hours.
Please verify your password immediately at http://paypa1-login.com/verify
"""
    email_input = EmlParser.parse_bytes(raw_eml)
    assert email_input.message_id == "12345@paypa1-login.com"
    assert email_input.from_address == "security@paypa1-login.com"
    assert email_input.from_display_name == "PayPal Security"
    assert email_input.reply_to == "collector@paypa1-login.com"
    assert email_input.subject == "Urgent: Your account will be suspended!"
    assert "account will be suspended within 24 hours" in email_input.body_text
    assert "http://paypa1-login.com/verify" in email_input.urls

def test_eml_parser_multipart_with_attachment():
    raw_eml = b"""From: service@paypa1.com
To: user@target.org
Subject: Invoice Attached
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY123"

--BOUNDARY123
Content-Type: text/plain; charset="utf-8"

Please see attached invoice.

--BOUNDARY123
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"

fakeexecutablecontent
--BOUNDARY123--
"""
    email_input = EmlParser.parse_bytes(raw_eml)
    assert email_input.from_address == "service@paypa1.com"
    assert "invoice" in email_input.subject.lower()
    assert len(email_input.attachments) == 1
    assert email_input.attachments[0].filename == "invoice.pdf.exe"
