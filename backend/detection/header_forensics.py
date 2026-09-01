import re
import email
from typing import List, Optional
from .models import EmailInput, Indicator
from .sender_domain import extract_domain, get_registrable_domain

class HeaderForensicsAnalyzer:
    def parse_auth_results(self, headers_raw: str) -> List[Indicator]:
        indicators = []
        if not headers_raw:
            return indicators

        auth_results_match = re.search(r'Authentication-Results:([^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*)', headers_raw, re.IGNORECASE)
        auth_header = auth_results_match.group(1).lower() if auth_results_match else headers_raw.lower()

        # Check SPF
        spf_fail = re.search(r'spf=(fail|softfail)', auth_header)
        spf_pass = re.search(r'spf=pass', auth_header)
        spf_none = re.search(r'spf=(none|neutral)', auth_header)

        # Check DKIM
        dkim_fail = re.search(r'dkim=(fail|hardfail)', auth_header)
        dkim_pass = re.search(r'dkim=pass', auth_header)
        dkim_none = re.search(r'dkim=(none|neutral)', auth_header)

        # Check DMARC
        dmarc_fail = re.search(r'dmarc=(fail|reject)', auth_header)
        dmarc_pass = re.search(r'dmarc=pass', auth_header)
        dmarc_none = re.search(r'dmarc=(none)', auth_header)

        if spf_fail:
            indicators.append(Indicator(
                module="header_forensics",
                indicator="spf_auth_failure",
                evidence=f"SPF authentication failed ({spf_fail.group(0)}) indicating possible sender forgery.",
                weight=0.7,
                confidence=0.95
            ))
        if dkim_fail:
            indicators.append(Indicator(
                module="header_forensics",
                indicator="dkim_auth_failure",
                evidence=f"DKIM cryptographic signature verification failed ({dkim_fail.group(0)}).",
                weight=0.7,
                confidence=0.95
            ))
        if dmarc_fail:
            indicators.append(Indicator(
                module="header_forensics",
                indicator="dmarc_auth_failure",
                evidence=f"DMARC policy enforcement evaluation failed ({dmarc_fail.group(0)}).",
                weight=0.7,
                confidence=0.95
            ))

        # Check if all auth are completely missing/none
        if (spf_none and dkim_none and dmarc_none) or (not spf_pass and not dkim_pass and not dmarc_pass and "authentication-results" in headers_raw.lower()):
            indicators.append(Indicator(
                module="header_forensics",
                indicator="unauthenticated_sender_domain",
                evidence="Email lacks passing SPF/DKIM/DMARC authentication verification records.",
                weight=0.4,
                confidence=0.85
            ))

        return indicators

    def check_reply_to_mismatch(self, from_addr: str, reply_to: Optional[str]) -> List[Indicator]:
        indicators = []
        if not reply_to:
            return indicators

        from_domain = get_registrable_domain(extract_domain(from_addr))
        reply_domain = get_registrable_domain(extract_domain(reply_to))

        if from_domain and reply_domain and from_domain != reply_domain:
            indicators.append(Indicator(
                module="header_forensics",
                indicator="reply_to_domain_mismatch",
                evidence=f"Reply-To domain '{reply_domain}' does not match From address domain '{from_domain}', potential redirection of user responses.",
                weight=0.5,
                confidence=0.90
            ))
        return indicators

    def check_received_hops(self, headers_raw: str) -> List[Indicator]:
        indicators = []
        if not headers_raw:
            return indicators

        received_headers = re.findall(r'^Received:\s', headers_raw, re.IGNORECASE | re.MULTILINE)
        hop_count = len(received_headers)
        if hop_count > 7:
            indicators.append(Indicator(
                module="header_forensics",
                indicator="excessive_received_hops",
                evidence=f"Message routed through unusually large number of hops ({hop_count} relays), possible relay/proxy evasion.",
                weight=0.2,
                confidence=0.70
            ))
        return indicators

    def analyze(self, email_input: EmailInput) -> List[Indicator]:
        indicators = []
        indicators.extend(self.parse_auth_results(email_input.headers_raw))
        indicators.extend(self.check_reply_to_mismatch(email_input.from_address, email_input.reply_to))
        indicators.extend(self.check_received_hops(email_input.headers_raw))
        return indicators
