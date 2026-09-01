import datetime
import math
from typing import List, Dict, Any
from .models import EmailInput, Indicator, AnalysisResult
from .sender_domain import SenderDomainAnalyzer, extract_domain, get_registrable_domain
from .url_analysis import UrlAnalyzer
from .content_nlp import ContentNlpAnalyzer
from .header_forensics import HeaderForensicsAnalyzer
from .attachment_link import AttachmentLinkAnalyzer

class RiskAggregator:
    def __init__(self):
        self.sender_analyzer = SenderDomainAnalyzer()
        self.url_analyzer = UrlAnalyzer()
        self.content_analyzer = ContentNlpAnalyzer()
        self.header_analyzer = HeaderForensicsAnalyzer()
        self.attachment_analyzer = AttachmentLinkAnalyzer()

    def run_all_analyzers(self, email_input: EmailInput) -> List[Indicator]:
        indicators: List[Indicator] = []
        indicators.extend(self.sender_analyzer.analyze(email_input))
        indicators.extend(self.url_analyzer.analyze(email_input))
        indicators.extend(self.content_analyzer.analyze(email_input))
        indicators.extend(self.header_analyzer.analyze(email_input))
        indicators.extend(self.attachment_analyzer.analyze(email_input))

        # Sort by weight desc, then confidence desc
        indicators.sort(key=lambda x: (x.weight, x.confidence), reverse=True)
        return indicators

    def compute_noisy_or_score(self, indicators: List[Indicator]) -> int:
        """
        Noisy-OR combination:
        risk_score = min(100, round(100 * (1 - product(1 - weight_i * confidence_i for i in indicators))))
        
        Formula Rationale:
        Each indicator acts as an independent piece of evidence indicating threat probability.
        The complement product (1 - P(threat)) naturally saturates at 1.0 (100%), avoids 
        naive double-counting of multiple weak indicators, and scales smoothly.
        """
        if not indicators:
            return 0
        
        prob_safe = 1.0
        for ind in indicators:
            prob_threat_i = min(0.99, max(0.01, ind.weight * ind.confidence))
            prob_safe *= (1.0 - prob_threat_i)

        risk_score = min(100, max(0, round(100.0 * (1.0 - prob_safe))))
        return risk_score

    def extract_iocs(self, email_input: EmailInput, indicators: List[Indicator]) -> Dict[str, Any]:
        domains = set()
        if email_input.from_address:
            d = extract_domain(email_input.from_address)
            if d:
                domains.add(d)
        if email_input.reply_to:
            d = extract_domain(email_input.reply_to)
            if d:
                domains.add(d)

        # Collect URLs
        urls = list(set(email_input.urls))

        # Attachment filenames
        attachments = [att.filename for att in email_input.attachments if att.filename]

        return {
            "sender_address": email_input.from_address,
            "domains": sorted(list(domains)),
            "urls": urls,
            "attachment_names": attachments,
            "attachment_hashes": []
        }

    def evaluate(self, email_input: EmailInput) -> AnalysisResult:
        indicators = self.run_all_analyzers(email_input)
        risk_score = self.compute_noisy_or_score(indicators)

        # Classification bands: 0-29 = LOW_RISK, 30-69 = MEDIUM_RISK, 70-100 = HIGH_RISK
        if risk_score >= 70:
            classification = "HIGH_RISK"
            recommended_action = "BLOCK_SENDER"
        elif risk_score >= 30:
            classification = "MEDIUM_RISK"
            recommended_action = "QUARANTINE"
        else:
            classification = "LOW_RISK"
            recommended_action = "USER_AWARENESS_NOTE" if len(indicators) > 0 else "NO_ACTION_REQUIRED"

        iocs = self.extract_iocs(email_input, indicators)
        analyzed_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        return AnalysisResult(
            message_id=email_input.message_id or f"msg_{int(datetime.datetime.now().timestamp())}",
            risk_score=risk_score,
            classification=classification,
            indicators=indicators,
            iocs=iocs,
            recommended_action=recommended_action,
            analyzed_at=analyzed_at
        )
