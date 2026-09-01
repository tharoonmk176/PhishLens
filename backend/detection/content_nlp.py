import re
from typing import List
from .models import EmailInput, Indicator

try:
    from spellchecker import SpellChecker
    _spell = SpellChecker()
except ImportError:
    _spell = None

URGENCY_PATTERNS = [
    "account will be suspended",
    "account suspended",
    "act now",
    "immediate action required",
    "verify immediately",
    "unusual activity",
    "unauthorized login",
    "click here to avoid",
    "within 24 hours",
    "within 12 hours",
    "security alert",
    "critical update",
    "terminate your account",
    "final notice",
    "respond immediately",
    "urgent notification",
    "payment overdue",
    "service cancellation",
    "action required",
    "limited time",
    "account locked",
    "suspended permanently"
]

CREDENTIAL_PATTERNS = [
    r"enter your password",
    r"confirm your pin",
    r"update your billing details",
    r"verify your identity",
    r"provide your card details",
    r"enter credit card",
    r"enter debit card",
    r"login to verify",
    r"re-enter password",
    r"ssn|social security number",
    r"verify your credentials",
    r"submit your otp",
    r"provide bank details"
]

class ContentNlpAnalyzer:
    def __init__(self):
        self.urgency_phrases = URGENCY_PATTERNS
        self.credential_regexes = [re.compile(p, re.IGNORECASE) for p in CREDENTIAL_PATTERNS]

    def analyze_urgency(self, text: str) -> List[Indicator]:
        indicators = []
        lower_text = text.lower()
        matched_phrases = []

        for phrase in self.urgency_phrases:
            if phrase in lower_text:
                matched_phrases.append(phrase)

        if matched_phrases:
            # 0.3 per unique phrase, capped at 0.6 total
            calculated_weight = min(0.6, 0.3 * len(matched_phrases))
            indicators.append(Indicator(
                module="content_nlp",
                indicator="urgency_language",
                evidence=f"Detected artificial urgency language: {', '.join([repr(p) for p in matched_phrases[:4]])}.",
                weight=calculated_weight,
                confidence=0.85
            ))
        return indicators

    def analyze_credential_request(self, text: str) -> List[Indicator]:
        indicators = []
        matched_patterns = []

        for r in self.credential_regexes:
            match = r.search(text)
            if match:
                matched_patterns.append(match.group(0))

        if matched_patterns:
            indicators.append(Indicator(
                module="content_nlp",
                indicator="credential_harvesting_phrasing",
                evidence=f"Direct request for sensitive credentials/data: {', '.join([repr(p) for p in matched_patterns[:3]])}.",
                weight=0.7,
                confidence=0.92
            ))
        return indicators

    def analyze_spelling_anomalies(self, text: str) -> List[Indicator]:
        indicators = []
        if not _spell:
            return indicators

        words = re.findall(r'\b[a-zA-Z]{4,}\b', text)
        if len(words) >= 15:
            # check misspelled ratio
            misspelled = _spell.unknown(words)
            ratio = len(misspelled) / len(words)
            if ratio > 0.15: # >15% anomalous words
                weight = min(0.3, round(ratio * 0.5, 2))
                indicators.append(Indicator(
                    module="content_nlp",
                    indicator="grammar_spelling_anomaly",
                    evidence=f"High anomaly rate in email body ({len(misspelled)} unusual or misspelled tokens, {round(ratio*100, 1)}% anomaly rate).",
                    weight=weight,
                    confidence=0.75
                ))
        return indicators

    def analyze(self, email_input: EmailInput) -> List[Indicator]:
        indicators = []
        full_content = f"{email_input.subject} {email_input.body_text}"
        
        indicators.extend(self.analyze_urgency(full_content))
        indicators.extend(self.analyze_credential_request(full_content))
        indicators.extend(self.analyze_spelling_anomalies(email_input.body_text))

        return indicators
