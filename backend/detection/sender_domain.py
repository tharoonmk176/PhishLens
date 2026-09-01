import os
import json
import re
from typing import List, Dict, Any, Optional
import datetime

try:
    import Levenshtein
except ImportError:
    Levenshtein = None

try:
    import tldextract
except ImportError:
    tldextract = None

try:
    import requests
except ImportError:
    requests = None

from .models import EmailInput, Indicator

VISUAL_SUBSTITUTIONS = {
    '1': 'l', 'l': '1',
    '0': 'o', 'o': '0',
    'rn': 'm', 'm': 'rn',
    'vv': 'w', 'w': 'vv',
    'cl': 'd', 'd': 'cl',
    '5': 's', 's': '5',
    '8': 'b', 'b': '8',
    '@': 'a'
}

def extract_domain(email_or_url: str) -> str:
    if not email_or_url:
        return ""
    if "@" in email_or_url:
        domain = email_or_url.split("@")[-1].strip().lower()
    else:
        domain = email_or_url.strip().lower()
    # Strip < > if present
    domain = domain.strip("<> ")
    if "/" in domain:
        domain = domain.split("/")[0]
    return domain

def get_registrable_domain(domain: str) -> str:
    if not domain:
        return ""
    if tldextract:
        ext = tldextract.extract(domain)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}".lower()
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:]).lower()
    return domain.lower()

class SenderDomainAnalyzer:
    def __init__(self, brand_corpus_path: Optional[str] = None):
        self.brands = []
        if not brand_corpus_path:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            brand_corpus_path = os.path.join(base_dir, "rag", "corpora", "brand_domains.json")
        
        if os.path.exists(brand_corpus_path):
            try:
                with open(brand_corpus_path, "r", encoding="utf-8") as f:
                    self.brands = json.load(f)
            except Exception:
                self.brands = []

    def check_typosquat(self, sender_reg_domain: str) -> List[Indicator]:
        indicators = []
        sender_base = sender_reg_domain.split(".")[0] if "." in sender_reg_domain else sender_reg_domain
        
        # Check normalized confusable substitutions
        normalized_variants = [sender_base]
        for src, dst in VISUAL_SUBSTITUTIONS.items():
            if src in sender_base:
                normalized_variants.append(sender_base.replace(src, dst))

        for brand_entry in self.brands:
            brand_name = brand_entry["brand"]
            legit_domains = brand_entry.get("legitimate_domains", [])
            keywords = brand_entry.get("keywords", [])

            # If sender domain is an exact legitimate domain, no typosquatting
            if any(sender_reg_domain == legit.lower() or sender_reg_domain.endswith("." + legit.lower()) for legit in legit_domains):
                continue

            # Check character substitutions
            for legit in legit_domains:
                legit_reg = get_registrable_domain(legit)
                legit_base = legit_reg.split(".")[0] if "." in legit_reg else legit_reg
                
                # Levenshtein distance check
                dist = 999
                if Levenshtein:
                    dist = Levenshtein.distance(sender_base, legit_base)
                else:
                    # fallback manual edit distance
                    s1, s2 = sender_base, legit_base
                    dist = abs(len(s1) - len(s2)) + sum(1 for a, b in zip(s1, s2) if a != b)

                is_confusable = False
                matched_sub = ""
                for variant in normalized_variants:
                    if variant == legit_base and sender_base != legit_base:
                        is_confusable = True
                        matched_sub = f"visual substitution variant matches '{legit_base}'"
                        break

                if is_confusable or (0 < dist <= 2 and len(legit_base) >= 4 and sender_base != legit_base):
                    evidence = f"Domain '{sender_reg_domain}' visually mimics legitimate brand '{brand_name}' ({legit_reg})."
                    if is_confusable:
                        evidence += f" Detected char substitution: {matched_sub}."
                    else:
                        evidence += f" Levenshtein distance = {dist}."
                    indicators.append(Indicator(
                        module="sender_domain",
                        indicator="domain_typosquat",
                        evidence=evidence,
                        weight=0.9,
                        confidence=0.95
                    ))
                    break # Break per brand

                # Check keyword combo like paypal-security or paypa1-login
                if any(kw in sender_base for kw in keywords) and sender_reg_domain not in legit_domains:
                    indicators.append(Indicator(
                        module="sender_domain",
                        indicator="brand_keyword_in_unauthorized_domain",
                        evidence=f"Domain '{sender_reg_domain}' contains brand keyword matching '{brand_name}' but is not an authorized domain.",
                        weight=0.85,
                        confidence=0.90
                    ))
                    break

        return indicators

    def check_display_name_mismatch(self, display_name: str, sender_reg_domain: str) -> List[Indicator]:
        indicators = []
        if not display_name:
            return indicators

        disp_lower = display_name.lower()
        for brand_entry in self.brands:
            brand_name = brand_entry["brand"].lower()
            legit_domains = [get_registrable_domain(d).lower() for d in brand_entry.get("legitimate_domains", [])]

            if brand_name in disp_lower or any(kw in disp_lower for kw in brand_entry.get("keywords", [])):
                # If display name claims to be this brand, check if sender domain is legit
                if sender_reg_domain not in legit_domains:
                    indicators.append(Indicator(
                        module="sender_domain",
                        indicator="display_name_brand_mismatch",
                        evidence=f"Display name '{display_name}' claims to be '{brand_entry['brand']}', but sender domain is '{sender_reg_domain}'.",
                        weight=0.6,
                        confidence=0.90
                    ))
                    break
        return indicators

    def check_domain_age(self, domain: str) -> List[Indicator]:
        indicators = []
        # Query RDAP (rdap.org/domain/{domain})
        if not requests or not domain:
            return indicators
        
        try:
            resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=2.5)
            if resp.status_code == 200:
                data = resp.json()
                events = data.get("events", [])
                reg_date_str = None
                for ev in events:
                    if ev.get("eventAction") in ["registration", "created"]:
                        reg_date_str = ev.get("eventDate")
                        break
                if reg_date_str:
                    clean_date = reg_date_str.split("T")[0]
                    reg_date = datetime.datetime.strptime(clean_date, "%Y-%m-%d").date()
                    age_days = (datetime.date.today() - reg_date).days
                    if age_days < 30:
                        indicators.append(Indicator(
                            module="sender_domain",
                            indicator="newly_registered_domain",
                            evidence=f"Domain '{domain}' was registered only {age_days} days ago ({clean_date}).",
                            weight=0.6,
                            confidence=0.85
                        ))
                    elif age_days < 90:
                        indicators.append(Indicator(
                            module="sender_domain",
                            indicator="recent_registered_domain",
                            evidence=f"Domain '{domain}' was registered {age_days} days ago (<90 days, {clean_date}).",
                            weight=0.3,
                            confidence=0.75
                        ))
        except Exception:
            # RDAP fails gracefully if offline or rate-limited
            pass

        return indicators

    def analyze(self, email_input: EmailInput) -> List[Indicator]:
        indicators = []
        raw_domain = extract_domain(email_input.from_address)
        reg_domain = get_registrable_domain(raw_domain)

        # 1. Typosquat / visual confusable / brand keywords
        indicators.extend(self.check_typosquat(reg_domain))

        # 2. Display name mismatch
        indicators.extend(self.check_display_name_mismatch(email_input.from_display_name, reg_domain))

        # 3. Domain age
        indicators.extend(self.check_domain_age(reg_domain))

        return indicators
