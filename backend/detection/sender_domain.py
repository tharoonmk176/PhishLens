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
from storage.duckdb_client import DuckDBClient

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

_RDAP_CACHE: Dict[str, Optional[int]] = {}

def extract_domain(email_or_url: str) -> str:
    if not email_or_url:
        return ""
    if "@" in email_or_url:
        domain = email_or_url.split("@")[-1].strip().lower()
    else:
        domain = email_or_url.strip().lower()
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
        self.brands: List[Dict[str, Any]] = []
        self._load_brands_from_duckdb(brand_corpus_path)

    def _load_brands_from_duckdb(self, fallback_path: Optional[str] = None):
        try:
            db = DuckDBClient()
            db_brands = db.get_known_brand_domains()
            if db_brands:
                for b in db_brands:
                    kws = [k.strip() for k in (b.get("logo_keywords") or "").split(",") if k.strip()]
                    legit_domain = b.get("legitimate_domain", "").strip()
                    self.brands.append({
                        "brand": b.get("brand", ""),
                        "legitimate_domains": [legit_domain] if legit_domain else [],
                        "keywords": kws
                    })
                return
        except Exception:
            pass

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        paths = [
            fallback_path,
            os.path.join(base_dir, "storage", "known_brand_domains_seed.json"),
            os.path.join(base_dir, "rag", "corpora", "brand_domains.json")
        ]
        for p in paths:
            if p and os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        raw = json.load(f)
                        for item in raw:
                            if "legitimate_domain" in item:
                                kws = [k.strip() for k in (item.get("logo_keywords") or "").split(",") if k.strip()]
                                self.brands.append({
                                    "brand": item.get("brand", ""),
                                    "legitimate_domains": [item.get("legitimate_domain", "")],
                                    "keywords": kws
                                })
                            else:
                                self.brands.append(item)
                        break
                except Exception:
                    pass

    def check_typosquat(self, sender_reg_domain: str) -> List[Indicator]:
        indicators = []
        if not sender_reg_domain:
            return indicators
        
        sender_reg_lower = sender_reg_domain.lower()

        # If sender domain is an exact legitimate domain for ANY brand in our knowledge base,
        # it is recognized as genuine and should not be falsely flagged as a typosquat of another brand.
        for brand_entry in self.brands:
            for legit in brand_entry.get("legitimate_domains", []):
                if legit:
                    legit_reg = get_registrable_domain(legit).lower()
                    if sender_reg_lower == legit_reg or sender_reg_lower.endswith("." + legit_reg):
                        return indicators

        sender_base = sender_reg_domain.split(".")[0] if "." in sender_reg_domain else sender_reg_domain
        
        # Check normalized confusable substitutions
        normalized_variants = [sender_base]
        full_normalized = sender_base
        for src, dst in VISUAL_SUBSTITUTIONS.items():
            if src in full_normalized:
                full_normalized = full_normalized.replace(src, dst)
        if full_normalized not in normalized_variants:
            normalized_variants.append(full_normalized)

        for src, dst in VISUAL_SUBSTITUTIONS.items():
            if src in sender_base:
                normalized_variants.append(sender_base.replace(src, dst))

        for brand_entry in self.brands:
            brand_name = brand_entry["brand"]
            legit_domains = brand_entry.get("legitimate_domains", [])
            keywords = brand_entry.get("keywords", [])

            for legit in legit_domains:
                if not legit:
                    continue
                legit_reg = get_registrable_domain(legit)
                legit_base = legit_reg.split(".")[0] if "." in legit_reg else legit_reg
                
                # Levenshtein distance check
                dist = 999
                if Levenshtein:
                    dist = Levenshtein.distance(sender_base, legit_base)
                else:
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
                    break

                # Check keyword combo like paypal-security or paypa1-login
                kw_match = any(
                    (kw.lower() in variant.lower() or kw.lower() in sender_base.lower())
                    for variant in normalized_variants
                    for kw in keywords
                    if len(kw) >= 3
                )
                if kw_match and sender_reg_domain not in legit_domains:
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
            legit_domains = [get_registrable_domain(d).lower() for d in brand_entry.get("legitimate_domains", []) if d]

            if brand_name in disp_lower or any(kw in disp_lower for kw in brand_entry.get("keywords", []) if len(kw) >= 4):
                if sender_reg_domain not in legit_domains:
                    indicators.append(Indicator(
                        module="sender_domain",
                        indicator="display_name_brand_mismatch",
                        evidence=f"Display name '{display_name}' claims to be '{brand_entry['brand']}', but sender domain is '{sender_reg_domain}'.",
                        weight=0.5,
                        confidence=0.90
                    ))
                    break
        return indicators

    def check_domain_age(self, domain: str) -> List[Indicator]:
        indicators = []
        if not requests or not domain or os.environ.get("DISABLE_EXTERNAL_RDAP") == "1":
            return indicators
        
        if domain in _RDAP_CACHE:
            age_days = _RDAP_CACHE[domain]
            if age_days is not None:
                if age_days < 30:
                    indicators.append(Indicator(
                        module="sender_domain",
                        indicator="newly_registered_domain",
                        evidence=f"Domain '{domain}' was registered only {age_days} days ago.",
                        weight=0.6,
                        confidence=0.85
                    ))
                elif age_days < 90:
                    indicators.append(Indicator(
                        module="sender_domain",
                        indicator="recent_registered_domain",
                        evidence=f"Domain '{domain}' was registered {age_days} days ago (<90 days).",
                        weight=0.3,
                        confidence=0.75
                    ))
            return indicators

        try:
            resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=3.0)
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
                    _RDAP_CACHE[domain] = age_days
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
                    return indicators
            _RDAP_CACHE[domain] = None
        except Exception:
            _RDAP_CACHE[domain] = None

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
