import re
import json
import os
from typing import List, Optional
import urllib.parse

try:
    import requests
except ImportError:
    requests = None

try:
    import tldextract
except ImportError:
    tldextract = None

from .models import EmailInput, Indicator

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".buzz", ".fit", ".rest",
    ".work", ".click", ".link", ".cam", ".monster", ".country", ".kim", ".surf",
    ".icu", ".bar", ".cfd", ".quest", ".sbs"
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "cutt.ly", "shorturl.at", "tiny.cc", "rebrand.ly"
}

IP_HOST_REGEX = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

def get_subdomain_and_domain(url: str):
    parsed = urllib.parse.urlparse(url)
    hostname = (parsed.hostname or "").lower()
    if tldextract:
        ext = tldextract.extract(hostname)
        sub = ext.subdomain.lower()
        reg_domain = f"{ext.domain}.{ext.suffix}".lower() if ext.domain and ext.suffix else hostname
        return sub, reg_domain, hostname
    parts = hostname.split(".")
    if len(parts) >= 2:
        reg_domain = ".".join(parts[-2:])
        sub = ".".join(parts[:-2])
        return sub, reg_domain, hostname
    return "", hostname, hostname

class UrlAnalyzer:
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

    def unwind_redirects(self, url: str, max_redirects: int = 5) -> List[str]:
        if not requests or not url.startswith(("http://", "https://")):
            return [url]
        chain = [url]
        current_url = url
        for _ in range(max_redirects):
            try:
                resp = requests.head(current_url, allow_redirects=False, timeout=2.5, headers={'User-Agent': 'Mozilla/5.0 SecurityScanner'})
                if resp.status_code in [301, 302, 303, 307, 308] and 'Location' in resp.headers:
                    next_url = resp.headers['Location']
                    if not next_url.startswith("http"):
                        next_url = urllib.parse.urljoin(current_url, next_url)
                    chain.append(next_url)
                    current_url = next_url
                else:
                    break
            except Exception:
                break
        return chain

    def analyze_single_url(self, url: str) -> List[Indicator]:
        indicators = []
        if not url:
            return indicators

        # Unwind shorteners / redirects if applicable
        unwound_chain = [url]
        parsed_init = urllib.parse.urlparse(url)
        host_init = (parsed_init.hostname or "").lower()
        if host_init in SHORTENER_DOMAINS:
            unwound_chain = self.unwind_redirects(url)
            if len(unwound_chain) > 1:
                indicators.append(Indicator(
                    module="url_analysis",
                    indicator="url_shortener_expanded",
                    evidence=f"Shortened URL '{url}' redirects to '{unwound_chain[-1]}'.",
                    weight=0.45,
                    confidence=0.90
                ))

        for target_url in set(unwound_chain):
            parsed = urllib.parse.urlparse(target_url)
            hostname = (parsed.hostname or "").lower()
            if not hostname:
                continue

            # 1. IP-literal host
            if IP_HOST_REGEX.match(hostname):
                indicators.append(Indicator(
                    module="url_analysis",
                    indicator="ip_literal_url",
                    evidence=f"URL '{target_url}' uses raw IP address '{hostname}' instead of a registered domain.",
                    weight=0.8,
                    confidence=0.95
                ))

            # 2. Suspicious TLD
            for tld in SUSPICIOUS_TLDS:
                if hostname.endswith(tld):
                    indicators.append(Indicator(
                        module="url_analysis",
                        indicator="suspicious_tld",
                        evidence=f"URL host '{hostname}' uses known high-abuse TLD '{tld}'.",
                        weight=0.4,
                        confidence=0.85
                    ))
                    break

            # 3. Brand name in subdomain but not registrable domain
            sub, reg_domain, full_host = get_subdomain_and_domain(target_url)
            for brand_entry in self.brands:
                brand_name = brand_entry["brand"]
                keywords = brand_entry.get("keywords", [])
                legit_domains = brand_entry.get("legitimate_domains", [])

                if any(reg_domain == legit.lower() for legit in legit_domains):
                    continue # Valid brand domain

                # Check if brand or keyword is nested in subdomain
                if sub and any(kw in sub for kw in keywords):
                    indicators.append(Indicator(
                        module="url_analysis",
                        indicator="brand_in_subdomain",
                        evidence=f"URL '{target_url}' embeds brand keyword '{brand_name}' in subdomain '{sub}' while registered domain is '{reg_domain}'.",
                        weight=0.85,
                        confidence=0.95
                    ))
                    break

            # 4. HTTP for sensitive paths
            if parsed.scheme == "http" and any(k in parsed.path.lower() for k in ["login", "verify", "account", "secure", "auth", "signin"]):
                indicators.append(Indicator(
                    module="url_analysis",
                    indicator="insecure_login_url",
                    evidence=f"Insecure HTTP URL '{target_url}' requests authentication or verification without SSL/TLS encryption.",
                    weight=0.7,
                    confidence=0.90
                ))

        return indicators

    def analyze(self, email_input: EmailInput) -> List[Indicator]:
        indicators = []
        urls = list(email_input.urls)
        
        # Also extract URLs from body_text / body_html using regex if not explicitly provided
        body_content = f"{email_input.body_text} {email_input.body_html or ''}"
        found_urls = re.findall(r'https?://[^\s<>"\']+', body_content)
        all_urls = list(set(urls + found_urls))

        for url in all_urls:
            indicators.extend(self.analyze_single_url(url))

        return indicators
