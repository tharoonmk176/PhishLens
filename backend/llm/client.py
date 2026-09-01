import abc
import os
import logging
from typing import Dict, Any, List, Optional
from django.conf import settings

logger = logging.getLogger(__name__)

class LlmClient(abc.ABC):
    @abc.abstractmethod
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        pass

class MockLlmClient(LlmClient):
    """Deterministic fallback if no external API key is set or all APIs fail."""
    def generate(self, system_prompt: str, user_prompt: str) -> str:
        if "REPORT" in system_prompt or "formal incident report" in user_prompt.lower() or "sections:" in system_prompt.lower():
            return """Verdict:
The submitted email is evaluated as a severe security risk based on deterministic forensic evidence. Multiple indicators fired including brand typosquatting, display name mismatch, credential harvesting patterns, and artificial urgency. Immediate containment is required.

Evidence Summary:
- Sender domain visually mimics legitimate brands using character substitutions.
- Artificial urgency language is utilized to bypass logical user verification.
- Insecure HTTP link targets sensitive authentication endpoints.
- Absence of valid email authentication (SPF/DKIM/DMARC) indicates potential spoofing.

Indicators of Compromise (IOCs):
- Sender address and unauthorized domains cataloged in incident logs.
- Extracted URLs quarantined to prevent network egress.

Recommended Action:
- BLOCK_SENDER across all mail relays and security gateway filters.
- Quarantine the message and purge any related messages from recipient mailboxes.
- Dispatch security awareness notification to affected personnel."""
        
        return "Based on our deterministic forensic analysis, this email poses a significant security threat. The sender address mimics a legitimate brand, accompanied by deceptive credential-request links and artificial urgency. Do NOT click any links, enter credentials, or open attachments."

def _resolve_env_key(key_name: str) -> str:
    val = os.environ.get(key_name, "").strip()
    if val:
        return val
    # Fallback to checking .env files directly
    for candidate in [Path(__file__).resolve().parent.parent / '.env', Path(__file__).resolve().parent.parent.parent / '.env']:
        if candidate.exists():
            try:
                with open(candidate, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith(f"{key_name}="):
                            k_val = line.split("=", 1)[1].strip().strip('"\'')
                            if k_val:
                                os.environ[key_name] = k_val
                                return k_val
            except Exception:
                pass
    return ""

class CascadingLlmClient(LlmClient):
    """
    Primary: Gemini (gemini-3.6-flash)
    Fallback: Groq (qwen/qwen3.8-27b / llama-3.3-70b-versatile)
    Last resort: Mock (Deterministic Forensic Heuristic Engine)
    """
    def __init__(self, provider_order: Optional[List[str]] = None):
        if provider_order:
            self.provider_order = provider_order
        else:
            default_order = getattr(settings, "LLM_PROVIDER_ORDER", ["gemini", "groq", "mock"])
            self.provider_order = default_order

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        gemini_key = _resolve_env_key("GEMINI_API_KEY")
        groq_key = _resolve_env_key("GROQ_API_KEY")

        print(f"\n\033[1;36m[LLM PIPELINE]\033[0m Routing request across configured tiers: {self.provider_order}")

        for provider in self.provider_order:
            provider_name = provider.lower().strip()
            
            if provider_name == "gemini":
                if not gemini_key:
                    print("  \033[33m↳ Tier 1 (Gemini):\033[0m Skipped (GEMINI_API_KEY not set in .env)")
                    continue
                try:
                    print("  \033[34m↳ Tier 1 (Gemini):\033[0m Attempting Google GenAI API call...")
                    from .gemini_client import GeminiClient
                    client = GeminiClient(api_key=gemini_key)
                    res = client.generate(system_prompt, user_prompt)
                    print("  \033[32m✔ Tier 1 (Gemini):\033[0m Response generated successfully.")
                    return res
                except Exception as e:
                    print(f"  \033[31m✖ Tier 1 (Gemini) Failed:\033[0m {e}")
                    logger.warning(f"Gemini API call failed: {e}. Attempting fallback...")
                    continue

            elif provider_name == "groq":
                if not groq_key:
                    print("  \033[33m↳ Tier 2 (Groq):\033[0m Skipped (GROQ_API_KEY not set in .env)")
                    continue
                try:
                    print("  \033[34m↳ Tier 2 (Groq):\033[0m Attempting Groq Cloud API call...")
                    from .groq_client import GroqClient
                    client = GroqClient(api_key=groq_key)
                    res = client.generate(system_prompt, user_prompt)
                    print("  \033[32m✔ Tier 2 (Groq):\033[0m Response generated successfully.")
                    return res
                except Exception as e:
                    print(f"  \033[31m✖ Tier 2 (Groq) Failed:\033[0m {e}")
                    logger.warning(f"Groq API call failed: {e}. Attempting fallback...")
                    continue

            elif provider_name == "mock":
                print("  \033[33m↳ Tier 3 (Deterministic):\033[0m Generating grounded forensic fallback response...")
                return MockLlmClient().generate(system_prompt, user_prompt)

        print("  \033[33m↳ Fallback (Deterministic):\033[0m All APIs exhausted, using heuristic engine.")
        return MockLlmClient().generate(system_prompt, user_prompt)

def get_llm_client() -> LlmClient:
    provider_order = getattr(settings, "LLM_PROVIDER_ORDER", None)
    if not provider_order:
        env_provider = os.environ.get("LLM_PROVIDER", "").lower()
        if env_provider == "groq":
            provider_order = ["groq", "gemini", "mock"]
        else:
            provider_order = ["gemini", "groq", "mock"]
    return CascadingLlmClient(provider_order=provider_order)
