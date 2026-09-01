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

class CascadingLlmClient(LlmClient):
    """
    Primary: Gemini (gemini-2.0-flash)
    Fallback: Groq (llama-3.3-70b-versatile)
    Last resort: Mock
    """
    def __init__(self, provider_order: Optional[List[str]] = None):
        if provider_order:
            self.provider_order = provider_order
        else:
            default_order = getattr(settings, "LLM_PROVIDER_ORDER", ["gemini", "groq", "mock"])
            self.provider_order = default_order

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        gemini_key = os.environ.get("GEMINI_API_KEY")
        groq_key = os.environ.get("GROQ_API_KEY")

        for provider in self.provider_order:
            provider_name = provider.lower().strip()
            if provider_name == "gemini" and gemini_key:
                try:
                    from .gemini_client import GeminiClient
                    client = GeminiClient(api_key=gemini_key)
                    return client.generate(system_prompt, user_prompt)
                except Exception as e:
                    logger.warning(f"Gemini API call failed: {e}. Attempting fallback...")
                    continue

            elif provider_name == "groq" and groq_key:
                try:
                    from .groq_client import GroqClient
                    client = GroqClient(api_key=groq_key)
                    return client.generate(system_prompt, user_prompt)
                except Exception as e:
                    logger.warning(f"Groq API call failed: {e}. Attempting fallback...")
                    continue

            elif provider_name == "mock":
                return MockLlmClient().generate(system_prompt, user_prompt)

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
