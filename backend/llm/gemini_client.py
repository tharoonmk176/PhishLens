import os
import logging
import warnings
from .client import LlmClient

logger = logging.getLogger(__name__)

# Suppress AFC function calling info logs from google_genai
logging.getLogger("google_genai").setLevel(logging.ERROR)
logging.getLogger("google.genai").setLevel(logging.ERROR)

class GeminiClient(LlmClient):
    """
    Modern Google GenAI client supporting Gemini models with automatic candidate fallback.
    """
    def __init__(self, api_key: str, model_name: str = "gemini-3.6-flash"):
        self.api_key = api_key
        self.model_name = os.environ.get("GEMINI_MODEL", model_name)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        # Verified active Google Gemini models
        candidate_models = [
            self.model_name,
            "gemini-3.6-flash",
            "gemini-3.5-flash",
            "gemini-3.1-flash-lite"
        ]
        seen = set()
        models_to_try = [m for m in candidate_models if not (m in seen or seen.add(m))]

        # 1. Try modern google.genai SDK
        try:
            from google import genai
            from google.genai import types
            client = genai.Client(api_key=self.api_key)

            for mod in models_to_try:
                try:
                    response = client.models.generate_content(
                        model=mod,
                        contents=f"System Instruction:\n{system_prompt}\n\nUser Request:\n{user_prompt}",
                        config=types.GenerateContentConfig(
                            temperature=0.2,
                        )
                    )
                    if response and response.text:
                        return response.text.strip()
                except Exception as e:
                    err_str = str(e).lower()
                    if any(k in err_str for k in ["404", "503", "not found", "unavailable", "deprecated", "rate"]):
                        continue
                    raise e
        except Exception as sdk_err:
            logger.debug(f"google.genai SDK error: {sdk_err}. Attempting legacy fallback...")

        # 2. Try legacy google.generativeai fallback
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                import google.generativeai as legacy_genai
                legacy_genai.configure(api_key=self.api_key)
                for mod in models_to_try:
                    try:
                        model = legacy_genai.GenerativeModel(model_name=mod)
                        resp = model.generate_content(f"{system_prompt}\n\n{user_prompt}")
                        if resp and resp.text:
                            return resp.text.strip()
                    except Exception:
                        continue
        except Exception:
            pass

        raise RuntimeError("Failed to generate response from Gemini API across all candidate models.")
