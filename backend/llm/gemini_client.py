import os
import google.generativeai as genai
from .client import LlmClient

class GeminiClient(LlmClient):
    def __init__(self, api_key: str, model_name: str = "gemini-2.0-flash"):
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(
            model_name=model_name,
            system_instruction=None
        )

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        full_prompt = f"System:\n{system_prompt}\n\n{user_prompt}"
        response = self.model.generate_content(full_prompt)
        if response and response.text:
            return response.text.strip()
        raise RuntimeError("Empty response received from Gemini API.")
