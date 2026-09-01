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
        try:
            full_prompt = f"System Instructions:\n{system_prompt}\n\nUser Request:\n{user_prompt}"
            response = self.model.generate_content(full_prompt)
            return response.text or ""
        except Exception as e:
            return f"Error querying Gemini API: {str(e)}."
