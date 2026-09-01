import os
from groq import Groq
from .client import LlmClient

class GroqClient(LlmClient):
    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.client = Groq(api_key=api_key)
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        try:
            chat_completion = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                model=self.model,
                temperature=0.2,
                max_tokens=1024,
            )
            return chat_completion.choices[0].message.content or ""
        except Exception as e:
            return f"Error connecting to Groq API: {str(e)}. (Forensic verdict is safe & deterministic)."
