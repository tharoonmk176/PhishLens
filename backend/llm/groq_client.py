import os
from groq import Groq
from .client import LlmClient

class GroqClient(LlmClient):
    def __init__(self, api_key: str, model: str = "llama-3.3-70b-versatile"):
        self.client = Groq(api_key=api_key)
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        chat_completion = self.client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            model=self.model,
            temperature=0.2,
            max_tokens=1024,
        )
        content = chat_completion.choices[0].message.content
        if content:
            return content.strip()
        raise RuntimeError("Empty response received from Groq API.")
