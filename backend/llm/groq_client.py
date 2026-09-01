import os
from groq import Groq
from .client import LlmClient

class GroqClient(LlmClient):
    def __init__(self, api_key: str, model: str = "qwen/qwen3.8-27b"):
        self.client = Groq(api_key=api_key)
        self.model = os.environ.get("GROQ_MODEL", model)

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        candidate_models = [
            self.model,
            "qwen/qwen3.8-27b",
            "qwen/qwen3.6-27b",
            "openai/gpt-oss-120b",
            "openai/gpt-oss-20b"
        ]
        # Deduplicate while preserving order
        seen = set()
        models_to_try = [m for m in candidate_models if not (m in seen or seen.add(m))]

        for mod in models_to_try:
            try:
                chat_completion = self.client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt}
                    ],
                    model=mod,
                    temperature=0.2,
                    max_tokens=1024,
                )
                content = chat_completion.choices[0].message.content
                if content and content.strip():
                    return content.strip()
            except Exception:
                continue

        raise RuntimeError("Empty or failed response across all Groq models.")
