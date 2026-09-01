import os
import json
from typing import Optional, Dict, Any

class GmailOAuthHandler:
    """Handles OAuth 2.0 flow for Gmail API access"""
    def __init__(self):
        self.client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
        self.client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")
        self.redirect_uri = os.environ.get("GMAIL_OAUTH_REDIRECT_URI", "http://localhost:8000/oauth2/callback")

    def get_auth_url(self) -> str:
        scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
        from urllib.parse import urlencode
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes),
            "access_type": "offline",
            "prompt": "consent"
        }
        return f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}"

    def exchange_code(self, code: str) -> Dict[str, Any]:
        import requests
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
            "grant_type": "authorization_code"
        }
        resp = requests.post(token_url, data=data, timeout=10)
        return resp.json()
