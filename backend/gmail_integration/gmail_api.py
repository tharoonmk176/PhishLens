import base64
from typing import Optional
from detection.models import EmailInput
from .eml_parser import EmlParser

class GmailApiClient:
    def __init__(self, access_token: str):
        self.access_token = access_token

    def fetch_raw_message(self, message_id: str) -> Optional[EmailInput]:
        import requests
        url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{message_id}?format=RAW"
        headers = {"Authorization": f"Bearer {self.access_token}"}
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            raw_b64 = data.get("raw", "")
            # Base64url decode
            raw_bytes = base64.urlsafe_b64decode(raw_b64.encode("ASCII"))
            email_input = EmlParser.parse_bytes(raw_bytes)
            email_input.message_id = message_id
            return email_input
        return None
