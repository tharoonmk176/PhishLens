import email
from email import policy
import re
from typing import Dict, Any, List
from detection.models import EmailInput, AttachmentInfo

class EmlParser:
    @staticmethod
    def parse_bytes(raw_bytes: bytes) -> EmailInput:
        msg = email.message_from_bytes(raw_bytes, policy=policy.default)
        
        # 1. Message-ID
        message_id = msg.get("Message-ID", "")
        if message_id:
            message_id = message_id.strip("<> \r\n")
        else:
            import uuid
            message_id = f"eml_{uuid.uuid4().hex[:12]}"

        # 2. From & Display Name
        from_header = msg.get("From", "")
        from_display_name = ""
        from_address = ""
        if from_header:
            from_str = str(from_header)
            match = re.search(r'(.*?)\s*<([^>]+)>', from_str)
            if match:
                from_display_name = match.group(1).strip('"\' ')
                from_address = match.group(2).strip()
            else:
                from_address = from_str.strip()

        # 3. Reply-To
        reply_to_header = msg.get("Reply-To", None)
        reply_to = None
        if reply_to_header:
            r_match = re.search(r'<([^>]+)>', str(reply_to_header))
            reply_to = r_match.group(1).strip() if r_match else str(reply_to_header).strip()

        # 4. Subject
        subject = str(msg.get("Subject", "") or "")

        # 5. Extract body (text and HTML) & attachments
        body_text_parts = []
        body_html_parts = []
        attachments: List[AttachmentInfo] = []

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                disposition = str(part.get("Content-Disposition", ""))
                filename = part.get_filename()

                if filename or "attachment" in disposition:
                    fn = filename or "unnamed_attachment"
                    payload = part.get_payload(decode=True)
                    size = len(payload) if payload else 0
                    attachments.append(AttachmentInfo(
                        filename=fn,
                        content_type=content_type,
                        size_bytes=size
                    ))
                else:
                    if content_type == "text/plain":
                        try:
                            body_text_parts.append(part.get_content())
                        except Exception:
                            body_text_parts.append(str(part.get_payload(decode=True) or ""))
                    elif content_type == "text/html":
                        try:
                            body_html_parts.append(part.get_content())
                        except Exception:
                            body_html_parts.append(str(part.get_payload(decode=True) or ""))
        else:
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                body_text_parts.append(msg.get_content())
            elif content_type == "text/html":
                body_html_parts.append(msg.get_content())

        body_text = "\n".join(body_text_parts)
        body_html = "\n".join(body_html_parts) if body_html_parts else None

        # 6. Extract URLs from body
        combined_text = f"{body_text} {body_html or ''}"
        urls = list(set(re.findall(r'https?://[^\s<>"\']+', combined_text)))

        # 7. Raw Headers
        headers_raw = ""
        for k, v in msg.items():
            headers_raw += f"{k}: {v}\n"

        return EmailInput(
            message_id=message_id,
            from_address=from_address,
            from_display_name=from_display_name,
            reply_to=reply_to,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            headers_raw=headers_raw,
            urls=urls,
            attachments=attachments
        )
