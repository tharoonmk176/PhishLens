import re
from typing import List
from .models import EmailInput, Indicator

DOUBLE_EXTENSION_REGEX = re.compile(
    r'.*\.(pdf|docx?|xlsx?|pptx?|jpg|png|txt|csv|zip)\.(exe|scr|bat|js|vbs|hta|cmd|pif|ps1|cpl|jar|iso|img)$',
    re.IGNORECASE
)

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".js", ".vbs", ".hta", ".cmd", ".pif", ".ps1", ".cpl", ".jar", ".iso", ".img", ".wsf", ".msi"
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam"
}

class AttachmentLinkAnalyzer:
    def analyze(self, email_input: EmailInput) -> List[Indicator]:
        indicators = []
        for att in email_input.attachments:
            fn = att.filename
            if not fn:
                continue

            lower_fn = fn.lower()

            # 1. Double extension spoofing
            if DOUBLE_EXTENSION_REGEX.match(lower_fn):
                indicators.append(Indicator(
                    module="attachment_link",
                    indicator="double_extension_spoofing",
                    evidence=f"Attachment '{fn}' uses deceptive double-extension technique to conceal executable payload.",
                    weight=0.9,
                    confidence=0.98
                ))

            # 2. Executable / script extension directly
            ext = "." + lower_fn.split(".")[-1] if "." in lower_fn else ""
            if ext in EXECUTABLE_EXTENSIONS and not DOUBLE_EXTENSION_REGEX.match(lower_fn):
                indicators.append(Indicator(
                    module="attachment_link",
                    indicator="executable_attachment",
                    evidence=f"Attachment '{fn}' contains dangerous executable file format ('{ext}').",
                    weight=0.85,
                    confidence=0.95
                ))

            # 3. Macro-enabled office documents
            if ext in MACRO_EXTENSIONS:
                indicators.append(Indicator(
                    module="attachment_link",
                    indicator="macro_enabled_document",
                    evidence=f"Attachment '{fn}' is a macro-enabled Office document ('{ext}'), frequently used for dropper staging.",
                    weight=0.5,
                    confidence=0.90
                ))

        return indicators
