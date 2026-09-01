
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class AttachmentInfo:
    filename: str
    content_type: str = "application/octet-stream"
    size_bytes: int = 0

@dataclass
class EmailInput:
    message_id: str
    from_address: str
    from_display_name: str = ""
    reply_to: Optional[str] = None
    subject: str = ""
    body_text: str = ""
    body_html: Optional[str] = None
    headers_raw: str = ""
    urls: List[str] = field(default_factory=list)
    attachments: List[AttachmentInfo] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EmailInput":
        attachments_data = data.get("attachments", [])
        attachments = [
            AttachmentInfo(
                filename=att.get("filename", ""),
                content_type=att.get("content_type", "application/octet-stream"),
                size_bytes=att.get("size_bytes", 0)
            ) if isinstance(att, dict) else att
            for att in attachments_data
        ]
        return cls(
            message_id=str(data.get("message_id", "")),
            from_address=str(data.get("from_address", "")),
            from_display_name=str(data.get("from_display_name", "")),
            reply_to=data.get("reply_to"),
            subject=str(data.get("subject", "")),
            body_text=str(data.get("body_text", "")),
            body_html=data.get("body_html"),
            headers_raw=str(data.get("headers_raw", "")),
            urls=list(data.get("urls", [])),
            attachments=attachments
        )

@dataclass
class Indicator:
    module: str
    indicator: str
    evidence: str
    weight: float
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "indicator": self.indicator,
            "evidence": self.evidence,
            "weight": round(self.weight, 2),
            "confidence": round(self.confidence, 2)
        }

@dataclass
class AnalysisResult:
    message_id: str
    risk_score: int
    classification: str
    indicators: List[Indicator]
    iocs: Dict[str, Any]
    recommended_action: str
    analyzed_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "indicators": [ind.to_dict() for ind in self.indicators],
            "iocs": self.iocs,
            "recommended_action": self.recommended_action,
            "analyzed_at": self.analyzed_at
        }
