import json
import io
import datetime
from django.http import HttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.renderers import JSONRenderer, BaseRenderer

class PassthroughRenderer(BaseRenderer):
    media_type = '*/*'
    format = 'txt'
    def render(self, data, accepted_media_type=None, renderer_context=None):
        return data

class PdfRenderer(BaseRenderer):
    media_type = 'application/pdf'
    format = 'pdf'
    def render(self, data, accepted_media_type=None, renderer_context=None):
        return data

class HtmlRenderer(BaseRenderer):
    media_type = 'text/html'
    format = 'html'
    def render(self, data, accepted_media_type=None, renderer_context=None):
        return data

from detection.models import EmailInput
from detection.aggregator import RiskAggregator
from storage.duckdb_client import DuckDBClient
from rag.embeddings import generate_embedding, serialize_embedding
from rag.retrieval import RagRetriever
from llm.client import get_llm_client
from llm.prompts import (CHAT_SYSTEM_PROMPT, build_chat_prompt,
                         REPORT_SYSTEM_PROMPT, build_report_prompt)
from gmail_integration.eml_parser import EmlParser
from gmail_integration.oauth import GmailOAuthHandler
from .serializers import (EmailInputSerializer, ChatRequestSerializer,
                          ReportRequestSerializer, GmailAnalyzeRequestSerializer)

SESSION_HISTORY = {}

aggregator     = RiskAggregator()
duckdb_client  = DuckDBClient()
rag_retriever  = RagRetriever()


# ── /api/analyze ──────────────────────────────────────────────────────────────
class AnalyzeEmailView(APIView):
    parser_classes = [JSONParser]

    def post(self, request):
        serializer = EmailInputSerializer(data=request.data)
        if not serializer.is_valid():
            print(f"\033[31m[API /api/analyze ERROR]\033[0m Invalid payload: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        email_input = EmailInput.from_dict(serializer.validated_data)
        print(f"\n\033[1;32m[INGESTION]\033[0m Analyzing email from '\033[1m{email_input.from_address}\033[0m' | Subject: '{email_input.subject}'")

        analysis_result = aggregator.evaluate(email_input)
        result_dict = analysis_result.to_dict()

        color = "\033[31m" if analysis_result.risk_score >= 70 else ("\033[33m" if analysis_result.risk_score >= 30 else "\033[32m")
        print(f"  \033[1m↳ Heuristic Evaluation:\033[0m {len(analysis_result.indicators)} indicators fired | Score: {color}{analysis_result.risk_score}/100 ({analysis_result.classification})\033[0m")
        print(f"  \033[1m↳ Recommended Action:\033[0m \033[1;35m{analysis_result.recommended_action}\033[0m")

        top3 = ", ".join([ind.evidence for ind in analysis_result.indicators[:3]])
        emb_text = f"Subject: {email_input.subject}. Indicators: {top3}"
        emb = generate_embedding(emb_text)
        emb_bytes = serialize_embedding(emb) if emb is not None else None
        duckdb_client.save_analysis(result_dict, subject=email_input.subject,
                                    from_address=email_input.from_address,
                                    embedding_bytes=emb_bytes)
        print(f"  \033[1m↳ DuckDB Store:\033[0m Persisted record & vector embedding for message ID \033[36m{analysis_result.message_id}\033[0m")
        return Response(result_dict, status=status.HTTP_200_OK)


# ── /api/analyze-eml ─────────────────────────────────────────────────────────
class AnalyzeEmlUploadView(APIView):
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        file_obj = request.FILES.get('file')
        if not file_obj:
            raw = request.data.get('raw_eml')
            if raw:
                file_bytes = raw.encode('utf-8')
            else:
                return Response({"error": "No file or raw_eml provided"},
                                status=status.HTTP_400_BAD_REQUEST)
        else:
            file_bytes = file_obj.read()

        print(f"\n\033[1;32m[EML INGESTION]\033[0m Parsing raw RFC 822 .eml payload ({len(file_bytes)} bytes)...")
        email_input = EmlParser.parse_bytes(file_bytes)
        print(f"  \033[1m↳ Extracted:\033[0m From='{email_input.from_address}', Subject='{email_input.subject}', URLs={len(email_input.urls)}, Attachments={len(email_input.attachments)}")

        analysis_result = aggregator.evaluate(email_input)
        result_dict = analysis_result.to_dict()

        color = "\033[31m" if analysis_result.risk_score >= 70 else ("\033[33m" if analysis_result.risk_score >= 30 else "\033[32m")
        print(f"  \033[1m↳ Heuristic Evaluation:\033[0m {len(analysis_result.indicators)} indicators fired | Score: {color}{analysis_result.risk_score}/100 ({analysis_result.classification})\033[0m")

        top3 = ", ".join([ind.evidence for ind in analysis_result.indicators[:3]])
        emb_text = f"Subject: {email_input.subject}. Indicators: {top3}"
        emb = generate_embedding(emb_text)
        emb_bytes = serialize_embedding(emb) if emb is not None else None
        duckdb_client.save_analysis(result_dict, subject=email_input.subject,
                                    from_address=email_input.from_address,
                                    embedding_bytes=emb_bytes)

        result_dict["extracted_email"] = {
            "from_address":      email_input.from_address,
            "from_display_name": email_input.from_display_name,
            "subject":           email_input.subject,
            "reply_to":          email_input.reply_to,
            "body_text":         email_input.body_text[:1000],
            "urls":              email_input.urls,
            "attachments":       [att.filename for att in email_input.attachments],
        }
        return Response(result_dict, status=status.HTTP_200_OK)


# ── /api/analyze-gmail ───────────────────────────────────────────────────────
class AnalyzeGmailMessageView(APIView):
    parser_classes = [JSONParser]

    def post(self, request):
        serializer = GmailAnalyzeRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        access_token = serializer.validated_data["access_token"]
        message_id   = serializer.validated_data["message_id"]

        print(f"\n\033[1;35m[GMAIL API]\033[0m Fetching raw RFC 822 message '{message_id}' via OAuth token...")
        from gmail_integration.gmail_api import GmailApiClient
        client = GmailApiClient(access_token=access_token)
        email_input = client.fetch_raw_message(message_id)

        if not email_input:
            print(f"\033[31m[GMAIL API ERROR]\033[0m Failed to fetch message '{message_id}' from Google endpoint.")
            return Response(
                {"error": f"Failed to fetch Gmail message '{message_id}'. Ensure access token is valid."},
                status=status.HTTP_400_BAD_REQUEST
            )

        print(f"  \033[1m↳ Gmail Decoded:\033[0m From='{email_input.from_address}', Subject='{email_input.subject}'")
        analysis_result = aggregator.evaluate(email_input)
        result_dict = analysis_result.to_dict()

        color = "\033[31m" if analysis_result.risk_score >= 70 else ("\033[33m" if analysis_result.risk_score >= 30 else "\033[32m")
        print(f"  \033[1m↳ Heuristic Evaluation:\033[0m Score: {color}{analysis_result.risk_score}/100 ({analysis_result.classification})\033[0m | Action: {analysis_result.recommended_action}")

        top3 = ", ".join([ind.evidence for ind in analysis_result.indicators[:3]])
        emb_text = f"Subject: {email_input.subject}. Indicators: {top3}"
        emb = generate_embedding(emb_text)
        emb_bytes = serialize_embedding(emb) if emb is not None else None
        duckdb_client.save_analysis(result_dict, subject=email_input.subject,
                                    from_address=email_input.from_address,
                                    embedding_bytes=emb_bytes)

        result_dict["extracted_email"] = {
            "from_address":      email_input.from_address,
            "from_display_name": email_input.from_display_name,
            "subject":           email_input.subject,
            "reply_to":          email_input.reply_to,
            "body_text":         email_input.body_text[:1000],
            "urls":              email_input.urls,
            "attachments":       [att.filename for att in email_input.attachments],
        }
        return Response(result_dict, status=status.HTTP_200_OK)


# ── /api/chat ─────────────────────────────────────────────────────────────────
class ChatExplanationView(APIView):
    parser_classes = [JSONParser]

    def post(self, request):
        serializer = ChatRequestSerializer(data=request.data)
        if not serializer.is_valid():
            print(f"\033[31m[API /api/chat ERROR]\033[0m Invalid payload: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        message_id    = serializer.validated_data["message_id"]
        user_message  = serializer.validated_data["user_message"]
        analysis_result = serializer.validated_data.get("analysis_result")

        print(f"\n\033[1;34m[COPILOT CHAT]\033[0m User query on message \033[36m{message_id}\033[0m: \"\033[1m{user_message}\033[0m\"")

        if not analysis_result:
            stored = duckdb_client.get_analysis(message_id)
            analysis_result = stored or {"message_id": message_id, "risk_score": 0, "indicators": []}

        # Multi-turn history: Retrieve stored turns
        history = SESSION_HISTORY.get(message_id, [])
        if not history:
            db_history = duckdb_client.get_chat_history(message_id)
            if db_history:
                history = db_history

        # RAG retrieval over threat patterns and past incidents in DuckDB
        query = f"{user_message} {json.dumps(analysis_result.get('indicators', []))}"
        rag_snippets = rag_retriever.retrieve_relevant_context(query, top_k=3)
        print(f"  \033[1m↳ DuckDB RAG Context:\033[0m Retrieved {len(rag_snippets)} relevant threat signatures.")
        
        # Build prompt injecting session_history and rag_snippets
        user_prompt = build_chat_prompt(analysis_result, rag_snippets, history, user_message)

        reply_text = get_llm_client().generate(CHAT_SYSTEM_PROMPT, user_prompt)

        # Update in-memory session history
        turn_idx = len(history)
        history.append({"role": "user", "content": user_message})
        history.append({"role": "assistant", "content": reply_text})
        SESSION_HISTORY[message_id] = history[-10:]

        # Persist to DuckDB chat_sessions
        try:
            duckdb_client.save_chat_turn(message_id, turn_idx, "user", user_message)
            duckdb_client.save_chat_turn(message_id, turn_idx + 1, "assistant", reply_text)
            print(f"  \033[1m↳ Chat Persistence:\033[0m Turn {turn_idx//2 + 1} saved to DuckDB chat history.")
        except Exception:
            pass

        return Response({
            "message_id": message_id,
            "reply": reply_text,
            "rag_snippets": rag_snippets
        }, status=status.HTTP_200_OK)


# ── /api/report ───────────────────────────────────────────────────────────────
class GenerateReportView(APIView):
    parser_classes = [JSONParser]
    renderer_classes = [JSONRenderer, PdfRenderer, HtmlRenderer, PassthroughRenderer]

    def perform_content_negotiation(self, request, force=False):
        fmt = request.query_params.get("format", "json")
        if fmt == "pdf":
            return PdfRenderer(), "application/pdf"
        elif fmt == "html":
            return HtmlRenderer(), "text/html"
        return JSONRenderer(), "application/json"

    def get(self, request):
        return self._handle(request)

    def post(self, request):
        return self._handle(request)

    def _resolve_analysis(self, request):
        analysis_result = None
        message_id = ""

        if request.method == "POST" and request.data:
            s = ReportRequestSerializer(data=request.data)
            if not s.is_valid():
                return None, Response(s.errors, status=status.HTTP_400_BAD_REQUEST)
            message_id = s.validated_data.get("message_id", "")
            analysis_result = s.validated_data.get("analysis_result")

        params = getattr(request, 'query_params', getattr(request, 'GET', {}))

        if not analysis_result:
            mid = message_id or params.get("message_id", "")
            if mid:
                analysis_result = duckdb_client.get_analysis(mid)

        # Last resort — grab the most recent stored analysis
        if not analysis_result:
            recent = duckdb_client.get_history(limit=1)
            if recent:
                analysis_result = duckdb_client.get_analysis(recent[0]["message_id"])

        if not analysis_result:
            return None, Response(
                {"error": "No analysis found. Run a triage scan first."},
                status=status.HTTP_404_NOT_FOUND
            )
        return analysis_result, None

    def _handle(self, request):
        analysis_result, err = self._resolve_analysis(request)
        if err:
            return err

        message_id = analysis_result.get("message_id", "report")
        narrative  = get_llm_client().generate(REPORT_SYSTEM_PROMPT,
                                               build_report_prompt(analysis_result))
        params = getattr(request, 'query_params', getattr(request, 'GET', {}))
        fmt = params.get("format", "json")

        if fmt == "pdf":
            pdf_bytes = self._build_pdf(analysis_result, narrative)
            resp = HttpResponse(pdf_bytes, content_type="application/pdf")
            resp["Content-Disposition"] = f'attachment; filename="incident_report_{message_id}.pdf"'
            resp["Access-Control-Allow-Origin"] = "*"
            return resp

        if fmt == "html":
            return HttpResponse(self._build_html(analysis_result, narrative),
                                content_type="text/html")

        return Response({
            "message_id": message_id,
            "report_narrative": narrative,
            "analysis_result": analysis_result
        }, status=status.HTTP_200_OK)

    def _build_pdf(self, ar, narrative):
        # Try WeasyPrint first, then ReportLab
        try:
            import weasyprint
            html_content = self._build_html(ar, narrative)
            return weasyprint.HTML(string=html_content).write_pdf()
        except Exception:
            pass

        return self._build_reportlab_pdf(ar, narrative)

    def _build_reportlab_pdf(self, ar, narrative):
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                        Table, TableStyle, HRFlowable)
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib import colors

        score  = ar.get("risk_score", 0)
        cls_   = ar.get("classification", "UNKNOWN")
        action = ar.get("recommended_action", "N/A")
        iocs   = ar.get("iocs", {})
        inds   = ar.get("indicators", [])

        accent = (colors.HexColor("#ef4444") if score >= 70 else
                  colors.HexColor("#f59e0b") if score >= 30 else
                  colors.HexColor("#22c55e"))
        dark   = colors.HexColor("#0f172a")
        subtle = colors.HexColor("#64748b")
        light  = colors.HexColor("#f8fafc")
        grid   = colors.HexColor("#e2e8f0")

        base = getSampleStyleSheet()["Normal"]

        def ps(name, **kw):
            return ParagraphStyle(name, parent=base, **kw)

        title_s  = ps("ti", fontSize=20, textColor=dark, fontName="Helvetica-Bold", spaceAfter=3)
        sub_s    = ps("su", fontSize=9,  textColor=subtle, spaceAfter=2)
        h2_s     = ps("h2", fontSize=12, textColor=dark, fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=6)
        body_s   = ps("bo", fontSize=9,  textColor=dark, leading=13, spaceAfter=4)
        mono_s   = ps("mo", fontSize=8,  textColor=dark, fontName="Courier", leading=11)
        verd_s   = ps("ve", fontSize=11, textColor=accent, fontName="Helvetica-Bold")
        lbl_s    = ps("lb", fontSize=8,  textColor=subtle, fontName="Helvetica-Bold", spaceAfter=1)
        bold9_s  = ps("b9", fontSize=9,  textColor=dark, fontName="Helvetica-Bold")
        ev_s     = ps("ev", fontSize=8,  textColor=dark, leading=11)

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=1.8*cm, rightMargin=1.8*cm,
                                topMargin=1.8*cm,  bottomMargin=2*cm,
                                title=f"Incident Report – {ar.get('message_id','')}",
                                author="Phish Forensics")
        W = doc.width
        story = []

        # Header
        story.append(Paragraph("Phish Forensics — Security Incident Report", title_s))
        story.append(Paragraph(
            f"Auto-generated forensic dossier &nbsp;·&nbsp; "
            f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}",
            sub_s))
        story.append(HRFlowable(width="100%", thickness=2, color=accent, spaceAfter=12))

        # Verdict summary table
        score_s = ps("sc", fontSize=16, textColor=accent, fontName="Helvetica-Bold")
        act_s   = ps("ac", fontSize=10, textColor=dark, fontName="Helvetica-Bold")
        vtbl = Table([
            [Paragraph("VERDICT", lbl_s),
             Paragraph("RISK SCORE", lbl_s),
             Paragraph("ACTION", lbl_s)],
            [Paragraph(cls_.replace("_", " "), verd_s),
             Paragraph(f"<b>{score} / 100</b>", score_s),
             Paragraph(action.replace("_", " "), act_s)],
        ], colWidths=[W*0.30, W*0.25, W*0.45])
        vtbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), light),
            ("BOX",           (0,0), (-1,-1), 0.5, grid),
            ("INNERGRID",     (0,0), (-1,-1), 0.5, grid),
            ("TOPPADDING",    (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ]))
        story.append(vtbl)
        story.append(Spacer(1, 12))

        # 1. Executive Summary & Narrative
        story.append(Paragraph("1. Executive Summary", h2_s))
        story.append(HRFlowable(width="100%", thickness=0.5, color=grid, spaceAfter=8))
        for line in narrative.strip().split("\n"):
            clean = line.strip().lstrip("#").strip()
            if clean:
                story.append(Paragraph(clean, body_s))
        story.append(Spacer(1, 8))

        # 2. Forensic Indicators
        story.append(Paragraph(f"2. Forensic Indicators ({len(inds)} fired)", h2_s))
        story.append(HRFlowable(width="100%", thickness=0.5, color=grid, spaceAfter=8))
        if inds:
            rows = [[Paragraph("<b>Indicator</b>", bold9_s),
                     Paragraph("<b>Forensic Evidence</b>", bold9_s),
                     Paragraph("<b>Wt</b>", bold9_s)]]
            for ind in inds:
                rows.append([
                    Paragraph(ind.get("indicator","").replace("_"," "), mono_s),
                    Paragraph(ind.get("evidence",""), ev_s),
                    Paragraph(str(ind.get("weight","")), mono_s),
                ])
            itbl = Table(rows, colWidths=[W*0.24, W*0.67, W*0.09])
            itbl.setStyle(TableStyle([
                ("BACKGROUND",    (0,0), (-1,0), light),
                ("ROWBACKGROUNDS",(0,1), (-1,-1),
                 [colors.white, colors.HexColor("#f8fafc")]),
                ("BOX",           (0,0), (-1,-1), 0.5, grid),
                ("INNERGRID",     (0,0), (-1,-1), 0.25, grid),
                ("TOPPADDING",    (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6),
                ("LEFTPADDING",   (0,0), (-1,-1), 7),
                ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ]))
            story.append(itbl)
        else:
            story.append(Paragraph("No threat indicators fired.", body_s))
        story.append(Spacer(1, 8))

        # 3. IOCs
        story.append(Paragraph("3. Indicators of Compromise (IOCs)", h2_s))
        story.append(HRFlowable(width="100%", thickness=0.5, color=grid, spaceAfter=8))
        ioc_rows = [
            ("Sender Address",   iocs.get("sender_address","N/A")),
            ("Hostile Domains",  ", ".join(iocs.get("domains",[])) or "None"),
            ("Malicious URLs",   "\n".join(iocs.get("urls",[])) or "None"),
            ("Attachment Names", ", ".join(iocs.get("attachment_names",[])) or "None"),
        ]
        itbl2 = Table(
            [[Paragraph(lbl, lbl_s), Paragraph(val, mono_s)] for lbl, val in ioc_rows],
            colWidths=[W*0.25, W*0.75])
        itbl2.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.white, light]),
            ("BOX",           (0,0), (-1,-1), 0.5, grid),
            ("INNERGRID",     (0,0), (-1,-1), 0.25, grid),
            ("TOPPADDING",    (0,0), (-1,-1), 7),
            ("BOTTOMPADDING", (0,0), (-1,-1), 7),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
        ]))
        story.append(itbl2)
        story.append(Spacer(1, 8))

        # 4. Recommended Action
        story.append(Paragraph("4. Recommended Action", h2_s))
        story.append(HRFlowable(width="100%", thickness=0.5, color=grid, spaceAfter=8))
        action_detail = {
            "BLOCK_SENDER": "Block sender at all gateway filters immediately and purge related messages from all mailboxes.",
            "QUARANTINE":   "Quarantine the message. Await security analyst review before delivery.",
        }.get(action, "Flag for user awareness. No immediate containment required.")
        story.append(Paragraph(
            f"<b>{action.replace('_', ' ')}</b> — {action_detail}", body_s))

        def footer(cv, doc_):
            cv.saveState()
            cv.setFont("Helvetica", 7)
            cv.setFillColor(subtle)
            cv.drawString(1.8*cm, 1.1*cm,
                f"Phish Forensics · Deterministic forensic engine · "
                f"{datetime.datetime.now().strftime('%Y-%m-%d')}")
            cv.drawRightString(A4[0]-1.8*cm, 1.1*cm, f"Page {doc_.page}")
            cv.restoreState()

        doc.build(story, onFirstPage=footer, onLaterPages=footer)
        return buf.getvalue()

    def _build_html(self, ar, narrative):
        score  = ar.get("risk_score", 0)
        col    = "#ef4444" if score >= 70 else "#f59e0b" if score >= 30 else "#22c55e"
        iocs   = ar.get("iocs", {})
        rows   = "".join(
            f"<tr><td><code>{i.get('indicator','')}</code></td>"
            f"<td>{i.get('evidence','')}</td>"
            f"<td>{i.get('weight','')}</td></tr>"
            for i in ar.get("indicators", [])
        )
        urls_html = "<br>".join(f"<code>{u}</code>" for u in iocs.get("urls", [])) or "None"
        return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
@page {{ margin: 1.5cm; size: A4; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; color: #0f172a; line-height: 1.5; font-size: 13px; }}
h1 {{ font-size: 20px; font-weight: 800; margin-bottom: 2px; color: #0f172a; }}
.sub {{ color: #64748b; font-size: 11px; margin-bottom: 14px; }}
.verdict-box {{ display: flex; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px; margin-bottom: 20px; }}
.badge {{ display: inline-block; padding: 4px 12px; border-radius: 16px; background: {col}; color: #fff; font-weight: 700; font-size: 12px; }}
h2 {{ font-size: 13px; font-weight: 700; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px; margin-top: 20px; margin-bottom: 8px; color: #0f172a; text-transform: uppercase; letter-spacing: 0.5px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 11px; margin-top: 6px; }}
th {{ background: #f8fafc; padding: 6px 8px; text-align: left; border-bottom: 2px solid #cbd5e1; font-weight: 600; color: #475569; }}
td {{ padding: 6px 8px; border-bottom: 1px solid #f1f5f9; vertical-align: top; }}
pre {{ background: #f8fafc; padding: 10px; border-radius: 6px; font-size: 11px; white-space: pre-wrap; border-left: 3px solid #3b82f6; margin: 0; font-family: inherit; }}
code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; color: #0f172a; }}
.action {{ font-weight: 700; color: {col}; font-size: 13px; }}
</style></head><body>
<h1>Phish Forensics — Security Incident Report</h1>
<p class="sub">Auto-generated forensic dossier &nbsp;·&nbsp; {datetime.datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</p>
<div class="verdict-box">
  <div>
    <span class="badge">{ar.get('classification','').replace('_',' ')} &nbsp;·&nbsp; {score}/100</span>
    <p style="margin: 6px 0 0 0; font-size: 12px;"><b>Action:</b> <span class="action">{ar.get('recommended_action','').replace('_',' ')}</span></p>
  </div>
</div>

<h2>1. Executive Summary</h2>
<pre>{narrative}</pre>

<h2>2. Forensic Indicators ({len(ar.get('indicators',[]))} fired)</h2>
<table><thead><tr><th>Indicator</th><th>Evidence</th><th>Weight</th></tr></thead>
<tbody>{rows if rows else "<tr><td colspan='3'>No threat indicators fired.</td></tr>"}</tbody></table>

<h2>3. Indicators of Compromise (IOCs)</h2>
<p><b>Sender:</b> <code>{iocs.get('sender_address','N/A')}</code></p>
<p><b>Hostile Domains:</b> <code>{', '.join(iocs.get('domains', [])) or 'None'}</code></p>
<p><b>Malicious URLs:</b><br>{urls_html}</p>
<p><b>Attachment Names:</b> <code>{', '.join(iocs.get('attachment_names',[])) or 'None'}</code></p>

<h2>4. Recommended Action</h2>
<p class="action">{ar.get('recommended_action','').replace('_',' ')}</p>
</body></html>"""


# ── /api/history ──────────────────────────────────────────────────────────────
class HistoryView(APIView):
    def get(self, request):
        limit = int(request.query_params.get("limit", 50))
        return Response(duckdb_client.get_history(limit=limit), status=status.HTTP_200_OK)


# ── /api/dashboard ────────────────────────────────────────────────────────────
class DashboardStatsView(APIView):
    def get(self, request):
        return Response(duckdb_client.get_dashboard_stats(), status=status.HTTP_200_OK)


# ── /oauth2/callback ──────────────────────────────────────────────────────────
class OAuthCallbackView(APIView):
    def get(self, request):
        code = request.query_params.get("code")
        if not code:
            return Response({"error": "Missing code"}, status=status.HTTP_400_BAD_REQUEST)
        return Response(GmailOAuthHandler().exchange_code(code), status=status.HTTP_200_OK)
