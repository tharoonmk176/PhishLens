// Content script injected into mail.google.com

(function() {
  if (window.__PHISH_FORENSICS_INJECTED__) return;
  window.__PHISH_FORENSICS_INJECTED__ = true;

  let currentAnalysis = null;
  let chatHistory = [];

  function createSidebar() {
    if (document.getElementById("phish-forensics-root")) return;

    const root = document.createElement("div");
    root.id = "phish-forensics-root";
    root.innerHTML = `
      <div id="phish-forensics-header">
        <div class="pf-title">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Phish Forensics Copilot
        </div>
        <div style="display:flex; gap:8px; align-items:center;">
          <button id="pf-min-btn" style="background:transparent; border:none; color:#94a3b8; cursor:pointer; font-size:16px;">−</button>
          <button id="pf-close-btn" style="background:transparent; border:none; color:#94a3b8; cursor:pointer; font-size:16px;">✕</button>
        </div>
      </div>
      <div id="phish-forensics-body">
        <div id="pf-triage-card">
          <button id="pf-scan-now-btn" class="pf-btn" style="width:100%;">
            ⚡ Scan Open Email Forensic Data
          </button>
          <div id="pf-extracted-preview" style="display:none; font-size:11px; color:#94a3b8; margin-top:8px; background:#1e293b; padding:8px; border-radius:6px; word-break:break-all;">
            <div><b>Sender:</b> <span id="pf-prev-sender"></span></div>
            <div><b>Subject:</b> <span id="pf-prev-subject"></span></div>
            <div><b>URLs Found:</b> <span id="pf-prev-urls"></span></div>
          </div>
        </div>
        <div id="pf-result-view" style="display:none; flex-direction:column; gap:10px;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div id="pf-score-badge" class="pf-badge pf-high">RISK SCORE: 0/100</div>
            <div id="pf-action-text" style="font-weight:700; color:#f87171;">BLOCK_SENDER</div>
          </div>
          <div style="font-weight:600; font-size:12px; color:#94a3b8;">FIRED FORENSIC INDICATORS:</div>
          <div id="pf-indicators-list" style="display:flex; flex-direction:column; gap:6px; max-height:160px; overflow-y:auto;"></div>
          
          <div style="font-weight:600; font-size:12px; color:#94a3b8; margin-top:4px;">ASSISTANT EXPLANATION & CHAT:</div>
          <div id="pf-chat-messages" class="pf-chat-box">
            <div class="pf-msg-bot">Forensic scan complete. Ask any questions regarding indicators or threats.</div>
          </div>
          <div class="pf-input-row">
            <input id="pf-chat-input" class="pf-input" placeholder="Why is this email dangerous?" />
            <button id="pf-send-chat-btn" class="pf-btn">Send</button>
          </div>
          <button id="pf-download-report-btn" class="pf-btn" style="background:#475569;">
            📄 Download Incident Report
          </button>
        </div>
      </div>
    `;
    document.body.appendChild(root);

    // Event listeners
    document.getElementById("pf-close-btn").addEventListener("click", () => {
      root.remove();
      window.__PHISH_FORENSICS_INJECTED__ = false;
    });

    const bodyEl = document.getElementById("phish-forensics-body");
    document.getElementById("pf-min-btn").addEventListener("click", () => {
      bodyEl.style.display = bodyEl.style.display === "none" ? "flex" : "none";
    });

    document.getElementById("pf-scan-now-btn").addEventListener("click", scanCurrentEmail);
    document.getElementById("pf-send-chat-btn").addEventListener("click", sendChatMessage);
    document.getElementById("pf-chat-input").addEventListener("keypress", (e) => {
      if (e.key === "Enter") sendChatMessage();
    });
    document.getElementById("pf-download-report-btn").addEventListener("click", downloadReport);
  }

  function extractVisibleEmailData() {
    // 1. Subject extraction: Look for Gmail's subject headers
    let subject = "";
    const subjectSelectors = ["h2.hP", "h2[data-thread-perm-id]", ".ha h2", "span.bqe"];
    for (const sel of subjectSelectors) {
      const el = document.querySelector(sel);
      if (el && el.innerText.trim()) {
        subject = el.innerText.trim();
        break;
      }
    }

    // 2. Sender extraction: Check multiple Gmail DOM selector variations
    let fromAddress = "";
    let fromDisplayName = "";
    
    // Look in standard sender spans
    const senderSelectors = [
      "span.gD", 
      "span[email]", 
      ".gE.iv.gt span[email]", 
      ".go", 
      "span.qu",
      "h3.iw span[email]"
    ];

    for (const sel of senderSelectors) {
      const el = document.querySelector(sel);
      if (el) {
        fromAddress = el.getAttribute("email") || el.getAttribute("data-hovercard-id") || "";
        fromDisplayName = el.getAttribute("name") || el.innerText.trim() || "";
        if (fromAddress) break;
      }
    }

    // If still empty, regex search inside sender container
    if (!fromAddress) {
      const senderContainer = document.querySelector(".gE") || document.querySelector(".adn.ads");
      if (senderContainer) {
        const text = senderContainer.innerText || "";
        const emailMatch = text.match(/([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)/);
        if (emailMatch) {
          fromAddress = emailMatch[1];
        }
      }
    }

    // 3. Email Body text extraction
    let bodyText = "";
    const bodySelectors = ["div.a3s.aiL", "div.a3s", "div.gmail_default", "div.adn.ads div.ii.gt", ".editable[aria-label*='Message Body']"];
    for (const sel of bodySelectors) {
      const el = document.querySelector(sel);
      if (el && el.innerText.trim()) {
        bodyText = el.innerText.trim();
        break;
      }
    }

    // 4. Extract all hyperlinks inside email body container
    const links = new Set();
    const linkContainers = document.querySelectorAll("div.a3s a, div.ii.gt a, .adn.ads a");
    linkContainers.forEach(a => {
      const href = a.href || a.getAttribute("href");
      if (href && !href.startsWith("mailto:") && !href.startsWith("javascript:")) {
        // Filter out internal Google redirect wrappers if needed (e.g. google.com/url?q=...)
        try {
          if (href.includes("google.com/url?")) {
            const urlObj = new URL(href);
            const target = urlObj.searchParams.get("q");
            if (target) links.add(target);
            else links.add(href);
          } else {
            links.add(href);
          }
        } catch(e) {
          links.add(href);
        }
      }
    });

    // 5. Attachments
    const attachments = [];
    const attEls = document.querySelectorAll("span.aV3.hq, div.aQH span[download_url], .aZo");
    attEls.forEach(att => {
      const fn = att.innerText || att.getAttribute("aria-label") || "";
      if (fn) attachments.push({ filename: fn.trim() });
    });

    // Fallback if not inside an open email
    if (!fromAddress && !subject && !bodyText) {
      console.warn("[Phish Forensics] No active email view detected in Gmail DOM.");
    }

    return {
      message_id: "gmail_dom_" + Date.now(),
      from_address: fromAddress || "unknown@sender.com",
      from_display_name: fromDisplayName || fromAddress,
      subject: subject || "Unspecified Subject",
      body_text: bodyText,
      urls: Array.from(links),
      attachments: attachments
    };
  }

  async function scanCurrentEmail() {
    const scanBtn = document.getElementById("pf-scan-now-btn");
    scanBtn.innerText = "Analyzing Heuristics...";
    scanBtn.disabled = true;

    const emailData = extractVisibleEmailData();

    // Show extracted preview in UI for transparency
    const prevDiv = document.getElementById("pf-extracted-preview");
    if (prevDiv) {
      prevDiv.style.display = "block";
      document.getElementById("pf-prev-sender").innerText = emailData.from_address;
      document.getElementById("pf-prev-subject").innerText = emailData.subject;
      document.getElementById("pf-prev-urls").innerText = emailData.urls.length > 0 ? emailData.urls.join(", ") : "None detected";
    }

    try {
      const resp = await fetch("http://localhost:8000/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(emailData)
      });

      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}: ${await resp.text()}`);
      }

      const data = await resp.json();
      currentAnalysis = data;
      renderAnalysis(data);
    } catch (err) {
      alert("Phish Forensics Error: Ensure backend is running at http://localhost:8000.\n\nDetails: " + err.message);
    } finally {
      scanBtn.innerText = "⚡ Scan Open Email Forensic Data";
      scanBtn.disabled = false;
    }
  }

  function renderAnalysis(data) {
    document.getElementById("pf-result-view").style.display = "flex";
    const badge = document.getElementById("pf-score-badge");
    badge.innerText = `RISK SCORE: ${data.risk_score}/100`;
    badge.className = "pf-badge " + (data.risk_score >= 70 ? "pf-high" : (data.risk_score >= 30 ? "pf-med" : "pf-low"));

    const actionText = document.getElementById("pf-action-text");
    actionText.innerText = data.recommended_action;
    actionText.style.color = data.risk_score >= 70 ? "#f87171" : (data.risk_score >= 30 ? "#fbbf24" : "#4ade80");

    const indList = document.getElementById("pf-indicators-list");
    indList.innerHTML = "";
    if (!data.indicators || data.indicators.length === 0) {
      indList.innerHTML = "<div style='color:#94a3b8; font-size:12px; padding:6px;'>No suspicious threat indicators triggered. Email appears legitimate.</div>";
    } else {
      data.indicators.forEach(ind => {
        const item = document.createElement("div");
        item.className = "pf-indicator-card";
        item.innerHTML = `
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-weight:700; color:#38bdf8; font-family:monospace;">${ind.indicator}</span>
            <span style="font-size:10px; color:#94a3b8; font-family:monospace;">Weight: ${ind.weight}</span>
          </div>
          <div style="font-size:11px; color:#cbd5e1; margin-top:3px; line-height:1.4;">${ind.evidence}</div>
        `;
        indList.appendChild(item);
      });
    }
  }

  async function sendChatMessage() {
    const input = document.getElementById("pf-chat-input");
    const userMsg = input.value.trim();
    if (!userMsg || !currentAnalysis) return;

    input.value = "";
    const chatBox = document.getElementById("pf-chat-messages");

    const userBubble = document.createElement("div");
    userBubble.className = "pf-msg-user";
    userBubble.innerText = userMsg;
    chatBox.appendChild(userBubble);
    chatBox.scrollTop = chatBox.scrollHeight;

    try {
      const resp = await fetch("http://localhost:8000/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message_id: currentAnalysis.message_id,
          user_message: userMsg,
          analysis_result: currentAnalysis
        })
      });
      const data = await resp.json();
      const botBubble = document.createElement("div");
      botBubble.className = "pf-msg-bot";
      botBubble.innerText = data.reply;
      chatBox.appendChild(botBubble);
      chatBox.scrollTop = chatBox.scrollHeight;
    } catch (err) {
      const errBubble = document.createElement("div");
      errBubble.className = "pf-msg-bot";
      errBubble.innerText = "Error contacting assistant: " + err.message;
      chatBox.appendChild(errBubble);
    }
  }

  function downloadReport() {
    if (!currentAnalysis) return;
    window.open(`http://localhost:8000/api/report?message_id=${encodeURIComponent(currentAnalysis.message_id)}&format=pdf`, "_blank");
  }

  // Periodic check to ensure sidebar exists when viewing Gmail
  setInterval(() => {
    if (!document.getElementById("phish-forensics-root")) {
      createSidebar();
    }
  }, 2000);
})();
