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
        <div class="pf-brand">
          <div class="pf-icon-box">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          </div>
          <div class="pf-brand-text">
            <span class="pf-brand-name">Phish Forensics</span>
            <span class="pf-brand-sub">SIH-2026 · PS-02 COPILOT</span>
          </div>
        </div>
        <div class="pf-hdr-actions">
          <button id="pf-min-btn" class="pf-ctrl-btn" title="Minimize">−</button>
          <button id="pf-close-btn" class="pf-ctrl-btn" title="Close">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
      </div>
      <div id="phish-forensics-body">
        <div class="pf-action-card">
          <button id="pf-scan-now-btn" class="pf-btn-primary">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <span>Scan Open Email Forensics</span>
          </button>
          <div id="pf-extracted-preview" style="display:none; font-size:10.5px; color:#94a3b8; background:#070a11; padding:8px; border-radius:6px; border:1px solid rgba(255,255,255,0.06); word-break:break-all;">
            <div><b style="color:#64748b;">SENDER:</b> <span id="pf-prev-sender" style="color:#e2e8f0; font-family:monospace;"></span></div>
            <div style="margin-top:2px;"><b style="color:#64748b;">SUBJECT:</b> <span id="pf-prev-subject" style="color:#cbd5e1;"></span></div>
            <div style="margin-top:2px;"><b style="color:#64748b;">DETECTED URLS:</b> <span id="pf-prev-urls" style="color:#38bdf8; font-family:monospace;"></span></div>
          </div>
        </div>

        <div id="pf-result-view" style="display:none; flex-direction:column; gap:12px;">
          <!-- Radial Gauge Verdict Hero -->
          <div id="pf-verdict-card" class="pf-verdict-hero pf-verdict-hero-high">
            <div class="pf-gauge-wrap">
              <svg class="pf-gauge-svg" width="80" height="80" viewBox="0 0 80 80">
                <circle class="pf-gauge-bg" cx="40" cy="40" r="32" />
                <circle id="pf-gauge-arc" class="pf-gauge-fill" cx="40" cy="40" r="32" stroke="#ef4444" stroke-dasharray="201.06" stroke-dashoffset="0" />
              </svg>
              <div class="pf-gauge-text">
                <span id="pf-gauge-score-val" class="pf-gauge-num" style="color:#ef4444;">0</span>
                <span class="pf-gauge-lbl">/100 RISK</span>
              </div>
            </div>
            <div class="pf-verdict-info">
              <span id="pf-score-badge" class="pf-badge pf-high">HIGH RISK</span>
              <span id="pf-action-text" class="pf-action-text">ACTION: BLOCK SENDER</span>
              <div id="pf-iocs-container" class="pf-iocs-wrap"></div>
            </div>
          </div>

          <!-- Indicators List -->
          <div>
            <div class="pf-sec-title">
              <span>Triggered Indicators</span>
              <span id="pf-ind-count" class="pf-count-badge">0</span>
            </div>
            <div id="pf-indicators-list" class="pf-indicators-container" style="margin-top:6px;"></div>
          </div>
          
          <!-- Copilot AI Terminal -->
          <div class="pf-copilot-card">
            <div class="pf-copilot-hdr">
              <span style="display:flex; align-items:center; gap:6px;">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                Security Copilot
              </span>
              <span style="font-size:9.5px; color:#64748b; font-family:monospace;">DuckDB RAG</span>
            </div>
            <div id="pf-chat-messages" class="pf-copilot-chat">
              <div class="pf-msg-bot">Scan complete. Ask questions about this incident or request containment advice.</div>
            </div>
            <div class="pf-quick-chips">
              <button class="pf-chip" onclick="window.__pfSendQuickChat('Why is this domain flagged?')">Explain domain</button>
              <button class="pf-chip" onclick="window.__pfSendQuickChat('What containment action is recommended?')">Containment</button>
              <button class="pf-chip" onclick="window.__pfSendQuickChat('Explain the SPF/DKIM headers.')">Headers</button>
            </div>
            <div class="pf-input-row">
              <input id="pf-chat-input" class="pf-input" placeholder="Ask follow-up questions..." />
              <button id="pf-send-chat-btn" class="pf-send-btn">Send</button>
            </div>
          </div>

          <!-- Bottom Action Buttons -->
          <div style="display:flex; gap:8px;">
            <button id="pf-download-report-btn" class="pf-btn-ghost" style="flex:1; display:flex; align-items:center; justify-content:center; gap:6px;">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              <span>Export PDF Report</span>
            </button>
            <a href="http://localhost:5173" target="_blank" class="pf-btn-ghost" style="flex:1; display:flex; align-items:center; justify-content:center; gap:6px;">
              <span>Open Dashboard</span>
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
            </a>
          </div>
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
      let analysisData = null;

      // 1. Attempt Gmail API fetch via OAuth token if available
      try {
        const authResp = await new Promise(resolve => {
          chrome.runtime.sendMessage({ action: "getAuthToken", interactive: false }, resolve);
        });

        const openMsgEl = document.querySelector("[data-legacy-message-id], [data-message-id]");
        const legacyId = openMsgEl ? (openMsgEl.getAttribute("data-legacy-message-id") || openMsgEl.getAttribute("data-message-id")) : null;

        if (authResp && authResp.success && authResp.token && legacyId) {
          const gResp = await fetch("http://localhost:8000/api/analyze-gmail", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ access_token: authResp.token, message_id: legacyId })
          });
          if (gResp.ok) {
            analysisData = await gResp.json();
          }
        }
      } catch (oauthErr) {
        // Fall back to direct DOM analysis
      }

      // 2. Direct DOM fallback analysis
      if (!analysisData) {
        const resp = await fetch("http://localhost:8000/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(emailData)
        });

        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}: ${await resp.text()}`);
        }
        analysisData = await resp.json();
      }

      currentAnalysis = analysisData;
      renderAnalysis(analysisData);
    } catch (err) {
      alert("Phish Forensics Error: Ensure backend is running at http://localhost:8000.\n\nDetails: " + err.message);
    } finally {
      scanBtn.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span>Scan Open Email Forensics</span>
      `;
      scanBtn.disabled = false;
    }
  }

  function renderAnalysis(data) {
    document.getElementById("pf-result-view").style.display = "flex";

    const score = data.risk_score || 0;
    const scoreColor = score >= 70 ? "#ef4444" : (score >= 30 ? "#f59e0b" : "#10b981");
    const heroClass = score >= 70 ? "pf-verdict-hero-high" : (score >= 30 ? "pf-verdict-hero-med" : "pf-verdict-hero-low");

    const vCard = document.getElementById("pf-verdict-card");
    vCard.className = "pf-verdict-hero " + heroClass;

    // 1. Update Radial Gauge
    const scoreVal = document.getElementById("pf-gauge-score-val");
    scoreVal.innerText = score;
    scoreVal.style.color = scoreColor;

    const arc = document.getElementById("pf-gauge-arc");
    const circ = 201.06; // 2 * pi * 32
    const offset = circ - (score / 100) * circ;
    arc.setAttribute("stroke", scoreColor);
    arc.style.strokeDashoffset = offset;

    // 2. Badges & Actions
    const badge = document.getElementById("pf-score-badge");
    badge.innerText = data.classification.replace(/_/g, " ");
    badge.className = "pf-badge " + (score >= 70 ? "pf-high" : (score >= 30 ? "pf-med" : "pf-low"));

    const actionText = document.getElementById("pf-action-text");
    actionText.innerText = "ACTION: " + (data.recommended_action || "REVIEW").replace(/_/g, " ");

    // 3. IOC Chips
    const iocsWrap = document.getElementById("pf-iocs-container");
    iocsWrap.innerHTML = "";
    if (data.iocs?.sender_address) {
      const chip = document.createElement("span");
      chip.className = "pf-ioc-chip";
      chip.innerText = "From: " + data.iocs.sender_address;
      iocsWrap.appendChild(chip);
    }
    if (data.iocs?.domains?.length > 0) {
      data.iocs.domains.slice(0, 2).forEach(d => {
        const chip = document.createElement("span");
        chip.className = "pf-ioc-chip";
        chip.innerText = "Host: " + d;
        iocsWrap.appendChild(chip);
      });
    }

    // 4. Indicator List
    const indCount = document.getElementById("pf-ind-count");
    const indList = document.getElementById("pf-indicators-list");
    indList.innerHTML = "";

    if (!data.indicators || data.indicators.length === 0) {
      indCount.innerText = "0";
      indList.innerHTML = "<div style='color:#10b981; font-size:11px; padding:8px; background:rgba(16,185,129,0.1); border-radius:6px; border:1px solid rgba(16,185,129,0.25); display:flex; align-items:center; gap:6px;'><svg width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2.5'><polyline points='20 6 9 17 4 12'/></svg><span>No suspicious indicators triggered. Message verified clean.</span></div>";
    } else {
      indCount.innerText = String(data.indicators.length);
      data.indicators.forEach(ind => {
        const item = document.createElement("div");
        item.className = "pf-ind-card";
        item.innerHTML = `
          <div class="pf-ind-top">
            <div style="display:flex; align-items:center; gap:6px;">
              <span class="pf-ind-module">${(ind.module || "HEURISTIC").replace(/_/g, " ")}</span>
              <span class="pf-ind-name">${(ind.indicator || "").replace(/_/g, " ")}</span>
            </div>
            <span class="pf-ind-metrics">wt: ${ind.weight}</span>
          </div>
          <div class="pf-ind-evidence">${ind.evidence}</div>
        `;
        indList.appendChild(item);
      });
    }
  }

  window.__pfSendQuickChat = function(promptText) {
    const input = document.getElementById("pf-chat-input");
    if (input) {
      input.value = promptText;
      sendChatMessage();
    }
  };

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

    const loadingBubble = document.createElement("div");
    loadingBubble.className = "pf-msg-bot";
    loadingBubble.innerText = "Synthesizing forensic explanation...";
    chatBox.appendChild(loadingBubble);
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
      loadingBubble.innerText = data.reply || "No reply generated.";
      chatBox.scrollTop = chatBox.scrollHeight;
    } catch (err) {
      loadingBubble.innerText = "Error contacting security copilot: " + err.message;
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
