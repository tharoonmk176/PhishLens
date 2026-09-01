import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import {
  Shield, Send, Upload, RefreshCw, Download,
  AlertTriangle, CheckCircle2, ChevronDown, ChevronUp,
  BarChart3, Clock, Inbox, Copy, Check, Sparkles,
  Paperclip, Link2, ExternalLink, Search, ShieldAlert, ShieldCheck, Trash2
} from 'lucide-react';

const API_BASE = 'http://localhost:8000';

const EMPTY_EMAIL = {
  from_address: '',
  from_display_name: '',
  reply_to: '',
  subject: '',
  body_text: '',
  urls: '',
  attachments: '',
  headers_raw: ''
};

export default function App() {
  const [tab, setTab] = useState('analyze');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const [email, setEmail] = useState(EMPTY_EMAIL);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  // Copilot Chat
  const [messages, setMessages] = useState([]);
  const [chatInput, setChatInput] = useState('');
  const [chatLoading, setChatLoading] = useState(false);
  const chatBottomRef = useRef(null);

  // History & Analytics
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [search, setSearch] = useState('');

  useEffect(() => {
    if (tab === 'history') loadHistory();
    if (tab === 'analytics') loadStats();
  }, [tab]);

  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const clearForm = () => {
    setEmail(EMPTY_EMAIL);
    setResult(null);
    setError('');
    setMessages([]);
  };

  const setField = (k, v) => setEmail(prev => ({ ...prev, [k]: v }));

  const analyzeEmail = async () => {
    setError('');
    setLoading(true);
    try {
      const payload = {
        from_address: email.from_address,
        from_display_name: email.from_display_name,
        reply_to: email.reply_to || null,
        subject: email.subject,
        body_text: email.body_text,
        headers_raw: email.headers_raw || '',
        urls: (email.urls || '').split('\n').map(s => s.trim()).filter(Boolean),
        attachments: (email.attachments || '').split('\n').map(s => s.trim()).filter(Boolean).map(f => ({ filename: f })),
      };

      const { data } = await axios.post(`${API_BASE}/api/analyze`, payload);
      setResult(data);
      setMessages([
        {
          role: 'ai',
          text: `Analysis complete. Risk Score: ${data.risk_score}/100 (${data.classification.replace(/_/g, ' ')}). You can ask me to explain any finding or suggest next steps.`
        }
      ]);
    } catch (err) {
      setError(err.response?.data?.error || 'Unable to contact backend at ' + API_BASE);
    } finally {
      setLoading(false);
    }
  };

  const uploadEml = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setError('');
    setLoading(true);
    const fd = new FormData();
    fd.append('file', file);
    try {
      const { data } = await axios.post(`${API_BASE}/api/analyze-eml`, fd);
      setResult(data);
      if (data.extracted_email) {
        const ex = data.extracted_email;
        setEmail({
          from_address: ex.from_address || '',
          from_display_name: ex.from_display_name || '',
          reply_to: ex.reply_to || '',
          subject: ex.subject || '',
          body_text: ex.body_text || '',
          urls: (ex.urls || []).join('\n'),
          attachments: (ex.attachments || []).join('\n'),
          headers_raw: ex.headers_raw || ''
        });
      }
      setMessages([
        {
          role: 'ai',
          text: `Parsed .eml file. Evaluated as ${data.classification.replace(/_/g, ' ')} (${data.risk_score}/100). Ask any questions below.`
        }
      ]);
    } catch (err) {
      setError('Failed to parse .eml file.');
    } finally {
      setLoading(false);
    }
  };

  const sendChatMessage = async (presetText) => {
    const text = presetText || chatInput;
    if (!text.trim() || !result) return;
    if (!presetText) setChatInput('');

    setMessages(prev => [...prev, { role: 'me', text }]);
    setChatLoading(true);
    try {
      const { data } = await axios.post(`${API_BASE}/api/chat`, {
        message_id: result.message_id,
        user_message: text,
        analysis_result: result,
      });
      setMessages(prev => [...prev, { role: 'ai', text: data.reply }]);
    } catch {
      setMessages(prev => [...prev, { role: 'ai', text: 'Error contacting security assistant.' }]);
    } finally {
      setChatLoading(false);
    }
  };

  const loadHistory = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/api/history`);
      setHistory(data);
    } catch {}
  };

  const loadStats = async () => {
    try {
      const { data } = await axios.get(`${API_BASE}/api/dashboard`);
      setStats(data);
    } catch {}
  };

  const inspectPastItem = (item) => {
    setTab('analyze');
    axios.get(`${API_BASE}/api/report?message_id=${encodeURIComponent(item.message_id)}&format=json`)
      .then(res => {
        if (res.data?.analysis_result) {
          setResult(res.data.analysis_result);
          setMessages([{
            role: 'ai',
            text: `Loaded archived scan for ${item.from_address}. Risk score: ${item.risk_score}/100.`
          }]);
        }
      })
      .catch(() => {});
  };

  const scoreColor = (score) => score >= 70 ? '#ef4444' : score >= 30 ? '#f59e0b' : '#10b981';

  return (
    <div className="app-container">
      {/* ── Minimal Navbar ── */}
      <header className="navbar">
        <div className="nav-brand">
          <div className="brand-icon">
            <Shield size={18} strokeWidth={2.4} />
          </div>
          <span className="brand-title">Phish Guard</span>
          <span className="brand-sub">PS-02</span>
        </div>

        <nav className="nav-links">
          <button
            className={`nav-btn ${tab === 'analyze' ? 'nav-btn-active' : ''}`}
            onClick={() => setTab('analyze')}
          >
            <Inbox size={14} /> Analyze
          </button>
          <button
            className={`nav-btn ${tab === 'history' ? 'nav-btn-active' : ''}`}
            onClick={() => setTab('history')}
          >
            <Clock size={14} /> History
          </button>
          <button
            className={`nav-btn ${tab === 'analytics' ? 'nav-btn-active' : ''}`}
            onClick={() => setTab('analytics')}
          >
            <BarChart3 size={14} /> Analytics
          </button>
        </nav>

        <div className="nav-status">
          <span className="dot-green"></span>
          <span>Engine Online</span>
        </div>
      </header>

      {/* ── Main View ── */}
      <main className="main-view">
        {tab === 'analyze' && (
          <div className="grid-triage">
            {/* ── Left: Clean Manual Input Card ── */}
            <div className="card">
              <div className="card-title-row">
                <span className="card-title">
                  <Inbox size={14} className="text-cyan" /> Manual Email Input
                </span>
                <div className="flex gap-2">
                  <button className="preset-btn" onClick={clearForm} title="Clear all fields">
                    <Trash2 size={12} /> Clear
                  </button>
                  <label className="preset-btn cursor-pointer" title="Upload .eml file">
                    <Upload size={12} /> Upload .eml
                    <input type="file" accept=".eml,.msg,.txt" onChange={uploadEml} hidden />
                  </label>
                </div>
              </div>

              {/* Main Fields */}
              <div className="input-group">
                <label className="input-label">Sender Email</label>
                <input
                  className="clean-input mono-font"
                  placeholder="e.g. security@paypal.com"
                  value={email.from_address}
                  onChange={e => setField('from_address', e.target.value)}
                />
              </div>

              <div className="input-group">
                <label className="input-label">Subject</label>
                <input
                  className="clean-input"
                  placeholder="Subject line..."
                  value={email.subject}
                  onChange={e => setField('subject', e.target.value)}
                />
              </div>

              <div className="input-group">
                <label className="input-label">Message Body</label>
                <textarea
                  className="clean-input clean-textarea"
                  rows={4}
                  placeholder="Paste email content here..."
                  value={email.body_text}
                  onChange={e => setField('body_text', e.target.value)}
                />
              </div>

              {/* Expandable Advanced Artifacts */}
              <div>
                <button
                  type="button"
                  className="text-xs text-slate-400 hover:text-white flex items-center gap-1 font-medium cursor-pointer"
                  onClick={() => setShowAdvanced(!showAdvanced)}
                >
                  {showAdvanced ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  {showAdvanced ? 'Hide advanced details (URLs, attachments, headers)' : '+ Add URLs, attachments, or auth headers'}
                </button>

                {showAdvanced && (
                  <div className="flex flex-col gap-3 mt-3 pt-3 border-t border-slate-800">
                    <div className="input-group">
                      <label className="input-label">Links / URLs (one per line)</label>
                      <textarea
                        className="clean-input mono-font"
                        rows={2}
                        placeholder="http://example.com/login"
                        value={email.urls}
                        onChange={e => setField('urls', e.target.value)}
                      />
                    </div>
                    <div className="input-group">
                      <label className="input-label">Attachment Filenames (one per line)</label>
                      <textarea
                        className="clean-input mono-font"
                        rows={2}
                        placeholder="invoice.pdf.exe"
                        value={email.attachments}
                        onChange={e => setField('attachments', e.target.value)}
                      />
                    </div>
                    <div className="input-group">
                      <label className="input-label">Raw Auth Headers</label>
                      <textarea
                        className="clean-input mono-font text-xs"
                        rows={2}
                        placeholder="Authentication-Results: ..."
                        value={email.headers_raw}
                        onChange={e => setField('headers_raw', e.target.value)}
                      />
                    </div>
                  </div>
                )}
              </div>

              {error && <div className="p-3 bg-red-950/60 border border-red-800/60 rounded text-red-400 text-xs">{error}</div>}

              <button className="btn-scan" onClick={analyzeEmail} disabled={loading}>
                {loading ? <RefreshCw size={15} className="spin" /> : <Shield size={15} />}
                <span>{loading ? 'Scanning Email...' : 'Scan Email for Threats'}</span>
              </button>
            </div>

            {/* ── Right: Clean Verdict & AI Copilot ── */}
            <div className="card">
              {!result ? (
                <div className="flex flex-col items-center justify-center h-full text-center p-8 gap-3 text-slate-500">
                  <ShieldCheck size={44} strokeWidth={1.5} className="text-slate-700" />
                  <p className="text-sm font-medium text-slate-400">Ready to Analyze</p>
                  <p className="text-xs max-w-xs text-slate-500">
                    Select a preset on the left or enter an email, then click <em>Scan Email for Threats</em>.
                  </p>
                </div>
              ) : (
                <>
                  {/* Verdict Banner */}
                  <div className="verdict-hero-clean">
                    <div className="text-center">
                      <div className="text-3xl font-black font-mono" style={{ color: scoreColor(result.risk_score) }}>
                        {result.risk_score}
                      </div>
                      <div className="text-3xs text-slate-500 font-mono font-bold">/ 100 RISK</div>
                    </div>

                    <div className="flex flex-col gap-1.5 flex-1">
                      <span className={`score-badge ${result.risk_score >= 70 ? 'score-high' : result.risk_score >= 30 ? 'score-med' : 'score-low'}`}>
                        {result.classification.replace(/_/g, ' ')}
                      </span>
                      <span className="text-xs text-slate-300 font-medium">
                        Recommended Action: <strong className="text-white font-mono">{result.recommended_action.replace(/_/g, ' ')}</strong>
                      </span>
                    </div>

                    <a
                      href={`${API_BASE}/api/report?message_id=${encodeURIComponent(result.message_id)}&format=pdf`}
                      target="_blank"
                      rel="noreferrer"
                      className="preset-btn"
                    >
                      <Download size={12} /> PDF
                    </a>
                  </div>

                  {/* Key Evidence Reasons */}
                  <div className="flex flex-col gap-2">
                    <span className="card-title text-xs">Why was this flagged?</span>
                    <div className="reasons-list">
                      {!result.indicators?.length ? (
                        <div className="reason-card text-emerald-400 text-xs flex items-center gap-2">
                          <CheckCircle2 size={13} className="text-emerald-400" />
                          <span>No suspicious indicators found. Sender authentication and link reputations are safe.</span>
                        </div>
                      ) : (
                        result.indicators.map((ind, idx) => (
                          <div key={idx} className="reason-card">
                            <span className="reason-title">{ind.indicator.replace(/_/g, ' ')}</span>
                            <span className="reason-desc">{ind.evidence}</span>
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  {/* AI Copilot Chat */}
                  <div className="chat-container">
                    <div className="chat-header">
                      <span className="flex items-center gap-1.5 font-semibold text-slate-200">
                        <Shield size={13} className="text-cyan" /> Security Copilot
                      </span>
                      <span className="text-3xs text-slate-500 font-mono">DuckDB RAG</span>
                    </div>

                    <div className="chat-history">
                      {messages.map((m, idx) => (
                        <div key={idx} className={`bubble ${m.role === 'me' ? 'bubble-me' : 'bubble-ai'}`}>
                          {m.text}
                        </div>
                      ))}
                      {chatLoading && (
                        <div className="bubble bubble-ai text-xs text-slate-400 flex items-center gap-1.5">
                          <RefreshCw size={12} className="spin text-cyan" /> Analyzing context...
                        </div>
                      )}
                      <div ref={chatBottomRef} />
                    </div>

                    <div className="chat-chips">
                      <button className="chat-chip" onClick={() => sendChatMessage('Why is this domain suspicious?')}>
                        <Search size={11} /> Explain domain
                      </button>
                      <button className="chat-chip" onClick={() => sendChatMessage('What action should I take?')}>
                        <Shield size={11} /> Remediation advice
                      </button>
                      <button className="chat-chip" onClick={() => sendChatMessage('Are the email headers forged?')}>
                        <Inbox size={11} /> Check headers
                      </button>
                    </div>

                    <form onSubmit={(e) => { e.preventDefault(); sendChatMessage(); }} className="chat-input-bar">
                      <input
                        className="chat-input"
                        placeholder="Ask follow-up questions..."
                        value={chatInput}
                        onChange={e => setChatInput(e.target.value)}
                        disabled={chatLoading}
                      />
                      <button className="chat-send-btn" type="submit" disabled={chatLoading || !chatInput.trim()}>
                        <Send size={13} />
                      </button>
                    </form>
                  </div>
                </>
              )}
            </div>
          </div>
        )}

        {/* ── Tab: History ── */}
        {tab === 'history' && (
          <div className="card max-w-5xl mx-auto">
            <div className="card-title-row pb-2 border-b border-slate-800">
              <span className="card-title">Past Incident Scans</span>
              <button className="preset-btn" onClick={loadHistory}><RefreshCw size={12} /> Refresh</button>
            </div>

            <input
              className="clean-input text-xs"
              placeholder="Filter by sender or subject..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-mono text-3xs uppercase">
                    <th className="py-2.5 px-3">Sender</th>
                    <th className="py-2.5">Subject</th>
                    <th className="py-2.5">Score</th>
                    <th className="py-2.5">Verdict</th>
                    <th className="py-2.5">Date</th>
                    <th className="py-2.5">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800 font-mono">
                  {history
                    .filter(h => !search || (h.from_address + h.subject).toLowerCase().includes(search.toLowerCase()))
                    .map((h, i) => (
                      <tr key={i} className="hover:bg-slate-800/40">
                        <td className="py-3 px-3 text-cyan">{h.from_address}</td>
                        <td className="py-3 text-slate-300 font-sans max-w-xs truncate">{h.subject}</td>
                        <td className="py-3 font-bold">{h.risk_score}/100</td>
                        <td className="py-3">
                          <span className={`score-badge ${h.risk_score >= 70 ? 'score-high' : h.risk_score >= 30 ? 'score-med' : 'score-low'}`}>
                            {h.classification.replace(/_/g, ' ')}
                          </span>
                        </td>
                        <td className="py-3 text-slate-500">{h.analyzed_at?.slice(0, 10)}</td>
                        <td className="py-3">
                          <button className="preset-btn" onClick={() => inspectPastItem(h)}>View</button>
                        </td>
                      </tr>
                    ))}
                  {history.length === 0 && (
                    <tr>
                      <td colSpan={6} className="text-center py-8 text-slate-500">No past records found.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ── Tab: Analytics ── */}
        {tab === 'analytics' && (
          <div className="card max-w-5xl mx-auto">
            <div className="card-title-row pb-2 border-b border-slate-800">
              <span className="card-title">Threat Telemetry</span>
              <button className="preset-btn" onClick={loadStats}><RefreshCw size={12} /> Refresh</button>
            </div>

            {!stats ? (
              <div className="py-8 text-center text-slate-500">Loading analytics...</div>
            ) : (
              <div className="flex flex-col gap-6">
                <div className="grid grid-cols-4 gap-4">
                  <div className="p-4 bg-slate-900 rounded-lg border border-slate-800 text-center">
                    <div className="text-2xs text-slate-400 uppercase font-mono">Total Scanned</div>
                    <div className="text-2xl font-bold font-mono text-white mt-1">{stats.total_analyzed}</div>
                  </div>
                  <div className="p-4 bg-slate-900 rounded-lg border border-slate-800 text-center">
                    <div className="text-2xs text-slate-400 uppercase font-mono">Average Risk</div>
                    <div className="text-2xl font-bold font-mono text-amber-400 mt-1">{stats.average_risk_score} / 100</div>
                  </div>
                  <div className="p-4 bg-slate-900 rounded-lg border border-slate-800 text-center">
                    <div className="text-2xs text-slate-400 uppercase font-mono">High Risk</div>
                    <div className="text-2xl font-bold font-mono text-red-400 mt-1">{stats.classifications?.HIGH_RISK || 0}</div>
                  </div>
                  <div className="p-4 bg-slate-900 rounded-lg border border-slate-800 text-center">
                    <div className="text-2xs text-slate-400 uppercase font-mono">Clean Emails</div>
                    <div className="text-2xl font-bold font-mono text-emerald-400 mt-1">{stats.classifications?.LOW_RISK || 0}</div>
                  </div>
                </div>

                <div className="flex flex-col gap-3">
                  <span className="card-title text-xs">Top Threat Indicators</span>
                  <div className="flex flex-col gap-2">
                    {stats.top_indicators?.map((ind, i) => (
                      <div key={i} className="flex items-center justify-between p-2.5 bg-slate-900 rounded border border-slate-800 text-xs">
                        <span className="font-mono text-slate-200">{ind.indicator.replace(/_/g, ' ')}</span>
                        <span className="font-bold text-cyan">{ind.count} occurrences</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
