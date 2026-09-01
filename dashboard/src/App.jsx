import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import {
  Shield, Send, Upload, RefreshCw, Download,
  AlertTriangle, CheckCircle, ChevronRight, Minus,
  BarChart2, Clock, Inbox, X
} from 'lucide-react';

const API_BASE = 'http://localhost:8000';

// ─── Utility ─────────────────────────────────────────────────────────────────
const cls = (...classes) => classes.filter(Boolean).join(' ');

function RiskBadge({ score }) {
  if (score >= 70) return (
    <span className="risk-badge risk-high">HIGH RISK · {score}/100</span>
  );
  if (score >= 30) return (
    <span className="risk-badge risk-med">MEDIUM RISK · {score}/100</span>
  );
  return (
    <span className="risk-badge risk-low">LOW RISK · {score}/100</span>
  );
}

function ScoreRing({ score }) {
  const r = 36;
  const circ = 2 * Math.PI * r;
  const fill = ((100 - score) / 100) * circ;
  const color = score >= 70 ? '#ef4444' : score >= 30 ? '#f59e0b' : '#22c55e';
  return (
    <div className="score-ring-wrap">
      <svg width="96" height="96" viewBox="0 0 96 96">
        <circle cx="48" cy="48" r={r} fill="none" stroke="#1e293b" strokeWidth="8" />
        <circle
          cx="48" cy="48" r={r} fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={circ}
          strokeDashoffset={fill}
          strokeLinecap="round"
          transform="rotate(-90 48 48)"
          style={{ transition: 'stroke-dashoffset 0.8s ease' }}
        />
      </svg>
      <div className="score-ring-label" style={{ color }}>
        <span className="score-ring-num">{score}</span>
        <span className="score-ring-denom">/100</span>
      </div>
    </div>
  );
}

// ─── Field ───────────────────────────────────────────────────────────────────
function Field({ label, children }) {
  return (
    <div className="field">
      <label className="field-label">{label}</label>
      {children}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function App() {
  const [page, setPage] = useState('triage');
  const [email, setEmail] = useState({
    from_address: 'security@paypa1-login.com',
    from_display_name: 'PayPal Security Team',
    reply_to: 'phish-collector@paypa1-login.com',
    subject: 'Urgent: Your account will be suspended within 24 hours!',
    body_text: 'Dear customer, suspicious activities have been detected. Your PayPal account will be permanently suspended unless you verify immediately.\n\nEnter your password and credit card PIN at: http://paypa1-login.com/verify to restore access.',
    urls: 'http://paypa1-login.com/verify',
    attachments: 'urgent-invoice.pdf.exe',
  });

  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const [messages, setMessages] = useState([]);
  const [query, setQuery] = useState('');
  const [chatting, setChatting] = useState(false);
  const chatEndRef = useRef(null);

  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);

  useEffect(() => {
    if (page === 'history') loadHistory();
    if (page === 'intel') loadStats();
  }, [page]);

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const setField = (k, v) => setEmail(prev => ({ ...prev, [k]: v }));

  const analyze = async () => {
    setError('');
    setAnalyzing(true);
    try {
      const { data } = await axios.post(`${API_BASE}/api/analyze`, {
        from_address: email.from_address,
        from_display_name: email.from_display_name,
        reply_to: email.reply_to || null,
        subject: email.subject,
        body_text: email.body_text,
        urls: email.urls.split('\n').map(s => s.trim()).filter(Boolean),
        attachments: email.attachments.split('\n').map(s => s.trim()).filter(Boolean).map(f => ({ filename: f })),
      });
      setResult(data);
      setMessages([{ role: 'assistant', text: `Scan complete — ${data.classification.replace('_', ' ')} (${data.risk_score}/100). Ask me anything about the results.` }]);
    } catch (e) {
      setError(e.response?.data?.error || 'Could not reach backend at ' + API_BASE);
    } finally {
      setAnalyzing(false);
    }
  };

  const uploadEml = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    setError('');
    setAnalyzing(true);
    const fd = new FormData();
    fd.append('file', file);
    try {
      const { data } = await axios.post(`${API_BASE}/api/analyze-eml`, fd);
      setResult(data);
      if (data.extracted_email) {
        const ex = data.extracted_email;
        setEmail(prev => ({
          ...prev,
          from_address: ex.from_address || prev.from_address,
          from_display_name: ex.from_display_name || prev.from_display_name,
          reply_to: ex.reply_to || prev.reply_to,
          subject: ex.subject || prev.subject,
          body_text: ex.body_text || prev.body_text,
          urls: (ex.urls || []).join('\n'),
          attachments: (ex.attachments || []).join('\n'),
        }));
      }
      setMessages([{ role: 'assistant', text: `Parsed .eml — ${data.classification.replace('_', ' ')} (${data.risk_score}/100). What would you like to know?` }]);
    } catch (e) {
      setError(e.response?.data?.error || 'Failed to parse .eml file.');
    } finally {
      setAnalyzing(false);
    }
  };

  const sendChat = async (e) => {
    e.preventDefault();
    if (!query.trim() || !result) return;
    const q = query;
    setQuery('');
    setMessages(prev => [...prev, { role: 'user', text: q }]);
    setChatting(true);
    try {
      const { data } = await axios.post(`${API_BASE}/api/chat`, {
        message_id: result.message_id,
        user_message: q,
        analysis_result: result,
      });
      setMessages(prev => [...prev, { role: 'assistant', text: data.reply }]);
    } catch {
      setMessages(prev => [...prev, { role: 'assistant', text: 'Could not reach the assistant.' }]);
    } finally {
      setChatting(false);
    }
  };

  const loadHistory = async () => {
    try { const { data } = await axios.get(`${API_BASE}/api/history`); setHistory(data); } catch {}
  };
  const loadStats = async () => {
    try { const { data } = await axios.get(`${API_BASE}/api/dashboard`); setStats(data); } catch {}
  };

  return (
    <div className="app">
      {/* ── Sidebar ── */}
      <nav className="sidebar">
        <div className="sidebar-logo">
          <Shield size={20} className="text-blue-400" />
          <span>Phish Forensics</span>
        </div>

        <div className="sidebar-nav">
          <NavItem icon={<Inbox size={16} />} label="Triage" active={page === 'triage'} onClick={() => setPage('triage')} />
          <NavItem icon={<Clock size={16} />} label="Incident Log" active={page === 'history'} onClick={() => setPage('history')} />
          <NavItem icon={<BarChart2 size={16} />} label="Threat Intel" active={page === 'intel'} onClick={() => setPage('intel')} />
        </div>

        <div className="sidebar-footer">
          <span className="sidebar-badge">Thrive
          </span>
        </div>
      </nav>

      {/* ── Content ── */}
      <main className="content">
        {page === 'triage' && (
          <TriagePage
            email={email} setField={setField}
            analyzing={analyzing} result={result}
            error={error} onAnalyze={analyze} onUpload={uploadEml}
            messages={messages} query={query} setQuery={setQuery}
            chatting={chatting} onSendChat={sendChat}
            chatEndRef={chatEndRef}
          />
        )}
        {page === 'history' && <HistoryPage rows={history} onRefresh={loadHistory} />}
        {page === 'intel' && <IntelPage stats={stats} onRefresh={loadStats} />}
      </main>
    </div>
  );
}

function NavItem({ icon, label, active, onClick }) {
  return (
    <button className={cls('nav-item', active && 'nav-item-active')} onClick={onClick}>
      {icon}
      <span>{label}</span>
    </button>
  );
}

// ─── Triage Page ─────────────────────────────────────────────────────────────
function TriagePage({ email, setField, analyzing, result, error, onAnalyze, onUpload, messages, query, setQuery, chatting, onSendChat, chatEndRef }) {
  return (
    <div className="triage-layout">
      {/* Left: Input Panel */}
      <section className="panel input-panel">
        <div className="panel-header">
          <h2 className="panel-title">Email Input</h2>
          <label className="btn-ghost">
            <Upload size={14} />
            Upload .eml
            <input type="file" accept=".eml,.msg" onChange={onUpload} hidden />
          </label>
        </div>

        <div className="fields">
          <Field label="From address">
            <input className="inp mono" value={email.from_address} onChange={e => setField('from_address', e.target.value)} />
          </Field>

          <div className="row-2">
            <Field label="Display name">
              <input className="inp" value={email.from_display_name} onChange={e => setField('from_display_name', e.target.value)} />
            </Field>
            <Field label="Reply-To">
              <input className="inp mono" value={email.reply_to} onChange={e => setField('reply_to', e.target.value)} />
            </Field>
          </div>

          <Field label="Subject">
            <input className="inp" value={email.subject} onChange={e => setField('subject', e.target.value)} />
          </Field>

          <Field label="Body">
            <textarea className="inp mono text-xs" rows={5} value={email.body_text} onChange={e => setField('body_text', e.target.value)} />
          </Field>

          <div className="row-2">
            <Field label="URLs (one per line)">
              <textarea className="inp mono text-xs text-blue-400" rows={3} value={email.urls} onChange={e => setField('urls', e.target.value)} />
            </Field>
            <Field label="Attachments">
              <textarea className="inp mono text-xs text-red-400" rows={3} value={email.attachments} onChange={e => setField('attachments', e.target.value)} />
            </Field>
          </div>
        </div>

        {error && <p className="error-msg">{error}</p>}

        <button className="btn-primary" onClick={onAnalyze} disabled={analyzing}>
          {analyzing ? <RefreshCw size={15} className="spin" /> : <Shield size={15} />}
          {analyzing ? 'Analyzing…' : 'Run Forensic Analysis'}
        </button>
      </section>

      {/* Right: Results + Chat */}
      <section className="panel results-panel">
        {!result ? (
          <EmptyState />
        ) : (
          <>
            <VerdictCard result={result} />
            <IndicatorList indicators={result.indicators} />
            <ChatPanel
              messages={messages} query={query} setQuery={setQuery}
              chatting={chatting} onSend={onSendChat} chatEndRef={chatEndRef}
              disabled={!result}
              messageId={result?.message_id}
            />
          </>
        )}
      </section>
    </div>
  );
}

function EmptyState() {
  return (
    <div className="empty-state">
      <Shield size={40} strokeWidth={1.2} className="text-slate-700" />
      <p className="empty-title">No analysis yet</p>
      <p className="empty-sub">Fill in the email fields and click<br /><em>Run Forensic Analysis</em> to begin.</p>
    </div>
  );
}

function VerdictCard({ result }) {
  const actionColor = result.risk_score >= 70 ? 'text-red-400' : result.risk_score >= 30 ? 'text-amber-400' : 'text-emerald-400';
  return (
    <div className="verdict-card">
      <ScoreRing score={result.risk_score} />
      <div className="verdict-meta">
        <RiskBadge score={result.risk_score} />
        <p className={cls('verdict-action', actionColor)}>{result.recommended_action.replace(/_/g, ' ')}</p>
        <p className="verdict-id">ID: {result.message_id}</p>
      </div>
      <div className="verdict-ioc">
        <p className="ioc-label">Sender</p>
        <p className="ioc-val mono">{result.iocs?.sender_address}</p>
        {result.iocs?.urls?.length > 0 && <>
          <p className="ioc-label mt-2">Extracted URLs</p>
          {result.iocs.urls.map((u, i) => <p key={i} className="ioc-val mono text-blue-400">{u}</p>)}
        </>}
      </div>
      <a
        href={`${API_BASE}/api/report?message_id=${encodeURIComponent(result.message_id)}&format=pdf`}
        target="_blank"
        rel="noreferrer"
        className="btn-ghost ml-auto self-start"
      >
        <Download size={13} /> Export PDF
      </a>
    </div>
  );
}

function IndicatorList({ indicators }) {
  if (!indicators?.length) return (
    <div className="no-indicators">
      <CheckCircle size={14} className="text-emerald-400" />
      No threat indicators fired.
    </div>
  );
  return (
    <div className="indicator-section">
      <p className="section-label">Forensic Indicators <span className="count-badge">{indicators.length}</span></p>
      <div className="indicator-list">
        {indicators.map((ind, i) => (
          <div key={i} className="indicator-row">
            <div className="indicator-top">
              <span className="indicator-name">{ind.indicator.replace(/_/g, ' ')}</span>
              <div className="indicator-weights">
                <span className="weight-chip">w {ind.weight}</span>
                <span className="weight-chip">c {ind.confidence}</span>
              </div>
            </div>
            <p className="indicator-evidence">{ind.evidence}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function ChatPanel({ messages, query, setQuery, chatting, onSend, chatEndRef, disabled }) {
  return (
    <div className="chat-panel">
      <p className="section-label">Security Copilot</p>
      <div className="chat-messages">
        {messages.map((m, i) => (
          <div key={i} className={cls('chat-bubble', m.role === 'user' ? 'bubble-user' : 'bubble-bot')}>
            {m.text}
          </div>
        ))}
        {chatting && (
          <div className="bubble-bot chat-bubble typing">
            <span /><span /><span />
          </div>
        )}
        <div ref={chatEndRef} />
      </div>
      <form onSubmit={onSend} className="chat-form">
        <input
          className="inp chat-inp"
          placeholder={disabled ? 'Run analysis first…' : 'Ask about indicators, risks, or actions…'}
          value={query}
          onChange={e => setQuery(e.target.value)}
          disabled={disabled || chatting}
        />
        <button className="btn-icon" type="submit" disabled={disabled || chatting || !query.trim()}>
          <Send size={15} />
        </button>
      </form>
    </div>
  );
}

// ─── History Page ─────────────────────────────────────────────────────────────
function HistoryPage({ rows, onRefresh }) {
  return (
    <div className="page">
      <div className="page-header">
        <div>
          <h1 className="page-title">Incident Log</h1>
          <p className="page-sub">All emails analyzed and persisted in DuckDB</p>
        </div>
        <button className="btn-ghost" onClick={onRefresh}><RefreshCw size={14} /> Refresh</button>
      </div>

      {rows.length === 0 ? (
        <div className="empty-state"><Clock size={36} strokeWidth={1.2} className="text-slate-700" /><p className="empty-title">No incidents recorded</p><p className="empty-sub">Run a triage scan to populate this log.</p></div>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Message ID</th>
                <th>Sender</th>
                <th>Subject</th>
                <th>Score</th>
                <th>Verdict</th>
                <th>Action</th>
                <th>Analyzed</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i}>
                  <td className="mono text-blue-400">{r.message_id}</td>
                  <td className="mono">{r.from_address}</td>
                  <td>{r.subject}</td>
                  <td className="mono font-semibold">{r.risk_score}/100</td>
                  <td><RiskBadge score={r.risk_score} /></td>
                  <td className="mono text-red-400">{r.recommended_action}</td>
                  <td className="text-slate-500">{r.analyzed_at?.slice(0, 19)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Intel Page ───────────────────────────────────────────────────────────────
function IntelPage({ stats, onRefresh }) {
  if (!stats) return (
    <div className="page">
      <div className="page-header">
        <div><h1 className="page-title">Threat Intelligence</h1><p className="page-sub">Aggregate analytics across all incidents</p></div>
        <button className="btn-ghost" onClick={onRefresh}><RefreshCw size={14} /> Load</button>
      </div>
      <div className="empty-state"><BarChart2 size={36} strokeWidth={1.2} className="text-slate-700" /><p className="empty-title">Click Load to fetch stats</p></div>
    </div>
  );

  const high = stats.classifications?.HIGH_RISK || 0;
  const med  = stats.classifications?.MEDIUM_RISK || 0;
  const low  = stats.classifications?.LOW_RISK || 0;

  return (
    <div className="page">
      <div className="page-header">
        <div><h1 className="page-title">Threat Intelligence</h1><p className="page-sub">Aggregate analytics across all incidents</p></div>
        <button className="btn-ghost" onClick={onRefresh}><RefreshCw size={14} /> Refresh</button>
      </div>

      {/* KPI row */}
      <div className="kpi-row">
        <Kpi label="Total Analyzed" value={stats.total_analyzed} />
        <Kpi label="Avg Risk Score" value={`${stats.average_risk_score}`} sub="/100" accent="amber" />
        <Kpi label="High Risk" value={high} accent="red" />
        <Kpi label="Medium Risk" value={med} accent="amber" />
        <Kpi label="Low Risk" value={low} accent="green" />
      </div>

      <div className="intel-grid">
        {/* Top indicators */}
        <div className="panel">
          <p className="section-label">Top Fired Indicators</p>
          <div className="bar-list">
            {stats.top_indicators?.length ? stats.top_indicators.map((ind, i) => {
              const max = stats.top_indicators[0]?.count || 1;
              return (
                <div key={i} className="bar-row">
                  <span className="bar-name mono">{ind.indicator.replace(/_/g,' ')}</span>
                  <div className="bar-track">
                    <div className="bar-fill" style={{ width: `${(ind.count/max)*100}%` }} />
                  </div>
                  <span className="bar-count">{ind.count}</span>
                </div>
              );
            }) : <p className="empty-sub">No data yet.</p>}
          </div>
        </div>

        {/* Top senders */}
        <div className="panel">
          <p className="section-label">Frequent Hostile Senders</p>
          <div className="sender-list">
            {stats.top_senders?.length ? stats.top_senders.map((s, i) => (
              <div key={i} className="sender-row">
                <div>
                  <p className="sender-addr mono">{s.from_address}</p>
                  <p className="sender-meta">{s.count} incident{s.count > 1 ? 's' : ''}</p>
                </div>
                <span className="risk-num">{s.avg_risk}</span>
              </div>
            )) : <p className="empty-sub">No data yet.</p>}
          </div>
        </div>
      </div>
    </div>
  );
}

function Kpi({ label, value, sub, accent }) {
  const color = accent === 'red' ? 'text-red-400' : accent === 'amber' ? 'text-amber-400' : accent === 'green' ? 'text-emerald-400' : 'text-white';
  return (
    <div className="kpi-card">
      <p className="kpi-label">{label}</p>
      <p className={cls('kpi-value', color)}>{value}<span className="kpi-sub">{sub}</span></p>
    </div>
  );
}
