import { MessageSquareText, Eraser, Send } from 'lucide-react';
import { Card, ScoreRing, RiskBadge, FindingSeverity, EmptyState } from '../components/ui';
import type { ScanResultFull } from '../lib/api';

const CHANNELS = [
  { id: 'whatsapp', label: 'WhatsApp' },
  { id: 'email', label: 'Email' },
  { id: 'offer', label: 'Offer letter' },
  { id: 'interview', label: 'Interview invite' },
  { id: 'payment', label: 'Payment request' },
];
const MSG_SAMPLES = [
  { name: 'Scam WhatsApp (Hinglish)', channel: 'whatsapp', text: 'Dear Candidate, apki selection ho gayi hai! ₹85000 salary, no interview. ₹2499 refundable fee UPI par bhejo aur Aadhaar + OTP WhatsApp par share karo. Offer sirf 2 hours ke liye!' },
  { name: 'Scam fee email', channel: 'email', text: 'Congratulations! You are selected for the back-office role. To release your appointment letter, pay Rs 1500 verification fee via the QR code attached and reply with your PAN card and bank details. HR Team (Gmail).' },
  { name: 'Genuine interview invite', channel: 'email', text: 'Hello, thank you for your application for Senior React Developer. We would like to invite you for a technical interview on Monday 11am at our Bengaluru office (address below) or over Google Meet. Please confirm your availability. No fees are involved at any stage. Regards, Priya Sharma, careers@company.com.' },
];

export function MessageForm({ channel, setChannel, msgText, setMsgText, loading, onScan, onClear, onSample }:
  { channel: string; setChannel: (v: string) => void; msgText: string; setMsgText: (v: string) => void; loading: boolean; onScan: () => void; onClear: () => void; onSample: (s: { channel: string; text: string }) => void }) {
  return (
    <Card>
      <h2><MessageSquareText size={17} style={{ verticalAlign: -3 }} /> Recruiter message scanner</h2>
      <p className="sub">Same detection engine, text-only. Nothing is sent to AI services — analysis stays local.</p>
      <label className="lbl">Message type</label>
      <div className="pillrow" role="radiogroup" aria-label="Message type">
        {CHANNELS.map((c) => (
          <button key={c.id} role="radio" aria-checked={channel === c.id} className={channel === c.id ? 'pill active' : 'pill'} onClick={() => setChannel(c.id)}>{c.label}</button>
        ))}
      </div>
      <label className="lbl" htmlFor="msg">Message text</label>
      <textarea id="msg" className="textarea" placeholder="Paste the WhatsApp message, email, offer letter, invite or payment request…" value={msgText} onChange={(e) => setMsgText(e.target.value)} />
      <div className="row">
        <button className="btn primary" disabled={!msgText.trim() || loading} onClick={onScan} aria-busy={loading}>
          <Send size={16} /> {loading ? 'Analysing…' : 'Analyse message'}
        </button>
        <button className="btn ghost" onClick={onClear}><Eraser size={16} /> Clear</button>
      </div>
      <label className="lbl">Samples</label>
      <div className="pillrow">
        {MSG_SAMPLES.map((s, i) => <button key={i} className="pill" onClick={() => onSample(s)}>{s.name}</button>)}
      </div>
    </Card>
  );
}

export function MessageResult({ result }: { result: ScanResultFull }) {
  const sa = result.safeApply;
  return (
    <Card style={{ borderColor: result.color }}>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <h2>Message analysis</h2>
        <span className="tag">{sa?.channel || 'message'}</span>
        <RiskBadge level={result.level} band={result.band} />
      </div>
      <div className="score-hero" style={{ marginTop: 12 }}>
        <ScoreRing score={result.score} color={result.color} />
        <p style={{ flex: 1, minWidth: 220 }}>{sa?.whyUnsafe}</p>
      </div>
      {result.overrides.map((o) => (
        <div className="alert crit" key={o.id}><b>⚠ {o.title}</b><div className="note">{o.detail}</div></div>
      ))}
      {sa?.recommendedResponse && (
        <>
          <h3 style={{ marginTop: 12 }}>Recommended response</h3>
          <div className="finding" style={{ borderLeftColor: '#a78bfa' }}><div>{sa.recommendedResponse}</div></div>
        </>
      )}
      <h3 style={{ marginTop: 12 }}>Next steps</h3>
      <ol className="steps">{(sa?.steps || []).map((s, i) => <li key={i} className={s.priority === 'urgent' ? 'urgent' : ''}><b>{s.title}</b><div className="note">{s.detail}</div></li>)}</ol>
      <h3 style={{ marginTop: 12 }}>Evidence</h3>
      {result.allFindings.filter((f) => f.severity !== 'info').length === 0 && (
        <EmptyState title="No significant flags" body="Stay cautious and verify the sender through official channels." />
      )}
      {result.allFindings.filter((f) => f.severity !== 'info').map((f) => (
        <div className="finding" key={f.id} style={{ borderLeftColor: f.severity === 'critical' ? '#ef4444' : f.severity === 'high' ? '#f97316' : '#f59e0b' }}>
          <FindingSeverity severity={f.severity} /> <b>{f.title}</b>
          <div className="ev">{f.evidence}</div>
        </div>
      ))}
    </Card>
  );
}
