import { ScanLine, Eraser, FlaskConical } from 'lucide-react';
import { Card } from '../components/ui';
import { SAMPLES } from '../lib/api';

export default function ScanView({ url, setUrl, text, setText, loading, progress, onScan, onClear, onSample }:
  { url: string; setUrl: (v: string) => void; text: string; setText: (v: string) => void; loading: boolean; progress: number; onScan: () => void; onClear: () => void; onSample: (i: number) => void }) {
  const canScan = url.trim() !== '' || text.trim() !== '';
  return (
    <div className="grid two">
      <Card>
        <h2>Scan a job listing</h2>
        <p className="sub">Paste a posting URL, the job text, or both. Behavioural evidence outweighs technical polish. Never paste your own Aadhaar, PAN, bank details or OTPs — evidence is redacted by default.</p>
        <label className="lbl" htmlFor="url">Posting URL</label>
        <input id="url" className="input" placeholder="https://example.com/careers/apply…" value={url} onChange={(e) => setUrl(e.target.value)} inputMode="url" autoComplete="off" />
        <label className="lbl" htmlFor="txt">Job description / recruiter message</label>
        <textarea id="txt" className="textarea" placeholder="Paste the full job ad, WhatsApp message, or email…" value={text} onChange={(e) => setText(e.target.value)} />
        <div className="row">
          <button className="btn primary" disabled={!canScan || loading} onClick={onScan} aria-busy={loading}>
            <ScanLine size={16} /> {loading ? 'Analysing…' : 'Scan for phishing risk'}
          </button>
          <button className="btn ghost" onClick={onClear}><Eraser size={16} /> Clear</button>
        </div>
        {loading && (
          <div role="status" aria-live="polite">
            <div className="progress"><div style={{ width: progress + '%' }} /></div>
            <p className="note">Running linguistic, behavioural, domain and verification checks…</p>
          </div>
        )}
        <div>
          <label className="lbl"><FlaskConical size={13} style={{ verticalAlign: -2 }} /> Sample cases</label>
          <div className="pillrow">
            {SAMPLES.map((s, i) => <button key={i} className="pill" onClick={() => onSample(i)} title={s.note}>{s.name}</button>)}
          </div>
        </div>
      </Card>
      <Card>
        <h2>How scoring works</h2>
        <p className="sub">Transparent weights · behaviour-first floors</p>
        <table className="rep" style={{ marginTop: 10 }}>
          <thead><tr><th>Category</th><th>Max</th></tr></thead>
          <tbody>
            <tr><td>Linguistic &amp; semantic red flags</td><td>35</td></tr>
            <tr><td>Recruitment behaviour &amp; structure</td><td>30</td></tr>
            <tr><td>URL &amp; domain anomalies</td><td>15</td></tr>
            <tr><td>Technical security signals</td><td>10</td></tr>
            <tr><td>Employer &amp; evidence verification</td><td>10</td></tr>
          </tbody>
        </table>
        <details className="exp">
          <summary>Formula, overrides &amp; risk floors</summary>
          <div className="body note">
            <p><b>total</b> = linguistic + behavioural + domain + technical + employer; <b>final</b> = max(total, highest floor).</p>
            <ul style={{ paddingLeft: 18, margin: '6px 0' }}>
              <li>OTP / UPI PIN / banking password → floor <b>80 (Critical)</b></li>
              <li>Payment demanded for job / offer → floor <b>65 (High)</b></li>
              <li>≥2 credential-harvesting indicators → floor <b>60 (High)</b></li>
              <li>Valid HTTPS, aged domain, clean reputation <b>never subtract</b> behavioural risk.</li>
            </ul>
            <p>Bands: 0–19 Low · 20–39 Caution · 40–59 Suspicious · 60–79 High · 80–100 Critical.</p>
          </div>
        </details>
        <p className="note">Backend adds SSRF-guarded static page inspection (no JS execution). Offline fallback uses the built-in local engine.</p>
      </Card>
    </div>
  );
}
