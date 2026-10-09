import { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Trash2, PlugZap, Eye, Info } from 'lucide-react';
import { Card, EmptyState } from '../components/ui';
import { listScans, clearHistory } from '../lib/history';

export default function Settings() {
  const [apiBase, setApiBase] = useState('');
  const [saved, setSaved] = useState(false);
  const [backendOk, setBackendOk] = useState<boolean | null>(null);
  const [reduceMotion, setReduceMotion] = useState(false);
  const [histCount, setHistCount] = useState(0);

  useEffect(() => {
    try {
      setApiBase(localStorage.getItem('jobshield.apiBase') || '');
      setReduceMotion(document.body.classList.contains('reduce-motion'));
    } catch { /* noop */ }
    setHistCount(listScans().length);
    const base = currentBase();
    fetch(base + '/api/health').then((r) => setBackendOk(r.ok)).catch(() => setBackendOk(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function currentBase(): string {
    try {
      const ov = localStorage.getItem('jobshield.apiBase');
      if (ov !== null && ov !== '') return ov.replace(/\/$/, '');
    } catch { /* noop */ }
    return '';
  }

  function saveApi() {
    try { localStorage.setItem('jobshield.apiBase', apiBase.trim()); } catch { /* noop */ }
    setSaved(true);
    setTimeout(() => setSaved(false), 2200);
    fetch((apiBase.trim() || '') + '/api/health').then((r) => setBackendOk(r.ok)).catch(() => setBackendOk(false));
  }

  function toggleMotion() {
    const next = !reduceMotion;
    setReduceMotion(next);
    document.body.classList.toggle('reduce-motion', next);
    try { localStorage.setItem('jobshield.reduceMotion', next ? '1' : '0'); } catch { /* noop */ }
  }

  return (
    <div>
      <div className="hero">
        <div>
          <h1><SettingsIcon size={28} style={{ verticalAlign: -5 }} /> Settings</h1>
          <p>Connection, data and display preferences. Everything stays on this device unless you point the app at a remote backend.</p>
        </div>
      </div>
      <div className="grid two">
        <Card>
          <h2><PlugZap size={16} style={{ verticalAlign: -3 }} /> Backend connection</h2>
          <p className="sub">Status: {backendOk === null ? 'checking…' : backendOk ? 'connected' : 'unreachable — offline engine in use'}</p>
          <label className="lbl" htmlFor="apibase">API base URL (empty = same origin / dev proxy)</label>
          <input id="apibase" className="input" placeholder="e.g. http://localhost:8787" value={apiBase} onChange={(e) => setApiBase(e.target.value)} inputMode="url" autoComplete="off" />
          <div className="row">
            <button className="btn primary" onClick={saveApi}>Save connection</button>
            {saved && <span className="note" role="status">Saved — new scans use this backend.</span>}
          </div>
          <p className="note">Pasted listings are sent only to this backend for analysis — never to AI providers.</p>
        </Card>
        <Card>
          <h2><Eye size={16} style={{ verticalAlign: -3 }} /> Data &amp; display</h2>
          <p className="sub">{histCount} scan(s) stored locally on this device.</p>
          <div className="row">
            <button className="btn ghost sm" onClick={() => { clearHistory(); setHistCount(0); }}><Trash2 size={14} /> Delete all local history</button>
          </div>
          <label className="note" style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 12, cursor: 'pointer' }}>
            <input type="checkbox" checked={reduceMotion} onChange={toggleMotion} style={{ width: 17, height: 17, accentColor: '#8b5cf6' }} />
            Reduce motion (also follows your OS setting automatically)
          </label>
          <p className="note" style={{ marginTop: 12, display: 'flex', gap: 6 }}><Info size={14} style={{ flexShrink: 0, marginTop: 2 }} /> The backend keeps only anonymous aggregate counts. Full scan evidence lives in your browser history until you delete it.</p>
        </Card>
      </div>
      <Card style={{ marginTop: 16 }}>
        <h2>About JobShield</h2>
        <p className="note">Behaviour-first heuristic detector (v1.1) + Safe Apply Assistant. Scores 0–100 are heuristics, not calibrated probabilities. Low risk never guarantees safety. Report fraud at <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">cybercrime.gov.in</a> or call 1930.</p>
      </Card>
    </div>
  );
}

export function applyMotionPreference() {
  try {
    if (localStorage.getItem('jobshield.reduceMotion') === '1') document.body.classList.add('reduce-motion');
  } catch { /* noop */ }
}
