import { useEffect, useState } from 'react';
import {
  LayoutDashboard, ScanLine, History as HistoryIcon, ShieldCheck,
  FileBarChart, Settings as SettingsIcon, CircleHelp, Shield,
} from 'lucide-react';
import SquishSwitch from './components/SquishSwitch';
import { localScan } from './lib/engine';
import { SAMPLES, scanViaBackend, scanMessageBackend, localSafeApply, type ScanResultFull } from './lib/api';
import { saveScan } from './lib/history';
import { EmptyState } from './components/ui';
import Dashboard from './views/Dashboard';
import ScanView from './views/Scan';
import Results, { SafeApplyOnly } from './views/Results';
import { MessageForm, MessageResult } from './views/Message';
import History from './views/History';
import Reports from './views/Reports';
import Settings, { applyMotionPreference } from './views/Settings';

applyMotionPreference();

type View = 'dashboard' | 'scan' | 'history' | 'safeapply' | 'reports' | 'settings';
const NAV: { id: View; label: string; icon: React.ReactNode }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
  { id: 'scan', label: 'Scan Job', icon: <ScanLine size={18} /> },
  { id: 'history', label: 'Scan History', icon: <HistoryIcon size={18} /> },
  { id: 'safeapply', label: 'Safe Apply', icon: <ShieldCheck size={18} /> },
  { id: 'reports', label: 'Reports', icon: <FileBarChart size={18} /> },
  { id: 'settings', label: 'Settings', icon: <SettingsIcon size={18} /> },
];
const CRUMBS: Record<View, string> = {
  dashboard: 'Dashboard', scan: 'Scan Job', history: 'Scan History',
  safeapply: 'Safe Apply Assistant', reports: 'Reports', settings: 'Settings',
};

export default function App() {
  const [view, setView] = useState<View>('dashboard');
  const [scanTab, setScanTab] = useState<'listing' | 'message'>('listing');
  const [url, setUrl] = useState('');
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<ScanResultFull | null>(null);
  const [source, setSource] = useState<'backend' | 'local' | null>(null);
  const [channel, setChannel] = useState('whatsapp');
  const [msgText, setMsgText] = useState('');
  const [msgResult, setMsgResult] = useState<ScanResultFull | null>(null);
  const [msgLoading, setMsgLoading] = useState(false);
  const [historyKey, setHistoryKey] = useState(0);
  const [helpOpen, setHelpOpen] = useState(false);
  const [toast, setToast] = useState('');
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    try {
      return localStorage.getItem('jobshield.theme') === 'light' ? 'light' : 'dark';
    } catch { return 'dark'; }
  });

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('jobshield.theme', theme); } catch { /* noop */ }
  }, [theme]);

  function notify(msg: string) {
    setToast(msg);
    setTimeout(() => setToast(''), 2600);
  }

  async function onScan() {
    if ((url.trim() === '' && text.trim() === '') || loading) return;
    setLoading(true); setProgress(12);
    const tick = setInterval(() => setProgress((p) => Math.min(92, p + 9)), 280);
    try {
      const remote = await scanViaBackend(url.trim(), text);
      setProgress(96);
      let r: ScanResultFull;
      let src: 'backend' | 'local';
      if (remote) {
        if (!remote.safeApply) remote.safeApply = localSafeApply(remote, text);
        r = remote; src = 'backend';
      } else {
        const local = localScan(text, url.trim());
        r = { ...local, safeApply: localSafeApply(local, text) }; src = 'local';
        notify('Backend unreachable — offline estimate shown');
      }
      setResult(r); setSource(src);
      saveScan(r, 'listing', url, text);
      setHistoryKey((k) => k + 1);
    } finally {
      clearInterval(tick); setProgress(100);
      setTimeout(() => { setLoading(false); setProgress(0); }, 350);
    }
  }

  async function onMsgScan() {
    if (!msgText.trim() || msgLoading) return;
    setMsgLoading(true);
    try {
      const remote = await scanMessageBackend(msgText, channel);
      let r: ScanResultFull;
      if (remote) r = remote;
      else {
        const local = localScan(msgText, '');
        r = { ...local, safeApply: { ...localSafeApply(local, msgText), mode: 'message', recommendedResponse: 'Backend unreachable — verify the sender independently and never share money or credentials.' } };
        notify('Backend unreachable — offline estimate shown');
      }
      setMsgResult(r);
      saveScan(r, 'message', '', msgText);
      setHistoryKey((k) => k + 1);
    } finally { setMsgLoading(false); }
  }

  function openHistory(id: string) {
    try {
      const raw = localStorage.getItem('jobshield.history.v1');
      const entry = raw ? (JSON.parse(raw) as { id: string; kind: string; result: ScanResultFull }[]).find((e) => e.id === id) : null;
      if (!entry) return;
      if (entry.kind === 'message') { setMsgResult(entry.result); setScanTab('message'); }
      else { setResult(entry.result); setSource('backend'); setScanTab('listing'); }
      setView('scan');
      window.scrollTo(0, 0);
    } catch { /* noop */ }
  }

  const go = (v: View) => { setView(v); window.scrollTo(0, 0); };

  return (
    <div className="shell">
      <aside className="side" aria-label="Primary navigation">
        <div className="brand">
          <div className="brand-mark"><Shield size={20} /></div>
          <div><b>JobShield</b><small>scam intelligence</small></div>
        </div>
        {NAV.map((n) => (
          <button key={n.id} className={view === n.id ? 'nav-item active' : 'nav-item'} onClick={() => go(n.id)} aria-current={view === n.id ? 'page' : undefined} aria-label={n.label} title={n.label}>
            {n.icon}<span className="nav-label" aria-hidden="true">{n.label}</span>
          </button>
        ))}
        <div className="side-foot">
          <button className="nav-item" onClick={() => setHelpOpen(true)} aria-label="Help" title="Help"><CircleHelp size={18} /><span className="nav-label" aria-hidden="true">Help</span></button>
        </div>
      </aside>

      <div className="main">
        <div className="topbar">
          <span className="crumb">{CRUMBS[view]}</span>
          <span className="spacer" />
          <span className="theme-toggle" title={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}>
            <span className="theme-label" aria-hidden="true">{theme === 'light' ? 'Light' : 'Dark'}</span>
            <SquishSwitch
              checked={theme === 'light'}
              onChange={(next) => setTheme(next ? 'light' : 'dark')}
              ariaLabel={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
              width={64}
              height={32}
              radius={16}
            />
          </span>
          <button className="btn sm primary" onClick={() => { go('scan'); setScanTab('listing'); }}><ScanLine size={14} /> New scan</button>
        </div>
        <div className="content">
          {view === 'dashboard' && <Dashboard onScan={() => go('scan')} onOpen={openHistory} />}
          {view === 'scan' && (
            <div>
              <div className="pillrow" role="tablist" aria-label="Scan type" style={{ marginBottom: 14 }}>
                <button role="tab" aria-selected={scanTab === 'listing'} className={scanTab === 'listing' ? 'pill active' : 'pill'} onClick={() => setScanTab('listing')}>Listing scan</button>
                <button role="tab" aria-selected={scanTab === 'message'} className={scanTab === 'message' ? 'pill active' : 'pill'} onClick={() => setScanTab('message')}>Recruiter message</button>
              </div>
              {scanTab === 'listing' && (
                <>
                  <ScanView url={url} setUrl={setUrl} text={text} setText={setText} loading={loading} progress={progress}
                    onScan={onScan} onClear={() => { setUrl(''); setText(''); setResult(null); }}
                    onSample={(i) => { setUrl(SAMPLES[i].url); setText(SAMPLES[i].text); setResult(null); }} />
                  {result && <div style={{ marginTop: 16 }}><Results result={result} source={source} text={text} /></div>}
                </>
              )}
              {scanTab === 'message' && (
                <>
                  <MessageForm channel={channel} setChannel={setChannel} msgText={msgText} setMsgText={setMsgText}
                    loading={msgLoading} onScan={onMsgScan} onClear={() => { setMsgText(''); setMsgResult(null); }}
                    onSample={(s) => { setChannel(s.channel); setMsgText(s.text); setMsgResult(null); }} />
                  {msgResult && <div style={{ marginTop: 16 }}><MessageResult result={msgResult} /></div>}
                </>
              )}
            </div>
          )}
          {view === 'history' && <History onOpen={openHistory} refreshKey={historyKey} />}
          {view === 'safeapply' && (
            result?.safeApply
              ? <SafeApplyOnly result={result} text={text} />
              : <EmptyState icon={<ShieldCheck size={34} />} title="No scan to advise on yet"
                body="Run a listing scan first — your personalised Safe Apply action plan, verification results and checklist will appear here."
                action={<button className="btn primary" onClick={() => go('scan')}><ScanLine size={16} /> Scan a job</button>} />
          )}
          {view === 'reports' && <Reports onOpen={openHistory} />}
          {view === 'settings' && <Settings />}
          <div className="foot">JobShield 1.1 · behaviour-first heuristic detector · history stays on this device · <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">cybercrime.gov.in</a> · 1930</div>
        </div>
      </div>

      <nav className="mobnav" aria-label="Primary navigation">
        {NAV.map((n) => (
          <button key={n.id} className={view === n.id ? 'active' : ''} onClick={() => go(n.id)} aria-current={view === n.id ? 'page' : undefined}>
            {n.icon}<span>{n.label.split(' ')[0]}</span>
          </button>
        ))}
      </nav>

      {helpOpen && (
        <div className="dialog-back" onClick={() => setHelpOpen(false)}>
          <div className="dialog" role="dialog" aria-modal="true" aria-label="Help" onClick={(e) => e.stopPropagation()}>
            <h2>Using JobShield</h2>
            <div className="note" style={{ marginTop: 10 }}>
              <p><b>1.</b> Scan a job from <b>Scan Job</b> — paste the URL, the ad text, or both.</p>
              <p><b>2.</b> Read the <b>Safe Apply</b> verdict and work through the checklist before sharing anything.</p>
              <p><b>3.</b> Never share OTPs, UPI PINs, passwords or fees — no genuine hiring needs them.</p>
              <p><b>4.</b> Verify every vacancy on the employer's official site, reached by typing its address yourself.</p>
              <p>Suspected fraud: <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">cybercrime.gov.in</a> or helpline <b>1930</b>.</p>
            </div>
            <div className="row"><button className="btn primary sm" onClick={() => setHelpOpen(false)}>Got it</button></div>
          </div>
        </div>
      )}
      {toast && <div className="toast" role="status">{toast}</div>}
    </div>
  );
}
