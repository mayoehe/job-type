import { useEffect, useState } from 'react';
import {
  LayoutDashboard, ScanLine, History as HistoryIcon, ShieldCheck,
  FileBarChart, Settings as SettingsIcon, CircleHelp, Shield,
  Sun as SunIcon, Moon as MoonIcon,
} from 'lucide-react';
import { Button } from './components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from './components/ui/card';
import { Tabs, TabsList, TabsTrigger } from './components/ui/tabs';
import { localScan } from './lib/engine';
import { SAMPLES, scanViaBackend, scanMessageBackend, localSafeApply, type ScanResultFull } from './lib/api';
import { saveScan } from './lib/history';
import { EmptyState } from './components/ui';
import { cn } from './lib/utils';
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
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={19} /> },
  { id: 'scan', label: 'Scan Job', icon: <ScanLine size={19} /> },
  { id: 'history', label: 'Scan History', icon: <HistoryIcon size={19} /> },
  { id: 'safeapply', label: 'Safe Apply', icon: <ShieldCheck size={19} /> },
  { id: 'reports', label: 'Reports', icon: <FileBarChart size={19} /> },
  { id: 'settings', label: 'Settings', icon: <SettingsIcon size={19} /> },
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

  const isDark = theme !== 'light';
  const toggleTheme = () => setTheme(isDark ? 'light' : 'dark');

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
    <div className="flex min-h-screen bg-background font-sans text-foreground">
      <aside className="sticky top-0 hidden h-screen w-[76px] shrink-0 flex-col items-center gap-1.5 border-r border-sidebar-border bg-sidebar py-4 md:flex" aria-label="Primary navigation">
        <div className="mb-3 flex flex-col items-center gap-1.5">
          <div className="grid size-11 place-items-center rounded-xl bg-sidebar-primary text-sidebar-primary-foreground shadow-xs">
            <Shield size={22} />
          </div>
          <span className="text-[10px] font-bold tracking-wide text-sidebar-foreground">Shield</span>
        </div>
        {NAV.map((n) => (
          <div key={n.id} className="group relative">
            <button
              onClick={() => go(n.id)}
              aria-current={view === n.id ? 'page' : undefined}
              aria-label={n.label}
              title={n.label}
              className={cn(
                'grid size-11 place-items-center rounded-xl border transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring',
                view === n.id
                  ? 'border-transparent bg-sidebar-primary text-sidebar-primary-foreground shadow-xs'
                  : 'border-transparent text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground'
              )}
            >
              {n.icon}
            </button>
            <span
              aria-hidden="true"
              className="pointer-events-none absolute left-[calc(100%+10px)] top-1/2 z-50 -translate-y-1/2 whitespace-nowrap rounded-md border bg-popover px-2.5 py-1 text-xs font-semibold text-popover-foreground opacity-0 shadow-md transition-opacity group-hover:opacity-100 group-focus-within:opacity-100"
            >
              {n.label}
            </span>
          </div>
        ))}
        <div className="mt-auto flex flex-col items-center gap-1.5 border-t border-sidebar-border pt-3">
          <div className="group relative">
            <button
              onClick={() => setHelpOpen(true)}
              aria-label="Help"
              title="Help"
              className="grid size-11 place-items-center rounded-xl border border-transparent text-sidebar-foreground transition-colors hover:bg-sidebar-accent hover:text-sidebar-accent-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-sidebar-ring"
            >
              <CircleHelp size={19} />
            </button>
            <span
              aria-hidden="true"
              className="pointer-events-none absolute left-[calc(100%+10px)] top-1/2 z-50 -translate-y-1/2 whitespace-nowrap rounded-md border bg-popover px-2.5 py-1 text-xs font-semibold text-popover-foreground opacity-0 shadow-md transition-opacity group-hover:opacity-100"
            >
              Help
            </span>
          </div>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 border-b bg-background/90 backdrop-blur">
          <div className="mx-auto flex w-full max-w-6xl items-center gap-3 px-4 py-3 sm:px-6">
            <span className="font-serif text-xl font-bold tracking-tight">{CRUMBS[view]}</span>
            <span className="flex-1" />
            <button
              onClick={toggleTheme}
              className="relative flex h-9 w-9 cursor-pointer items-center justify-center rounded-xl p-2 text-muted-foreground opacity-0 backdrop-blur-sm transition-colors animate-fade-in hover:bg-accent hover:text-accent-foreground"
              aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
              title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
            >
              <SunIcon
                strokeWidth={1.5}
                className={`ticon${isDark ? ' show' : ''}`}
                aria-hidden="true"
              />
              <MoonIcon
                strokeWidth={1.5}
                className={`ticon flip${!isDark ? ' show' : ''}`}
                aria-hidden="true"
              />
            </button>
            <Button size="sm" onClick={() => { go('scan'); setScanTab('listing'); }}>
              <ScanLine /> New scan
            </Button>
          </div>
        </header>

        <main className="mx-auto w-full max-w-6xl flex-1 px-4 pb-28 pt-6 sm:px-6 md:pb-16">
          {view === 'dashboard' && <Dashboard onScan={() => go('scan')} onOpen={openHistory} />}
          {view === 'scan' && (
            <div>
              <Tabs value={scanTab} onValueChange={(v) => setScanTab(v as 'listing' | 'message')}>
                <TabsList aria-label="Scan type" className="mb-4">
                  <TabsTrigger value="listing">Listing scan</TabsTrigger>
                  <TabsTrigger value="message">Recruiter message</TabsTrigger>
                </TabsList>
              </Tabs>
              {scanTab === 'listing' && (
                <>
                  <ScanView url={url} setUrl={setUrl} text={text} setText={setText} loading={loading} progress={progress}
                    onScan={onScan} onClear={() => { setUrl(''); setText(''); setResult(null); }}
                    onSample={(i) => { setUrl(SAMPLES[i].url); setText(SAMPLES[i].text); setResult(null); }} />
                  {result && <div className="mt-4"><Results result={result} source={source} text={text} /></div>}
                </>
              )}
              {scanTab === 'message' && (
                <>
                  <MessageForm channel={channel} setChannel={setChannel} msgText={msgText} setMsgText={setMsgText}
                    loading={msgLoading} onScan={onMsgScan} onClear={() => { setMsgText(''); setMsgResult(null); }}
                    onSample={(s) => { setChannel(s.channel); setMsgText(s.text); setMsgResult(null); }} />
                  {msgResult && <div className="mt-4"><MessageResult result={msgResult} /></div>}
                </>
              )}
            </div>
          )}
          {view === 'history' && <History onOpen={openHistory} refreshKey={historyKey} />}
          {view === 'safeapply' && (
            result?.safeApply
              ? <SafeApplyOnly result={result} text={text} />
              : <Card><EmptyState icon={<ShieldCheck size={34} />} title="No scan to advise on yet"
                body="Run a listing scan first — your personalised Safe Apply action plan, verification results and checklist will appear here."
                action={<Button onClick={() => go('scan')}><ScanLine /> Scan a job</Button>} /></Card>
          )}
          {view === 'reports' && <Reports onOpen={openHistory} />}
          {view === 'settings' && <Settings />}
          <footer className="mt-8 text-center font-serif text-sm text-muted-foreground">
            JobShield · behaviour-first heuristic detector · history stays on this device ·{' '}
            <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer" className="text-primary underline-offset-4 hover:underline">cybercrime.gov.in</a> · 1930
          </footer>
        </main>
      </div>

      <nav className="fixed inset-x-0 bottom-0 z-30 flex gap-0.5 border-t bg-background/95 px-1.5 pb-[calc(0.5rem+env(safe-area-inset-bottom))] pt-2 backdrop-blur md:hidden" aria-label="Primary navigation">
        {NAV.map((n) => (
          <button
            key={n.id}
            onClick={() => go(n.id)}
            aria-current={view === n.id ? 'page' : undefined}
            className={cn(
              'flex flex-1 flex-col items-center gap-0.5 rounded-lg px-1 py-1.5 text-[10px] font-bold',
              view === n.id ? 'text-primary' : 'text-muted-foreground'
            )}
          >
            {n.icon}<span>{n.label.split(' ')[0]}</span>
          </button>
        ))}
      </nav>

      {helpOpen && (
        <div className="fixed inset-0 z-40 grid place-items-center bg-black/60 p-4" onClick={() => setHelpOpen(false)}>
          <Card className="w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
            <CardHeader>
              <CardTitle className="font-serif">Using JobShield</CardTitle>
              <CardDescription>Four steps before you share anything with a recruiter.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <p><b className="text-foreground">1.</b> Scan a job from <b className="text-foreground">Scan Job</b> — paste the URL, the ad text, or both.</p>
              <p><b className="text-foreground">2.</b> Read the <b className="text-foreground">Safe Apply</b> verdict and work through the checklist before sharing anything.</p>
              <p><b className="text-foreground">3.</b> Never share OTPs, UPI PINs, passwords or fees — no genuine hiring needs them.</p>
              <p><b className="text-foreground">4.</b> Verify every vacancy on the employer's official site, reached by typing its address yourself.</p>
              <p>Suspected fraud: <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer" className="text-primary underline-offset-4 hover:underline">cybercrime.gov.in</a> or helpline <b className="text-foreground">1930</b>.</p>
              <div className="pt-2"><Button size="sm" onClick={() => setHelpOpen(false)}>Got it</Button></div>
            </CardContent>
          </Card>
        </div>
      )}
      {toast && (
        <div role="status" className="fixed bottom-20 left-1/2 z-50 -translate-x-1/2 rounded-full border bg-popover px-4 py-2 text-[13px] font-semibold text-popover-foreground shadow-lg md:bottom-6">
          {toast}
        </div>
      )}
    </div>
  );
}
