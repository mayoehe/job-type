import { useEffect, useState } from 'react';
import { Settings as SettingsIcon, Trash2, PlugZap, Eye, Info } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Label } from '../components/ui/label';
import { PageHeader } from '../components/ui';
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
      <PageHeader
        title={<span className="inline-flex items-center gap-2"><SettingsIcon size={26} className="text-primary" /> Settings</span>}
        description="Connection, data and display preferences. Everything stays on this device unless you point the app at a remote backend."
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><PlugZap size={16} className="text-primary" /> Backend connection</CardTitle>
            <CardDescription>Status: {backendOk === null ? 'checking…' : backendOk ? 'connected' : 'unreachable — offline engine in use'}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="apibase">API base URL (empty = same origin / dev proxy)</Label>
              <Input id="apibase" placeholder="e.g. http://localhost:8787" value={apiBase} onChange={(e) => setApiBase(e.target.value)} inputMode="url" autoComplete="off" />
            </div>
            <div className="flex items-center gap-3">
              <Button onClick={saveApi}>Save connection</Button>
              {saved && <span className="text-[13px] text-muted-foreground" role="status">Saved — new scans use this backend.</span>}
            </div>
            <p className="text-[13px] text-muted-foreground">Pasted listings are sent only to this backend for analysis — never to AI providers.</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Eye size={16} className="text-primary" /> Data &amp; display</CardTitle>
            <CardDescription>{histCount} scan(s) stored locally on this device.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Button variant="outline" size="sm" onClick={() => { clearHistory(); setHistCount(0); }}><Trash2 /> Delete all local history</Button>
            </div>
            <label className="flex cursor-pointer items-center gap-2 text-[13px] text-muted-foreground">
              <input type="checkbox" checked={reduceMotion} onChange={toggleMotion} className="size-[17px] accent-[var(--ring)]" />
              Reduce motion (also follows your OS setting automatically)
            </label>
            <p className="flex gap-1.5 text-[13px] text-muted-foreground"><Info size={14} className="mt-0.5 shrink-0" /> The backend keeps only anonymous aggregate counts. Full scan evidence lives in your browser history until you delete it.</p>
          </CardContent>
        </Card>
      </div>
      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="font-serif text-xl">About JobShield</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-[13px] text-muted-foreground">Behaviour-first heuristic detector (v1.1) + Safe Apply Assistant. Scores 0–100 are heuristics, not calibrated probabilities. Low risk never guarantees safety. Report fraud at <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer" className="text-primary underline-offset-4 hover:underline">cybercrime.gov.in</a> or call 1930.</p>
        </CardContent>
      </Card>
    </div>
  );
}

export function applyMotionPreference() {
  try {
    if (localStorage.getItem('jobshield.reduceMotion') === '1') document.body.classList.add('reduce-motion');
  } catch { /* noop */ }
}
