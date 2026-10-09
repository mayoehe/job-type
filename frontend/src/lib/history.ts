import type { ScanResultFull } from './api';

export interface HistoryEntry {
  id: string;
  at: string; // ISO timestamp
  kind: 'listing' | 'message';
  label: string; // employer / host / channel summary
  sub: string; // url host or channel or position
  score: number;
  band: string;
  level: 'low' | 'caution' | 'suspicious' | 'high' | 'critical';
  verdict: string;
  employer: string | null;
  result: ScanResultFull; // full evidence for re-inspection
}

const KEY = 'jobshield.history.v1';
const MAX = 50;

function load(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr : [];
  } catch {
    return [];
  }
}

function persist(entries: HistoryEntry[]) {
  try {
    localStorage.setItem(KEY, JSON.stringify(entries.slice(0, MAX)));
  } catch {
    /* storage full/blocked — history is best-effort */
  }
}

export function labelFor(result: ScanResultFull, kind: 'listing' | 'message', url: string, text: string): { label: string; sub: string } {
  const emp = result.safeApply?.verification?.claimedEmployer || null;
  if (kind === 'message') {
    const ch = result.safeApply?.channel || 'message';
    return { label: emp ? `${emp} — recruiter ${ch}` : `Recruiter ${ch} message`, sub: ch };
  }
  try {
    if (url.trim()) {
      const host = new URL(url.trim()).hostname.replace(/^www\./, '');
      return { label: emp ? `${emp} — ${host}` : text.trim() ? `${text.trim().slice(0, 42)}…` : host, sub: host };
    }
  } catch { /* fall through */ }
  return { label: emp ? `${emp} (text-only)` : `${text.trim().slice(0, 48)}…`, sub: 'text-only' };
}

export function saveScan(result: ScanResultFull, kind: 'listing' | 'message', url = '', text = ''): HistoryEntry {
  const { label, sub } = labelFor(result, kind, url, text);
  const entry: HistoryEntry = {
    id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
    at: new Date().toISOString(),
    kind, label, sub,
    score: result.score, band: result.band, level: result.level as HistoryEntry['level'],
    verdict: result.safeApply?.verdictLabel || result.band,
    employer: result.safeApply?.verification?.claimedEmployer || null,
    result,
  };
  const entries = [entry, ...load()];
  persist(entries);
  return entry;
}

export function listScans(): HistoryEntry[] {
  return load();
}

export function getScan(id: string): HistoryEntry | null {
  return load().find((e) => e.id === id) || null;
}

export function deleteScan(id: string) {
  persist(load().filter((e) => e.id !== id));
}

export function clearHistory() {
  try { localStorage.removeItem(KEY); } catch { /* noop */ }
}

export interface HistoryStats {
  total: number;
  highRisk: number; // high + critical
  critical: number;
  needVerify: number; // verdict Verify Employer or band Suspicious
  byLevel: Record<string, number>;
  last14: { day: string; count: number; worst: number }[];
}

export function historyStats(): HistoryStats {
  const entries = load();
  const byLevel: Record<string, number> = { low: 0, caution: 0, suspicious: 0, high: 0, critical: 0 };
  for (const e of entries) if (byLevel[e.level] !== undefined) byLevel[e.level]++;
  const days: HistoryStats['last14'] = [];
  for (let i = 13; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    const inDay = entries.filter((e) => e.at.slice(0, 10) === key);
    days.push({ day: key.slice(5), count: inDay.length, worst: inDay.reduce((m, e) => Math.max(m, e.score), 0) });
  }
  return {
    total: entries.length,
    highRisk: byLevel.high + byLevel.critical,
    critical: byLevel.critical,
    needVerify: entries.filter((e) => /verify|suspicious/i.test(e.verdict)).length,
    byLevel,
    last14: days,
  };
}

/** Top recurring signal titles across real history (for Reports). */
export function topSignals(limit = 8): { title: string; count: number; maxSev: string }[] {
  const map = new Map<string, { count: number; maxSev: string }>();
  const rank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  for (const e of load()) {
    for (const f of e.result.allFindings || []) {
      if (!['critical', 'high', 'medium'].includes(f.severity)) continue;
      const cur = map.get(f.title) || { count: 0, maxSev: 'medium' };
      cur.count++;
      if ((rank[f.severity] || 0) > (rank[cur.maxSev] || 0)) cur.maxSev = f.severity;
      map.set(f.title, cur);
    }
  }
  return [...map.entries()].map(([title, v]) => ({ title, ...v })).sort((a, b) => b.count - a.count).slice(0, limit);
}
