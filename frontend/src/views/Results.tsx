import { useState } from 'react';
import { BellRing, Building2, Fingerprint, ListChecks, ChartColumn, Globe } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { Alert, AlertTitle, AlertDescription } from '../components/ui/alert';
import { Progress } from '../components/ui/progress';
import { RiskBadge, VerdictBadge, ScoreRing, StateDot, VerifyChip, FindingSeverity, EmptyState, FieldNote, riskVar } from '../components/ui';
import type { ScanResultFull, SafeApply } from '../lib/api';

const CATS = [
  { key: 'linguistic', label: 'Linguistic', max: 35, color: 'var(--chart-1)' },
  { key: 'behavioural', label: 'Behavioural', max: 30, color: 'var(--chart-2)' },
  { key: 'domain', label: 'URL & domain', max: 15, color: 'var(--chart-3)' },
  { key: 'technical', label: 'Technical', max: 10, color: 'var(--chart-4)' },
  { key: 'employer', label: 'Employer', max: 10, color: 'var(--chart-5)' },
];

export default function Results({ result, source, text }: { result: ScanResultFull; source: string | null; text: string }) {
  const sa = result.safeApply;
  const levelColor = riskVar[result.level] || result.color;
  const [reviewed, setReviewed] = useState<Set<string>>(new Set());
  const [selHi, setSelHi] = useState<number | null>(null);
  const [showShared, setShowShared] = useState(false);
  const toggle = (id: string) => setReviewed((p) => { const n = new Set(p); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  return (
    <div className="space-y-4">
      <Card style={{ borderColor: `color-mix(in srgb, ${levelColor} 55%, transparent)` }}>
        <CardHeader>
          <div className="flex flex-wrap items-center gap-2">
            <CardTitle className="font-serif text-xl">Risk assessment</CardTitle>
            <RiskBadge level={result.level} band={result.band} />
            {source && <Badge variant="secondary">{source === 'backend' ? 'backend evidence' : 'local estimate'}</Badge>}
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap items-center gap-5">
            <ScoreRing score={result.score} color={levelColor} />
            <div className="min-w-[240px] flex-1">
              <div className="mb-3 flex h-3 overflow-hidden rounded-full border bg-muted">
                {CATS.map((c) => {
                  const v = result.categories[c.key];
                  return <div key={c.key} title={`${c.label}: ${v.score}/${v.max}`} style={{ width: `${(v.score / 100) * 100}%`, background: c.color }} />;
                })}
              </div>
              {CATS.map((c) => {
                const v = result.categories[c.key];
                return (
                  <div key={c.key} className="my-1.5 grid grid-cols-[130px_1fr_56px] items-center gap-2.5 text-xs text-muted-foreground">
                    <span>{c.label} ({c.max})</span>
                    <div className="h-2 overflow-hidden rounded-full border bg-muted">
                      <div className="h-full rounded-full" style={{ width: `${Math.min(100, (v.score / v.max) * 100)}%`, background: c.color }} />
                    </div>
                    <span className="text-right font-bold tabular-nums text-foreground">{v.score}</span>
                  </div>
                );
              })}
              <FieldNote className="mt-2">
                Raw total {result.rawTotal}{result.floor > result.rawTotal ? ` · raised to floor ${result.floor} by severity override` : ''} · {result.counts.confirmed} confirmed · {result.counts.suspicious} suspicious · {result.counts.info} context/unknown.
              </FieldNote>
            </div>
          </div>
          <div className="mt-1 space-y-2">
            {result.overrides.map((o) => (
              <Alert key={o.id} variant="destructive">
                <BellRing size={15} />
                <AlertTitle>{o.title}</AlertTitle>
                <AlertDescription>{o.detail} (risk floor {o.floor})</AlertDescription>
              </Alert>
            ))}
          </div>
        </CardContent>
      </Card>

      {sa && <SafeApplyView sa={sa} text={text} reviewed={reviewed} toggle={toggle} selHi={selHi} setSelHi={setSelHi} showShared={showShared} setShowShared={setShowShared} />}

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 font-serif text-xl"><ChartColumn size={17} className="text-primary" /> All findings</CardTitle>
        </CardHeader>
        <CardContent>
          {result.allFindings.length === 0 && <EmptyState title="No findings" body="Sparse input produced no findings. Absence of flags is not proof of safety." />}
          <div className="space-y-2">
            {result.allFindings.map((f) => (
              <details key={f.id} className="overflow-hidden rounded-xl border bg-background shadow-xs">
                <summary className="flex cursor-pointer flex-wrap items-center gap-2 px-4 py-3 text-[13.5px] font-semibold">
                  <FindingSeverity severity={f.severity} /> {f.title}{' '}
                  <span className="text-xs font-normal text-muted-foreground">+{f.points} · {f.category}</span>
                </summary>
                <div className="px-4 pb-3">
                  <div className="whitespace-pre-wrap rounded-md border border-dashed bg-card px-3 py-2 font-mono text-xs text-muted-foreground">{f.evidence}</div>
                </div>
              </details>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 font-serif text-xl"><Globe size={17} className="text-primary" /> URL intelligence</CardTitle>
        </CardHeader>
        <CardContent>
          {result.intelligence ? <Intel intel={result.intelligence as Record<string, unknown>} /> : (
            <KV
              rows={[
                ['Mode', 'Local offline analysis (no live fetch)'],
                ['Host', result.meta.urlHost || '— (no URL provided; text-only analysis)'],
                ['Registrable domain', result.meta.registrableDomain || '—'],
                ['HTTPS / cert / age', 'Unknown in local mode — not treated as safe.'],
              ]}
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}

export function SafeApplyOnly({ result, text }: { result: ScanResultFull; text: string }) {
  const [reviewed, setReviewed] = useState<Set<string>>(new Set());
  const [selHi, setSelHi] = useState<number | null>(null);
  const [showShared, setShowShared] = useState(false);
  const toggle = (id: string) => setReviewed((p) => { const n = new Set(p); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  if (!result.safeApply) return null;
  return <SafeApplyView sa={result.safeApply} text={text} reviewed={reviewed} toggle={toggle} selHi={selHi} setSelHi={setSelHi} showShared={showShared} setShowShared={setShowShared} />;
}

function SafeApplyView({ sa, text, reviewed, toggle, selHi, setSelHi, showShared, setShowShared }:
  { sa: SafeApply; text: string; reviewed: Set<string>; toggle: (id: string) => void; selHi: number | null; setSelHi: (i: number | null) => void; showShared: boolean; setShowShared: (b: boolean) => void }) {
  const vColor = sa.verdict === 'avoid' ? 'var(--risk-critical)' : sa.verdict === 'verify' ? 'var(--risk-caution)' : 'var(--risk-low)';
  const cl = sa.checklist;
  const done = cl.items.filter((i) => i.state === 'passed').length + [...reviewed].filter((id) => cl.items.some((i) => i.id === id && i.state !== 'passed')).length;
  return (
    <div className="space-y-4">
      <Card style={{ borderColor: `color-mix(in srgb, ${vColor} 55%, transparent)` }}>
        <CardHeader>
          <div className="flex flex-wrap items-center gap-2">
            <CardTitle className="font-serif text-xl">Safe Apply</CardTitle>
            <VerdictBadge verdict={sa.verdict} label={sa.verdictLabel} />
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm">{sa.whyUnsafe}</p>
          <h3 className="text-sm font-semibold">Your action plan</h3>
          <ol className="list-decimal space-y-2.5 pl-5 text-sm">
            {sa.steps.map((s, i) => (
              <li key={i} className={s.priority === 'urgent' ? 'rounded-r-lg border-l-[3px] border-destructive pl-2.5' : ''}>
                <b>{s.title}</b>
                <FieldNote>{s.detail}</FieldNote>
              </li>
            ))}
          </ol>
          <Button variant="outline" size="sm" onClick={() => setShowShared(!showShared)} aria-expanded={showShared}>
            {showShared ? 'Hide' : 'Show'}: I already shared information / paid money
          </Button>
          {showShared && (
            <div className="grid gap-2 sm:grid-cols-2">
              <div className="rounded-xl border bg-background px-4 py-3 shadow-xs" style={{ borderLeft: '3px solid var(--risk-critical)' }}>
                <b className="text-sm">Money / credentials exposed</b>
                <FieldNote>{sa.alreadyShared.money}</FieldNote>
              </div>
              <div className="rounded-xl border bg-background px-4 py-3 shadow-xs" style={{ borderLeft: '3px solid var(--risk-caution)' }}>
                <b className="text-sm">Identity documents shared</b>
                <FieldNote>{sa.alreadyShared.identity}</FieldNote>
              </div>
              <div className="rounded-xl border bg-background px-4 py-3 shadow-xs sm:col-span-2" style={{ borderLeft: '3px solid var(--primary)' }}>
                <b className="text-sm">Report fraud</b>
                <FieldNote>{sa.alreadyShared.report}</FieldNote>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex flex-wrap items-center gap-2">
                <CardTitle className="flex items-center gap-2 text-base"><Building2 size={16} className="text-primary" /> Employer verification</CardTitle>
                {sa.verification && <VerifyChip status={sa.verification.overall} />}
              </div>
            </CardHeader>
            <CardContent>
              {!sa.verification && <FieldNote>Verification unavailable offline — locate the official site yourself.</FieldNote>}
              {sa.verification && (
                <>
                  <KV
                    rows={[
                      ['Claimed employer', sa.verification.claimedEmployer || 'Could not identify'],
                      ['Position', sa.verification.claimedPosition || 'Could not identify'],
                      ['Official domain', sa.verification.officialDomain || 'Could Not Verify'],
                      ['Listing domain', sa.verification.listingDomain || '— (no URL)'],
                    ]}
                  />
                  <div className="mt-2 space-y-2">
                    {sa.verification.checks.map((c) => (
                      <div key={c.id} className="rounded-xl border bg-background px-4 py-3 shadow-xs" style={{ borderLeft: `3px solid ${c.status === 'verified' ? 'var(--risk-low)' : c.status === 'mismatch' ? 'var(--risk-critical)' : 'var(--muted-foreground)'}` }}>
                        <div className="flex flex-wrap items-center gap-2">
                          <b className="text-[13.5px]">{c.label}</b> <VerifyChip status={c.status} />
                        </div>
                        <FieldNote className="mt-1">{c.evidence}</FieldNote>
                        <small className="text-xs text-muted-foreground">Source: {c.source}</small>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><Fingerprint size={16} className="text-primary" /> Information protection</CardTitle>
            </CardHeader>
            <CardContent>
              {sa.protection.length === 0 && <FieldNote>Offline estimate — protection detail needs the backend.</FieldNote>}
              <div className="space-y-2">
                {sa.protection.map((g) => (
                  <div key={g.id} className="rounded-xl border bg-background px-4 py-3 shadow-xs" style={{ borderLeft: `3px solid ${g.status === 'requested' ? 'var(--risk-critical)' : g.status === 'mentioned' ? 'var(--risk-caution)' : 'var(--muted-foreground)'}` }}>
                    <div className="flex flex-wrap items-center gap-2">
                      <b className="text-[13.5px]">{g.label}</b>{' '}
                      <Badge variant="secondary">{g.status.replace(/-/g, ' ').toUpperCase()}</Badge>
                    </div>
                    <FieldNote className="mt-1">{g.risk}</FieldNote>
                    {g.findings.map((f) => <small key={f.id} className="block text-xs text-muted-foreground">[{f.severity.toUpperCase()}] {f.title}</small>)}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Red-flag highlighter</CardTitle>
            </CardHeader>
            <CardContent>
              {!text.trim() && <FieldNote>Paste the listing text to inspect highlighted phrases.</FieldNote>}
              {text.trim() !== '' && sa.highlights.length === 0 && <FieldNote>No highlightable phrases — findings (if any) are listed under All findings.</FieldNote>}
              {text.trim() !== '' && sa.highlights.length > 0 && (
                <>
                  <div className="mt-1"><Highlighter text={text} highlights={sa.highlights} sel={selHi} onSelect={setSelHi} /></div>
                  {selHi !== null && sa.highlights[selHi] && (
                    <div className="mt-2 rounded-xl border bg-background px-4 py-3 shadow-xs" style={{ borderLeft: `3px solid ${sa.highlights[selHi].severity === 'critical' ? 'var(--risk-critical)' : sa.highlights[selHi].severity === 'high' ? 'var(--risk-high)' : 'var(--risk-suspicious)'}` }}>
                      <div className="flex flex-wrap items-center gap-2">
                        <FindingSeverity severity={sa.highlights[selHi].severity} />{' '}
                        <b className="text-[13.5px]">{sa.highlights[selHi].title}</b>{' '}
                        <small className="text-xs text-muted-foreground">{sa.highlights[selHi].category}</small>
                      </div>
                      <div className="mt-2 whitespace-pre-wrap rounded-md border border-dashed bg-card px-3 py-2 font-mono text-xs text-muted-foreground">{sa.highlights[selHi].quote}</div>
                      <FieldNote className="mt-2"><b className="text-foreground">Why it matters:</b> {sa.highlights[selHi].why}</FieldNote>
                      <FieldNote><b className="text-foreground">What to do:</b> {sa.highlights[selHi].recommendation}</FieldNote>
                    </div>
                  )}
                  <FieldNote className="mt-2">Select a highlighted phrase for the explanation.</FieldNote>
                </>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><ListChecks size={16} className="text-primary" /> Safety checklist</CardTitle>
            </CardHeader>
            <CardContent>
              <Progress value={(done / cl.total) * 100} />
              <FieldNote className="mt-1.5">{done}/{cl.total} complete · {cl.counts.passed} passed · {cl.counts.failed} failed · {cl.counts.unverified} unverified · {reviewed.size} reviewed by you</FieldNote>
              <div className="mt-2 space-y-2">
                {cl.items.map((c) => (
                  <div key={c.id} className="rounded-xl border bg-background px-4 py-3 shadow-xs" style={{ borderLeft: `3px solid ${c.state === 'passed' ? 'var(--risk-low)' : c.state === 'failed' ? 'var(--risk-critical)' : 'var(--muted-foreground)'}` }}>
                    <b className="text-[13.5px]">{c.label}</b>
                    <div className="mt-1 flex flex-wrap gap-1.5">
                      <StateDot state={c.state} />
                      <Badge variant="secondary">auto</Badge>
                      {reviewed.has(c.id) && <Badge variant="outline" style={{ color: 'var(--primary)', borderColor: 'color-mix(in srgb, var(--primary) 45%, transparent)' }}>reviewed by you</Badge>}
                    </div>
                    <FieldNote className="mt-1">{c.detail}</FieldNote>
                    <label className="mt-2 flex cursor-pointer items-center gap-2 text-[13px] text-muted-foreground">
                      <input type="checkbox" checked={reviewed.has(c.id)} onChange={() => toggle(c.id)} className="size-[18px] accent-[var(--ring)]" /> I have reviewed this myself
                    </label>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}

function Highlighter({ text, highlights, sel, onSelect }: { text: string; highlights: SafeApply['highlights']; sel: number | null; onSelect: (i: number | null) => void }) {
  const colors: Record<string, string> = { critical: 'var(--risk-critical)', high: 'var(--risk-high)', medium: 'var(--risk-suspicious)' };
  const spans = [...highlights].map((h, i) => ({ ...h, i })).sort((a, b) => a.start - b.start);
  const parts: React.ReactNode[] = [];
  let pos = 0;
  for (const h of spans) {
    if (h.start < pos || h.start >= text.length) continue;
    if (h.start > pos) parts.push(<span key={'t' + pos}>{text.slice(pos, h.start)}</span>);
    const c = colors[h.severity] || 'var(--muted-foreground)';
    parts.push(
      <mark
        key={'h' + h.i} onClick={() => onSelect(sel === h.i ? null : h.i)} title={`[${h.severity.toUpperCase()}] ${h.title}`}
        className="hl-mark"
        style={{ background: `color-mix(in srgb, ${c} 30%, transparent)`, borderBottom: `2px solid ${c}`, outline: sel === h.i ? `2px solid ${c}` : 'none' }}
      >
        {text.slice(h.start, Math.min(h.end, text.length))}
      </mark>
    );
    pos = Math.min(h.end, text.length);
  }
  if (pos < text.length) parts.push(<span key="t-end">{text.slice(pos)}</span>);
  return (
    <div className="max-h-[420px] overflow-y-auto whitespace-pre-wrap rounded-xl border bg-background p-4 text-sm leading-8 shadow-xs" aria-label="Job description with suspicious phrases highlighted">
      {parts}
    </div>
  );
}

function KV({ rows }: { rows: [string, string][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-3 gap-y-1.5 text-[13px] sm:grid-cols-[170px_1fr]">
      {rows.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="m-0">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function Intel({ intel }: { intel: Record<string, unknown> }) {
  const v = (k: string) => (intel[k] === null || intel[k] === undefined || intel[k] === '' ? 'unknown — not treated as safe' : String(intel[k]));
  return (
    <KV
      rows={[
        ['Registrable domain', v('domain')],
        ['Host', v('host')],
        ['Redirects', v('redirects')],
        ['HTTPS', v('https')],
        ['Certificate valid', v('certValid')],
        ['Threat-intel listing', intel['reputationListed'] ? `listed (${String(intel['reputationSource'] || 'feed')})` : 'not listed in checked feeds (not proof of safety)'],
        ['Domain age', intel['domainAgeDays'] === null || intel['domainAgeDays'] === undefined ? 'unknown — age never reduces behavioural risk' : `${intel['domainAgeDays']} days`],
        ['Inspection', `${String(intel['inspected'] ?? false)} · ${v('inspectNote')}`],
        ['Source / timestamp', `${v('source')} · ${v('at')}`],
      ]}
    />
  );
}
