import { useState } from 'react';
import { ShieldCheck, TriangleAlert, BellRing, Building2, Fingerprint, ListChecks, ChartColumn, Globe } from 'lucide-react';
import { Card, RiskBadge, ScoreRing, StateDot, VerifyChip, FindingSeverity, EmptyState } from '../components/ui';
import type { ScanResultFull, SafeApply } from '../lib/api';

const CATS = [
  { key: 'linguistic', label: 'Linguistic', max: 35, color: '#a78bfa' },
  { key: 'behavioural', label: 'Behavioural', max: 30, color: '#8b5cf6' },
  { key: 'domain', label: 'URL & domain', max: 15, color: '#c4b5fd' },
  { key: 'technical', label: 'Technical', max: 10, color: '#6d6d78' },
  { key: 'employer', label: 'Employer', max: 10, color: '#6d6d78' },
];

export default function Results({ result, source, text }: { result: ScanResultFull; source: string | null; text: string }) {
  const sa = result.safeApply;
  const [reviewed, setReviewed] = useState<Set<string>>(new Set());
  const [selHi, setSelHi] = useState<number | null>(null);
  const [showShared, setShowShared] = useState(false);
  const toggle = (id: string) => setReviewed((p) => { const n = new Set(p); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  return (
    <div>
      <Card style={{ borderColor: result.color }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap', marginBottom: 12 }}>
          <h2>Risk assessment</h2>
          <RiskBadge level={result.level} band={result.band} />
          {source && <span className="tag">{source === 'backend' ? 'backend evidence' : 'local estimate'}</span>}
        </div>
        <div className="score-hero">
          <ScoreRing score={result.score} color={result.color} />
          <div style={{ flex: 1, minWidth: 240 }}>
            <div className="segbar">
              {CATS.map((c) => {
                const v = result.categories[c.key];
                return <div key={c.key} title={`${c.label}: ${v.score}/${v.max}`} style={{ width: `${(v.score / 100) * 100}%`, background: c.color }} />;
              })}
            </div>
            {CATS.map((c) => {
              const v = result.categories[c.key];
              return (
                <div className="catline" key={c.key}>
                  <span>{c.label} ({c.max})</span>
                  <div className="track"><div className="fill" style={{ width: `${Math.min(100, (v.score / v.max) * 100)}%`, background: c.color }} /></div>
                  <span style={{ textAlign: 'right', fontWeight: 800 }}>{v.score}</span>
                </div>
              );
            })}
            <p className="note">Raw total {result.rawTotal}{result.floor > result.rawTotal ? ` · raised to floor ${result.floor} by severity override` : ''} · {result.counts.confirmed} confirmed · {result.counts.suspicious} suspicious · {result.counts.info} context/unknown.</p>
          </div>
        </div>
        {result.overrides.map((o) => (
          <div className="alert crit" key={o.id} role="alert"><b><BellRing size={15} style={{ verticalAlign: -2 }} /> {o.title}</b><div className="note">{o.detail} (risk floor {o.floor})</div></div>
        ))}
      </Card>

      {sa && <SafeApply sa={sa} text={text} reviewed={reviewed} toggle={toggle} selHi={selHi} setSelHi={setSelHi} showShared={showShared} setShowShared={setShowShared} />}

      <Card style={{ marginTop: 16 }}>
        <h2><ChartColumn size={16} style={{ verticalAlign: -3 }} /> All findings</h2>
        {result.allFindings.length === 0 && <EmptyState title="No findings" body="Sparse input produced no findings. Absence of flags is not proof of safety." />}
        {result.allFindings.map((f) => (
          <details className="exp" key={f.id}>
            <summary><FindingSeverity severity={f.severity} /> {f.title} <span className="note">+{f.points} · {f.category}</span></summary>
            <div className="body"><div className="ev finding" style={{ margin: 0 }}>{f.evidence}</div></div>
          </details>
        ))}
      </Card>

      <Card style={{ marginTop: 16 }}>
        <h2><Globe size={16} style={{ verticalAlign: -3 }} /> URL intelligence</h2>
        {result.intelligence ? <Intel intel={result.intelligence as Record<string, unknown>} /> : (
          <dl className="kv">
            <dt>Mode</dt><dd>Local offline analysis (no live fetch)</dd>
            <dt>Host</dt><dd>{result.meta.urlHost || '— (no URL provided; text-only analysis)'}</dd>
            <dt>Registrable domain</dt><dd>{result.meta.registrableDomain || '—'}</dd>
            <dt>HTTPS / cert / age</dt><dd>Unknown in local mode — not treated as safe.</dd>
          </dl>
        )}
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
  return <SafeApply sa={result.safeApply} text={text} reviewed={reviewed} toggle={toggle} selHi={selHi} setSelHi={setSelHi} showShared={showShared} setShowShared={setShowShared} />;
}

export function SafeApply({ sa, text, reviewed, toggle, selHi, setSelHi, showShared, setShowShared }:
  { sa: SafeApply; text: string; reviewed: Set<string>; toggle: (id: string) => void; selHi: number | null; setSelHi: (i: number | null) => void; showShared: boolean; setShowShared: (b: boolean) => void }) {
  const vColor = sa.verdict === 'avoid' ? '#ef4444' : sa.verdict === 'verify' ? '#f59e0b' : '#22c55e';
  const cl = sa.checklist;
  const done = cl.items.filter((i) => i.state === 'passed').length + [...reviewed].filter((id) => cl.items.some((i) => i.id === id && i.state !== 'passed')).length;
  return (
    <div>
      <Card style={{ marginTop: 16, borderColor: vColor }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <h2>Safe Apply</h2>
          <span className="badge" style={{ background: vColor }}>
            {sa.verdict === 'avoid' ? <ShieldCheck size={14} /> : <TriangleAlert size={14} />} {sa.verdictLabel}
          </span>
        </div>
        <p style={{ margin: '10px 0 0' }}>{sa.whyUnsafe}</p>
        <h3 style={{ marginTop: 14 }}>Your action plan</h3>
        <ol className="steps">
          {sa.steps.map((s, i) => (
            <li key={i} className={s.priority === 'urgent' ? 'urgent' : ''}>
              <b>{s.title}</b><div className="note">{s.detail}</div>
            </li>
          ))}
        </ol>
        <button className="btn ghost sm" onClick={() => setShowShared(!showShared)} aria-expanded={showShared}>
          {showShared ? 'Hide' : 'Show'}: I already shared information / paid money
        </button>
        {showShared && (
          <div className="grid two" style={{ marginTop: 10 }}>
            <div className="finding" style={{ borderLeftColor: '#ef4444' }}><b>Money / credentials exposed</b><div className="note">{sa.alreadyShared.money}</div></div>
            <div className="finding" style={{ borderLeftColor: '#f59e0b' }}><b>Identity documents shared</b><div className="note">{sa.alreadyShared.identity}</div></div>
            <div className="finding" style={{ borderLeftColor: '#a78bfa', gridColumn: '1 / -1' }}><b>Report fraud</b><div className="note">{sa.alreadyShared.report}</div></div>
          </div>
        )}
      </Card>

      <div className="grid two" style={{ marginTop: 16 }}>
        <div>
          <Card>
            <h2><Building2 size={16} style={{ verticalAlign: -3 }} /> Employer verification {sa.verification && <VerifyChip status={sa.verification.overall} />}</h2>
            {!sa.verification && <p className="note" style={{ marginTop: 8 }}>Verification unavailable offline — locate the official site yourself.</p>}
            {sa.verification && (
              <>
                <dl className="kv">
                  <dt>Claimed employer</dt><dd>{sa.verification.claimedEmployer || 'Could not identify'}</dd>
                  <dt>Position</dt><dd>{sa.verification.claimedPosition || 'Could not identify'}</dd>
                  <dt>Official domain</dt><dd>{sa.verification.officialDomain || 'Could Not Verify'}</dd>
                  <dt>Listing domain</dt><dd>{sa.verification.listingDomain || '— (no URL)'}</dd>
                </dl>
                {sa.verification.checks.map((c) => (
                  <div className="finding" key={c.id} style={{ borderLeftColor: c.status === 'verified' ? '#22c55e' : c.status === 'mismatch' ? '#ef4444' : '#64748b' }}>
                    <b>{c.label}</b> <VerifyChip status={c.status} />
                    <div className="note">{c.evidence}</div>
                    <small className="note">Source: {c.source}</small>
                  </div>
                ))}
              </>
            )}
          </Card>
          <Card style={{ marginTop: 16 }}>
            <h2><Fingerprint size={16} style={{ verticalAlign: -3 }} /> Information protection</h2>
            {sa.protection.length === 0 && <p className="note" style={{ marginTop: 8 }}>Offline estimate — protection detail needs the backend.</p>}
            {sa.protection.map((g) => (
              <div className="finding" key={g.id} style={{ borderLeftColor: g.status === 'requested' ? '#ef4444' : g.status === 'mentioned' ? '#f59e0b' : '#64748b' }}>
                <b>{g.label}</b> <span className="tag">{g.status.replace(/-/g, ' ').toUpperCase()}</span>
                <div className="note">{g.risk}</div>
                {g.findings.map((f) => <small key={f.id} className="note" style={{ display: 'block' }}>[{f.severity.toUpperCase()}] {f.title}</small>)}
              </div>
            ))}
          </Card>
        </div>
        <div>
          <Card>
            <h2>Red-flag highlighter</h2>
            {!text.trim() && <p className="note" style={{ marginTop: 8 }}>Paste the listing text to inspect highlighted phrases.</p>}
            {text.trim() !== '' && sa.highlights.length === 0 && <p className="note" style={{ marginTop: 8 }}>No highlightable phrases — findings (if any) are listed under All findings.</p>}
            {text.trim() !== '' && sa.highlights.length > 0 && (
              <>
                <div style={{ marginTop: 8 }}><Highlighter text={text} highlights={sa.highlights} sel={selHi} onSelect={setSelHi} /></div>
                {selHi !== null && sa.highlights[selHi] && (
                  <div className="finding" style={{ borderLeftColor: sa.highlights[selHi].severity === 'critical' ? '#ef4444' : sa.highlights[selHi].severity === 'high' ? '#f97316' : '#f59e0b' }}>
                    <FindingSeverity severity={sa.highlights[selHi].severity} /> <b>{sa.highlights[selHi].title}</b> <small className="note">{sa.highlights[selHi].category}</small>
                    <div className="ev">{sa.highlights[selHi].quote}</div>
                    <p className="note"><b>Why it matters:</b> {sa.highlights[selHi].why}</p>
                    <p className="note"><b>What to do:</b> {sa.highlights[selHi].recommendation}</p>
                  </div>
                )}
                <p className="note">Select a highlighted phrase for the explanation.</p>
              </>
            )}
          </Card>
          <Card style={{ marginTop: 16 }}>
            <h2><ListChecks size={16} style={{ verticalAlign: -3 }} /> Safety checklist</h2>
            <div className="progress" role="progressbar" aria-valuenow={done} aria-valuemax={cl.total} aria-label="Checklist progress"><div style={{ width: `${(done / cl.total) * 100}%` }} /></div>
            <p className="note">{done}/{cl.total} complete · {cl.counts.passed} passed · {cl.counts.failed} failed · {cl.counts.unverified} unverified · {reviewed.size} reviewed by you</p>
            {cl.items.map((c) => (
              <div className="finding" key={c.id} style={{ borderLeftColor: c.state === 'passed' ? '#22c55e' : c.state === 'failed' ? '#ef4444' : '#64748b' }}>
                <div className="check">
                  <div style={{ flex: 1 }}>
                    <b>{c.label}</b>
                    <div style={{ display: 'flex', gap: 6, marginTop: 4, flexWrap: 'wrap' }}>
                      <StateDot state={c.state} />
                      <span className="tag">auto</span>
                      {reviewed.has(c.id) && <span className="tag" style={{ color: '#a78bfa', borderColor: '#8b5cf666' }}>reviewed by you</span>}
                    </div>
                    <div className="note" style={{ marginTop: 4 }}>{c.detail}</div>
                    <label className="note" style={{ display: 'flex', gap: 7, marginTop: 8, cursor: 'pointer', alignItems: 'center' }}>
                      <input type="checkbox" checked={reviewed.has(c.id)} onChange={() => toggle(c.id)} /> I have reviewed this myself
                    </label>
                  </div>
                </div>
              </div>
            ))}
          </Card>
        </div>
      </div>
    </div>
  );
}

function Highlighter({ text, highlights, sel, onSelect }: { text: string; highlights: SafeApply['highlights']; sel: number | null; onSelect: (i: number | null) => void }) {
  const colors: Record<string, string> = { critical: '#ef4444', high: '#f97316', medium: '#f59e0b' };
  const spans = [...highlights].map((h, i) => ({ ...h, i })).sort((a, b) => a.start - b.start);
  const parts: React.ReactNode[] = [];
  let pos = 0;
  for (const h of spans) {
    if (h.start < pos || h.start >= text.length) continue;
    if (h.start > pos) parts.push(<span key={'t' + pos}>{text.slice(pos, h.start)}</span>);
    const c = colors[h.severity] || '#a1a1aa';
    parts.push(
      <mark key={'h' + h.i} onClick={() => onSelect(sel === h.i ? null : h.i)} title={`[${h.severity.toUpperCase()}] ${h.title}`}
        style={{ background: c + '44', borderBottom: `2px solid ${c}`, outline: sel === h.i ? `2px solid ${c}` : 'none' }}>
        {text.slice(h.start, Math.min(h.end, text.length))}
      </mark>
    );
    pos = Math.min(h.end, text.length);
  }
  if (pos < text.length) parts.push(<span key="t-end">{text.slice(pos)}</span>);
  return <div className="hlbox" aria-label="Job description with suspicious phrases highlighted">{parts}</div>;
}

function Intel({ intel }: { intel: Record<string, unknown> }) {
  const v = (k: string) => (intel[k] === null || intel[k] === undefined || intel[k] === '' ? 'unknown — not treated as safe' : String(intel[k]));
  return (
    <dl className="kv">
      <dt>Registrable domain</dt><dd>{v('domain')}</dd>
      <dt>Host</dt><dd>{v('host')}</dd>
      <dt>Redirects</dt><dd>{v('redirects')}</dd>
      <dt>HTTPS</dt><dd>{v('https')}</dd>
      <dt>Certificate valid</dt><dd>{v('certValid')}</dd>
      <dt>Threat-intel listing</dt><dd>{intel['reputationListed'] ? `listed (${String(intel['reputationSource'] || 'feed')})` : 'not listed in checked feeds (not proof of safety)'}</dd>
      <dt>Domain age</dt><dd>{intel['domainAgeDays'] === null || intel['domainAgeDays'] === undefined ? 'unknown — age never reduces behavioural risk' : `${intel['domainAgeDays']} days`}</dd>
      <dt>Inspection</dt><dd>{String(intel['inspected'] ?? false)} · {v('inspectNote')}</dd>
      <dt>Source / timestamp</dt><dd>{v('source')} · {v('at')}</dd>
    </dl>
  );
}
