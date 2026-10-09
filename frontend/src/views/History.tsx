import { useMemo, useState } from 'react';
import { Search, Trash2, History as HistoryIcon, TriangleAlert } from 'lucide-react';
import { Card, RiskBadge, EmptyState } from '../components/ui';
import { listScans, deleteScan, clearHistory } from '../lib/history';

const FILTERS = ['all', 'low', 'caution', 'suspicious', 'high', 'critical'] as const;

export default function History({ onOpen, refreshKey }: { onOpen: (id: string) => void; refreshKey: number }) {
  const [q, setQ] = useState('');
  const [level, setLevel] = useState<(typeof FILTERS)[number]>('all');
  const [confirmClear, setConfirmClear] = useState(false);
  const [version, setVersion] = useState(0);
  const entries = useMemo(() => listScans(), [refreshKey, version]); // eslint-disable-line
  const bump = () => setVersion((v) => v + 1);
  const filtered = entries.filter(
    (e) => (level === 'all' || e.level === level) &&
      (q.trim() === '' || `${e.label} ${e.sub} ${e.employer || ''}`.toLowerCase().includes(q.trim().toLowerCase()))
  );

  return (
    <div>
      <div className="hero">
        <div>
          <h1><HistoryIcon size={28} style={{ verticalAlign: -5 }} /> Scan history</h1>
          <p>Previous scans on this device, newest first. Threat-intel data may have changed since a scan ran — re-scan before acting on old results.</p>
        </div>
        {entries.length > 0 && (
          confirmClear
            ? <div className="hero-actions"><button className="btn sm" onClick={() => { clearHistory(); setConfirmClear(false); bump(); }} style={{ borderColor: '#ef4444', color: '#ef4444' }}>Confirm delete all</button><button className="btn sm ghost" onClick={() => setConfirmClear(false)}>Cancel</button></div>
            : <div className="hero-actions"><button className="btn sm ghost" onClick={() => setConfirmClear(true)}><Trash2 size={14} /> Clear history</button></div>
        )}
      </div>
      <Card>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: '1 1 220px' }}>
            <Search size={15} style={{ position: 'absolute', left: 13, top: 13, color: '#a1a1aa' }} aria-hidden />
            <input className="input" style={{ paddingLeft: 36, borderRadius: 999 }} placeholder="Search employer, domain, label…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search scan history" />
          </div>
          <div className="pillrow" role="radiogroup" aria-label="Filter by risk level">
            {FILTERS.map((f) => (
              <button key={f} role="radio" aria-checked={level === f} className={level === f ? 'pill active' : 'pill'} onClick={() => setLevel(f)} style={{ textTransform: 'capitalize' }}>{f === 'all' ? 'All' : f}</button>
            ))}
          </div>
        </div>
        {entries.length === 0 ? (
          <EmptyState title="No scan history" body="Scans you run on this device are stored locally (never uploaded) and will appear here for re-inspection." />
        ) : filtered.length === 0 ? (
          <EmptyState title="No matches" body="Try a different search term or risk filter." />
        ) : (
          <div className="hist-list" style={{ marginTop: 14 }}>
            {filtered.map((e) => (
              <div key={e.id} className="hist-row" role="button" tabIndex={0} onClick={() => onOpen(e.id)} onKeyDown={(ev) => { if (ev.key === 'Enter') onOpen(e.id); }} aria-label={`Open scan: ${e.label}`}>
                <span className="t">{e.label}</span>
                <span style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <RiskBadge level={e.level} band={`${e.score}`} />
                  <button className="btn sm ghost" aria-label={`Delete scan ${e.label}`} onClick={(ev) => { ev.stopPropagation(); deleteScan(e.id); bump(); }}><Trash2 size={14} /></button>
                </span>
                <span className="m">{new Date(e.at).toLocaleString()} · {e.kind === 'message' ? 'message scan' : e.sub} · {e.verdict}</span>
              </div>
            ))}
          </div>
        )}
        <p className="note" style={{ marginTop: 12, display: 'flex', gap: 6, alignItems: 'center' }}>
          <TriangleAlert size={14} /> Stored locally on this device only. Old results may be stale — re-scan before making decisions.
        </p>
      </Card>
    </div>
  );
}
