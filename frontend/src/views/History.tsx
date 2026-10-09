import { useMemo, useState } from 'react';
import { Search, Trash2, History as HistoryIcon, TriangleAlert } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { EmptyState, PageHeader, RiskBadge } from '../components/ui';
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
      <PageHeader
        title={<span className="inline-flex items-center gap-2"><HistoryIcon size={26} className="text-primary" /> Scan history</span>}
        description="Previous scans on this device, newest first. Threat-intel data may have changed since a scan ran — re-scan before acting on old results."
        actions={entries.length > 0 ? (
          confirmClear
            ? <>
                <Button size="sm" variant="destructive" onClick={() => { clearHistory(); setConfirmClear(false); bump(); }}>Confirm delete all</Button>
                <Button size="sm" variant="outline" onClick={() => setConfirmClear(false)}>Cancel</Button>
              </>
            : <Button size="sm" variant="outline" onClick={() => setConfirmClear(true)}><Trash2 /> Clear history</Button>
        ) : undefined}
      />
      <Card>
        <CardContent className="space-y-4 pt-6">
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="relative min-w-[220px] flex-1">
              <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" aria-hidden />
              <Input className="rounded-full pl-9" placeholder="Search employer, domain, label…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search scan history" />
            </div>
            <div className="flex flex-wrap gap-1.5" role="radiogroup" aria-label="Filter by risk level">
              {FILTERS.map((f) => (
                <Button
                  key={f} role="radio" aria-checked={level === f} size="sm"
                  variant={level === f ? 'default' : 'secondary'}
                  onClick={() => setLevel(f)} className="capitalize"
                >
                  {f === 'all' ? 'All' : f}
                </Button>
              ))}
            </div>
          </div>
          {entries.length === 0 ? (
            <EmptyState title="No scan history" body="Scans you run on this device are stored locally (never uploaded) and will appear here for re-inspection." />
          ) : filtered.length === 0 ? (
            <EmptyState title="No matches" body="Try a different search term or risk filter." />
          ) : (
            <div className="flex flex-col gap-2">
              {filtered.map((e) => (
                <div
                  key={e.id}
                  role="button" tabIndex={0}
                  onClick={() => onOpen(e.id)}
                  onKeyDown={(ev) => { if (ev.key === 'Enter') onOpen(e.id); }}
                  aria-label={`Open scan: ${e.label}`}
                  className="grid cursor-pointer grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 rounded-xl border bg-background p-3 shadow-xs transition-colors hover:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <span className="truncate text-sm font-semibold">{e.label}</span>
                  <span className="flex items-center gap-2">
                    <RiskBadge level={e.level} band={`${e.score}`} />
                    <Button size="sm" variant="ghost" aria-label={`Delete scan ${e.label}`} onClick={(ev) => { ev.stopPropagation(); deleteScan(e.id); bump(); }}>
                      <Trash2 />
                    </Button>
                  </span>
                  <span className="text-xs text-muted-foreground">{new Date(e.at).toLocaleString()} · {e.kind === 'message' ? 'message scan' : e.sub} · {e.verdict}</span>
                </div>
              ))}
            </div>
          )}
          <p className="flex items-center gap-1.5 text-[13px] text-muted-foreground">
            <TriangleAlert size={14} /> Stored locally on this device only. Old results may be stale — re-scan before making decisions.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
