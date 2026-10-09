import { useState } from 'react';
import { FileBarChart, Download, TriangleAlert } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table';
import { EmptyState, PageHeader, RiskBadge, FindingSeverity } from '../components/ui';
import { historyStats, listScans, topSignals } from '../lib/history';

export default function Reports({ onOpen }: { onOpen: (id: string) => void }) {
  const [toast, setToast] = useState('');
  const stats = historyStats();
  const signals = topSignals();
  const critical = listScans().filter((e) => e.level === 'critical' || e.level === 'high').slice(0, 10);

  function exportJson() {
    const blob = new Blob([JSON.stringify({ exportedAt: new Date().toISOString(), stats, scans: listScans() }, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `jobshield-report-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
    setToast('Report downloaded as JSON');
    setTimeout(() => setToast(''), 2600);
  }

  return (
    <div>
      <PageHeader
        title={<span className="inline-flex items-center gap-2"><FileBarChart size={26} className="text-primary" /> Reports</span>}
        description="Aggregates computed live from scans stored on this device. No data leaves your machine."
        actions={<Button disabled={stats.total === 0} onClick={exportJson}><Download /> Export JSON</Button>}
      />
      {stats.total === 0 ? (
        <Card><EmptyState title="No data to report" body="Run scans from Scan Job and they will be aggregated here — totals, recurring signals and high-risk cases." /></Card>
      ) : (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <ReportStat value={stats.total} label="Total scans" />
            <ReportStat value={stats.highRisk} label="High / critical" />
            <ReportStat value={stats.needVerify} label="Need verification" />
            <ReportStat value={signals.length} label="Distinct signals" />
          </div>
          <div className="mt-4 grid gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="font-serif text-xl">Top recurring signals</CardTitle>
                <CardDescription>Counted across your real scan history.</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader><TableRow><TableHead>Signal</TableHead><TableHead>Peak</TableHead><TableHead className="text-right">Hits</TableHead></TableRow></TableHeader>
                  <TableBody>
                    {signals.map((s) => (
                      <TableRow key={s.title}>
                        <TableCell>{s.title}</TableCell>
                        <TableCell><FindingSeverity severity={s.maxSev} /></TableCell>
                        <TableCell className="text-right font-bold tabular-nums">{s.count}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
                {signals.length === 0 && <p className="mt-2 text-sm text-muted-foreground">No medium+ signals recorded yet.</p>}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="font-serif text-xl">High-risk cases</CardTitle>
                <CardDescription>Scores reflect the moment of scanning — re-scan before acting.</CardDescription>
              </CardHeader>
              <CardContent>
                {critical.length === 0 && <p className="text-sm text-muted-foreground">None recorded.</p>}
                <div className="flex flex-col gap-2">
                  {critical.map((e) => (
                    <button
                      key={e.id}
                      onClick={() => onOpen(e.id)}
                      className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 rounded-xl border bg-background p-3 text-left shadow-xs transition-colors hover:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    >
                      <span className="truncate text-sm font-semibold">{e.label}</span>
                      <RiskBadge level={e.level} band={`${e.score}`} />
                      <span className="text-xs text-muted-foreground">{new Date(e.at).toLocaleString()}</span>
                    </button>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
          <p className="mt-3 flex items-center gap-1.5 text-[13px] text-muted-foreground">
            <TriangleAlert size={14} /> Historical scores may be stale as threat-intel data changes. Re-scan listings before making decisions.
          </p>
        </>
      )}
      {toast && (
        <div role="status" className="fixed bottom-20 left-1/2 z-50 -translate-x-1/2 rounded-full border bg-popover px-4 py-2 text-[13px] font-semibold text-popover-foreground shadow-lg md:bottom-6">
          {toast}
        </div>
      )}
    </div>
  );
}

function ReportStat({ value, label }: { value: number; label: string }) {
  return (
    <Card>
      <CardContent className="p-5">
        <div className="font-serif text-3xl font-bold leading-none tracking-tight tabular-nums">{value}</div>
        <div className="mt-1 text-xs font-medium text-muted-foreground">{label}</div>
      </CardContent>
    </Card>
  );
}
