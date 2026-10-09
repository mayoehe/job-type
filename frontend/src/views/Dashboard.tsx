import { ScanLine, ShieldX, AlertOctagon, UserSearch, ArrowRight, Activity, PieChart, Clock } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { RiskBadge, PageHeader, riskVar } from '../components/ui';
import { historyStats, listScans, type HistoryEntry } from '../lib/history';

const LEVELS = ['critical', 'high', 'suspicious', 'caution', 'low'] as const;

export default function Dashboard({ onScan, onOpen }: { onScan: () => void; onOpen: (id: string) => void }) {
  const stats = historyStats();
  const recent = listScans().slice(0, 5);
  const maxDay = Math.max(1, ...stats.last14.map((d) => d.count));
  const maxLevel = Math.max(1, ...Object.values(stats.byLevel));

  return (
    <div>
      <PageHeader
        title="Threat overview"
        description="JobShield scans job listings and recruiter messages for phishing behaviour — fee demands, credential harvesting and impersonation — and turns findings into a Safe Apply action plan."
        actions={<Button onClick={onScan}><ScanLine /> Scan a Job</Button>}
      />

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={<Activity size={20} />} tone="var(--chart-1)" value={stats.total} label="Jobs scanned" sub="on this device" />
        <StatCard icon={<ShieldX size={20} />} tone="var(--risk-high)" value={stats.highRisk} label="High-risk listings" sub="high + critical" />
        <StatCard icon={<AlertOctagon size={20} />} tone="var(--risk-critical)" value={stats.critical} label="Critical warnings" sub="immediate danger" />
        <StatCard icon={<UserSearch size={20} />} tone="var(--risk-caution)" value={stats.needVerify} label="Need verification" sub="verify employer" />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><PieChart size={16} className="text-primary" /> Risk distribution</CardTitle>
            <CardDescription>Real scans from this device — never sample data.</CardDescription>
          </CardHeader>
          <CardContent>
            {stats.total === 0 ? (
              <p className="text-sm text-muted-foreground">No scans yet. Scan your first listing to populate this chart.</p>
            ) : (
              <div className="flex flex-col gap-2.5">
                {LEVELS.map((l) => (
                  <div key={l} className="grid grid-cols-[96px_1fr_40px] items-center gap-2.5 text-[13px]">
                    <span className="capitalize text-muted-foreground">{l}</span>
                    <div className="h-2.5 overflow-hidden rounded-full bg-muted">
                      <div
                        className="h-full rounded-full"
                        style={{ width: `${(stats.byLevel[l] / maxLevel) * 100}%`, background: riskVar[l] }}
                      />
                    </div>
                    <span className="text-right font-bold tabular-nums">{stats.byLevel[l]}</span>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base"><Clock size={16} className="text-primary" /> Scan activity</CardTitle>
            <CardDescription>Genuine scan counts per day · last 14 days.</CardDescription>
          </CardHeader>
          <CardContent>
            {stats.total === 0 ? (
              <p className="text-sm text-muted-foreground">Nothing to show yet.</p>
            ) : (
              <div className="flex h-[120px] items-end gap-1.5" role="img" aria-label="Scan activity chart">
                {stats.last14.map((d) => (
                  <div key={d.day} title={`${d.day}: ${d.count} scan(s)`} className="flex min-w-0 flex-1 flex-col items-center gap-1">
                    <div className="flex h-[88px] w-full items-end">
                      <div
                        className="w-full rounded-full"
                        style={{
                          height: `${Math.max(d.count > 0 ? 10 : 3, (d.count / maxDay) * 88)}px`,
                          background: d.count > 0 ? 'linear-gradient(180deg, var(--chart-1), var(--chart-2))' : 'var(--muted)',
                        }}
                      />
                    </div>
                    <small className="text-[10px] text-muted-foreground">{d.day.slice(3)}</small>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle className="text-base">Recent scans</CardTitle>
          {recent.length > 0 && <CardDescription>{recent.length} of {stats.total} shown</CardDescription>}
        </CardHeader>
        <CardContent>
          {recent.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No scan history on this device.{' '}
              <Button variant="link" className="h-auto p-0 text-sm" onClick={onScan}>
                Scan your first job <ArrowRight />
              </Button>
            </p>
          ) : (
            <div className="flex flex-col gap-2">
              {recent.map((e: HistoryEntry) => (
                <button
                  key={e.id}
                  onClick={() => onOpen(e.id)}
                  className="grid grid-cols-[1fr_auto] items-center gap-x-3 gap-y-1 rounded-xl border bg-background p-3 text-left shadow-xs transition-colors hover:border-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <span className="truncate text-sm font-semibold">{e.label}</span>
                  <RiskBadge level={e.level} band={`${e.score} · ${e.band}`} />
                  <span className="text-xs text-muted-foreground">{new Date(e.at).toLocaleString()} · {e.kind === 'message' ? 'message' : e.sub}</span>
                </button>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function StatCard({ icon, value, label, sub, tone }: { icon: React.ReactNode; value: number; label: string; sub: string; tone: string }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3.5 p-5">
        <div
          className="grid size-11 shrink-0 place-items-center rounded-xl border shadow-xs"
          style={{ color: tone, borderColor: `color-mix(in srgb, ${tone} 40%, transparent)`, background: `color-mix(in srgb, ${tone} 10%, transparent)` }}
        >
          {icon}
        </div>
        <div>
          <div className="font-serif text-3xl font-bold leading-none tracking-tight tabular-nums">{value}</div>
          <div className="mt-1 text-xs font-medium text-muted-foreground">{label} · {sub}</div>
        </div>
      </CardContent>
    </Card>
  );
}
