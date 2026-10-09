import { ScanLine, ShieldX, AlertOctagon, UserSearch, ArrowRight, Activity, PieChart, Clock } from 'lucide-react';
import { Card, RiskBadge } from '../components/ui';
import { historyStats, listScans, type HistoryEntry } from '../lib/history';

const levelColor: Record<string, string> = { low: '#22c55e', caution: '#eab308', suspicious: '#f59e0b', high: '#f97316', critical: '#ef4444' };

export default function Dashboard({ onScan, onOpen }: { onScan: () => void; onOpen: (id: string) => void }) {
  const stats = historyStats();
  const recent = listScans().slice(0, 5);
  const maxDay = Math.max(1, ...stats.last14.map((d) => d.count));
  const maxLevel = Math.max(1, ...Object.values(stats.byLevel));

  return (
    <div>
      <div className="hero">
        <div>
          <h1>Threat overview</h1>
          <p>JobShield scans job listings and recruiter messages for phishing behaviour — fee demands, credential harvesting and impersonation — and turns findings into a Safe Apply action plan.</p>
        </div>
        <div className="hero-actions">
          <button className="btn primary" onClick={onScan}><ScanLine size={16} /> Scan a Job</button>
        </div>
      </div>

      <div className="grid four">
        <Card><Stat icon={<Activity size={20} />} value={stats.total} label="Jobs scanned" sub="this device" /></Card>
        <Card><Stat icon={<ShieldX size={20} />} value={stats.highRisk} label="High-risk listings" sub="high + critical" /></Card>
        <Card><Stat icon={<AlertOctagon size={20} />} value={stats.critical} label="Critical warnings" sub="immediate danger" /></Card>
        <Card><Stat icon={<UserSearch size={20} />} value={stats.needVerify} label="Need verification" sub="verify employer" /></Card>
      </div>

      <div className="grid two" style={{ marginTop: 16 }}>
        <Card>
          <h2><PieChart size={16} style={{ verticalAlign: -3 }} /> Risk distribution</h2>
          <p className="sub">Real scans from this device — never sample data.</p>
          {stats.total === 0 ? (
            <p className="note" style={{ marginTop: 12 }}>No scans yet. Scan your first listing to populate this chart.</p>
          ) : (
            <div className="bars">
              {(['critical', 'high', 'suspicious', 'caution', 'low'] as const).map((l) => (
                <div className="barrow" key={l}>
                  <span style={{ textTransform: 'capitalize' }}>{l}</span>
                  <div className="track"><div className="fill" style={{ width: `${(stats.byLevel[l] / maxLevel) * 100}%`, background: levelColor[l] }} /></div>
                  <span style={{ textAlign: 'right', fontWeight: 800 }}>{stats.byLevel[l]}</span>
                </div>
              ))}
            </div>
          )}
        </Card>
        <Card>
          <h2><Clock size={16} style={{ verticalAlign: -3 }} /> Scan activity · last 14 days</h2>
          <p className="sub">Bars show genuine scan counts per day.</p>
          {stats.total === 0 ? (
            <p className="note" style={{ marginTop: 12 }}>Nothing to show yet.</p>
          ) : (
            <div style={{ display: 'flex', gap: 6, alignItems: 'flex-end', height: 120, marginTop: 14 }} role="img" aria-label="Scan activity chart">
              {stats.last14.map((d) => (
                <div key={d.day} title={`${d.day}: ${d.count} scan(s)`} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 5, minWidth: 0 }}>
                  <div style={{ width: '100%', height: 88, display: 'flex', alignItems: 'flex-end' }}>
                    <div style={{ width: '100%', height: `${Math.max(d.count > 0 ? 8 : 2, (d.count / maxDay) * 88)}px`, borderRadius: 5, background: d.count > 0 ? 'linear-gradient(180deg,#8b5cf6,#6d28d9)' : '#25242d' }} />
                  </div>
                  <small style={{ fontSize: 9.5, color: '#a1a1aa' }}>{d.day.slice(3)}</small>
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>

      <Card style={{ marginTop: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
          <h2>Recent scans</h2>
          {recent.length > 0 && <span className="note">{recent.length} of {stats.total} shown</span>}
        </div>
        {recent.length === 0 ? (
          <p className="note" style={{ marginTop: 10 }}>No scan history on this device. <button className="btn sm" onClick={onScan} style={{ marginLeft: 6 }}>Scan your first job <ArrowRight size={14} /></button></p>
        ) : (
          <div className="hist-list" style={{ marginTop: 12 }}>
            {recent.map((e: HistoryEntry) => (
              <button key={e.id} className="hist-row" onClick={() => onOpen(e.id)}>
                <span className="t">{e.label}</span>
                <RiskBadge level={e.level} band={`${e.score} · ${e.band}`} />
                <span className="m">{new Date(e.at).toLocaleString()} · {e.kind === 'message' ? 'message' : e.sub}</span>
              </button>
            ))}
          </div>
        )}
      </Card>
    </div>
  );
}

function Stat({ icon, value, label, sub }: { icon: React.ReactNode; value: number; label: string; sub: string }) {
  return (
    <div className="stat">
      <div className="stat-ic">{icon}</div>
      <div><b>{value}</b><span>{label} · {sub}</span></div>
    </div>
  );
}
