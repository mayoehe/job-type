import { useState } from 'react';
import { FileBarChart, Download, TriangleAlert } from 'lucide-react';
import { Card, RiskBadge, EmptyState, FindingSeverity } from '../components/ui';
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
      <div className="hero">
        <div>
          <h1><FileBarChart size={28} style={{ verticalAlign: -5 }} /> Reports</h1>
          <p>Aggregates computed live from scans stored on this device. No data leaves your machine.</p>
        </div>
        <div className="hero-actions">
          <button className="btn primary" disabled={stats.total === 0} onClick={exportJson}><Download size={16} /> Export JSON</button>
        </div>
      </div>
      {stats.total === 0 ? (
        <Card><EmptyState title="No data to report" body="Run scans from Scan Job and they will be aggregated here — totals, recurring signals and high-risk cases." /></Card>
      ) : (
        <>
          <div className="grid four">
            <Card><ReportStat value={stats.total} label="Total scans" /></Card>
            <Card><ReportStat value={stats.highRisk} label="High / critical" /></Card>
            <Card><ReportStat value={stats.needVerify} label="Need verification" /></Card>
            <Card><ReportStat value={signals.length} label="Distinct signals" /></Card>
          </div>
          <div className="grid two" style={{ marginTop: 16 }}>
            <Card>
              <h2>Top recurring signals</h2>
              <p className="sub">Counted across your real scan history.</p>
              <table className="rep" style={{ marginTop: 8 }}>
                <thead><tr><th>Signal</th><th>Peak</th><th>Hits</th></tr></thead>
                <tbody>
                  {signals.map((s) => (
                    <tr key={s.title}><td>{s.title}</td><td><FindingSeverity severity={s.maxSev} /></td><td style={{ fontWeight: 800 }}>{s.count}</td></tr>
                  ))}
                </tbody>
              </table>
              {signals.length === 0 && <p className="note">No medium+ signals recorded yet.</p>}
            </Card>
            <Card>
              <h2>High-risk cases</h2>
              <p className="sub">Scores reflect the moment of scanning — re-scan before acting.</p>
              {critical.length === 0 && <p className="note">None recorded.</p>}
              <div className="hist-list" style={{ marginTop: 10 }}>
                {critical.map((e) => (
                  <button key={e.id} className="hist-row" onClick={() => onOpen(e.id)}>
                    <span className="t">{e.label}</span>
                    <RiskBadge level={e.level} band={`${e.score}`} />
                    <span className="m">{new Date(e.at).toLocaleString()}</span>
                  </button>
                ))}
              </div>
            </Card>
          </div>
          <p className="note" style={{ marginTop: 12, display: 'flex', gap: 6, alignItems: 'center' }}>
            <TriangleAlert size={14} /> Historical scores may be stale as threat-intel data changes. Re-scan listings before making decisions.
          </p>
        </>
      )}
      {toast && <div className="toast" role="status">{toast}</div>}
    </div>
  );
}

function ReportStat({ value, label }: { value: number; label: string }) {
  return <div className="stat"><div><b>{value}</b><span>{label}</span></div></div>;
}
