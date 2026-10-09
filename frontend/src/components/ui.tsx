import type { ReactNode } from 'react';
import {
  ShieldCheck, ShieldAlert, ShieldX, AlertTriangle, Info, CheckCircle2,
  MinusCircle, HelpCircle, Inbox,
} from 'lucide-react';

export const sevColor: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#f59e0b', low: '#64748b', info: '#64748b',
};
export const levelColor: Record<string, string> = {
  low: '#22c55e', caution: '#eab308', suspicious: '#f59e0b', high: '#f97316', critical: '#ef4444',
};
export const verdictMeta: Record<string, { icon: ReactNode; color: string; label: string }> = {
  avoid: { icon: <ShieldX size={15} />, color: '#ef4444', label: 'Avoid This Listing' },
  verify: { icon: <ShieldAlert size={15} />, color: '#f59e0b', label: 'Verify Employer' },
  proceed: { icon: <ShieldCheck size={15} />, color: '#22c55e', label: 'Proceed Carefully' },
};

export function Card({ children, style, hover }: { children: ReactNode; style?: React.CSSProperties; hover?: boolean }) {
  return <div className={hover ? 'card hoverable' : 'card'} style={style}>{children}</div>;
}

export function RiskBadge({ level, band }: { level: string; band: string }) {
  return (
    <span className={`badge risk-${level}`} style={{ background: levelColor[level] || '#64748b' }}>
      {level === 'low' ? <ShieldCheck size={14} /> : level === 'critical' || level === 'high' ? <ShieldX size={14} /> : <AlertTriangle size={14} />}
      {band}
    </span>
  );
}

export function ScoreRing({ score, color }: { score: number; color: string }) {
  const r = 62;
  const c = 2 * Math.PI * r;
  const frac = Math.max(0, Math.min(100, score)) / 100;
  return (
    <div className="ring" role="img" aria-label={`Risk score ${score} out of 100`}>
      <svg width="148" height="148" viewBox="0 0 148 148">
        <circle cx="74" cy="74" r={r} fill="none" stroke="#303039" strokeWidth="12" />
        <circle cx="74" cy="74" r={r} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={`${frac * c} ${c}`} />
      </svg>
      <div className="num"><div><b>{score}</b><br /><small>/ 100</small></div></div>
    </div>
  );
}

export function StateDot({ state }: { state: 'passed' | 'failed' | 'unverified' }) {
  const color = state === 'passed' ? '#22c55e' : state === 'failed' ? '#ef4444' : '#64748b';
  const Icon = state === 'passed' ? CheckCircle2 : state === 'failed' ? MinusCircle : HelpCircle;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 800, letterSpacing: '0.05em', color }}>
      <Icon size={14} aria-hidden /> {state.toUpperCase()}
    </span>
  );
}

export function VerifyChip({ status }: { status: string }) {
  const color = status === 'verified' ? '#22c55e' : status === 'mismatch' ? '#ef4444' : '#a1a1aa';
  return (
    <span className="tag" style={{ color, borderColor: color + '66' }}>
      {status === 'verified' ? <CheckCircle2 size={12} /> : status === 'mismatch' ? <AlertTriangle size={12} /> : <Info size={12} />}
      {status.replace(/-/g, ' ')}
    </span>
  );
}

export function EmptyState({ icon, title, body, action }: { icon?: ReactNode; title: string; body: string; action?: ReactNode }) {
  return (
    <div className="empty">
      {icon || <Inbox size={34} />}
      <h3 style={{ marginBottom: 6 }}>{title}</h3>
      <p className="note" style={{ maxWidth: 420, margin: '0 auto 12px' }}>{body}</p>
      {action}
    </div>
  );
}

export function Skeleton({ height = 120 }: { height?: number }) {
  return <div className="skel" style={{ height }} aria-hidden />;
}

export function FindingSeverity({ severity }: { severity: string }) {
  return (
    <span className="tag" style={{ color: sevColor[severity] || '#a1a1aa', borderColor: (sevColor[severity] || '#666') + '66' }}>
      {severity.toUpperCase()}
    </span>
  );
}
