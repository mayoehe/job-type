import type { ReactNode } from 'react';
import {
  ShieldCheck, ShieldAlert, ShieldX, AlertTriangle, Info, CheckCircle2,
  MinusCircle, HelpCircle, Inbox,
} from 'lucide-react';

export const sevColor: Record<string, string> = {
  critical: 'var(--sev-crit)', high: 'var(--sev-high)', medium: 'var(--sev-med)', low: 'var(--sev-mut)', info: 'var(--sev-mut)',
};
export const levelColor: Record<string, string> = {
  low: '#bef264', caution: '#fbbf24', suspicious: '#fb923c', high: '#ef4444', critical: '#dc2626',
};
// Lime/amber/orange badges carry dark text; red badges carry white text (accessible contrast on dark canvas).
export const levelInk: Record<string, string> = {
  low: '#141a05', caution: '#1c1206', suspicious: '#1c1006', high: '#ffffff', critical: '#ffffff',
};
export const verdictMeta: Record<string, { icon: ReactNode; color: string; label: string }> = {
  avoid: { icon: <ShieldX size={15} />, color: '#ef4444', label: 'Avoid This Listing' },
  verify: { icon: <ShieldAlert size={15} />, color: '#fb923c', label: 'Verify Employer' },
  proceed: { icon: <ShieldCheck size={15} />, color: '#bef264', label: 'Proceed Carefully' },
};

export function Card({ children, style, hover }: { children: ReactNode; style?: React.CSSProperties; hover?: boolean }) {
  return <div className={hover ? 'card hoverable' : 'card'} style={style}>{children}</div>;
}

export function RiskBadge({ level, band }: { level: string; band: string }) {
  return (
    <span className={`badge risk-${level}`} style={{ background: levelColor[level] || '#71717a', color: levelInk[level] || '#fafafa' }}>
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
        <circle cx="74" cy="74" r={r} fill="none" stroke="#26262c" strokeWidth="12" />
        <circle cx="74" cy="74" r={r} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={`${frac * c} ${c}`} />
      </svg>
      <div className="num"><div><b>{score}</b><br /><small>/ 100</small></div></div>
    </div>
  );
}

export function StateDot({ state }: { state: 'passed' | 'failed' | 'unverified' }) {
  const color = state === 'passed' ? 'var(--ok)' : state === 'failed' ? 'var(--fail)' : 'var(--mut)';
  const Icon = state === 'passed' ? CheckCircle2 : state === 'failed' ? MinusCircle : HelpCircle;
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 800, letterSpacing: '0.05em', color }}>
      <Icon size={14} aria-hidden /> {state.toUpperCase()}
    </span>
  );
}

export function VerifyChip({ status }: { status: string }) {
  const color = status === 'verified' ? 'var(--ok)' : status === 'mismatch' ? 'var(--fail)' : 'var(--ink-2)';
  return (
    <span className="tag" style={{ color, borderColor: `color-mix(in srgb, ${color} 40%, transparent)` }}>
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
  const color = sevColor[severity] || 'var(--ink-2)';
  return (
    <span className="tag" style={{ color, borderColor: `color-mix(in srgb, ${color} 40%, transparent)` }}>
      {severity.toUpperCase()}
    </span>
  );
}
