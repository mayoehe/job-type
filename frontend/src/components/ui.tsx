import type { ReactNode } from 'react';
import {
  ShieldCheck, ShieldAlert, ShieldX, AlertTriangle, Info, CheckCircle2,
  MinusCircle, HelpCircle, Inbox,
} from 'lucide-react';
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { cn } from '../lib/utils';

/** Risk-scale colours (theme-aware CSS vars; red reserved for high/critical). */
export const riskVar: Record<string, string> = {
  low: 'var(--risk-low)',
  caution: 'var(--risk-caution)',
  suspicious: 'var(--risk-suspicious)',
  high: 'var(--risk-high)',
  critical: 'var(--risk-critical)',
};

export const sevVar: Record<string, string> = {
  critical: 'var(--risk-critical)',
  high: 'var(--risk-high)',
  medium: 'var(--risk-suspicious)',
  low: 'var(--muted-foreground)',
  info: 'var(--muted-foreground)',
};

export const verdictVar: Record<string, string> = {
  avoid: 'var(--risk-critical)',
  verify: 'var(--risk-caution)',
  proceed: 'var(--risk-low)',
};

export const verdictMeta: Record<string, { icon: ReactNode; label: string }> = {
  avoid: { icon: <ShieldX />, label: 'Avoid This Listing' },
  verify: { icon: <ShieldAlert />, label: 'Verify Employer' },
  proceed: { icon: <ShieldCheck />, label: 'Proceed Carefully' },
};

function softStyle(color: string): React.CSSProperties {
  return {
    color,
    borderColor: `color-mix(in srgb, ${color} 45%, transparent)`,
    background: `color-mix(in srgb, ${color} 12%, transparent)`,
  };
}

export function RiskBadge({ level, band }: { level: string; band: string }) {
  const c = riskVar[level] || 'var(--muted-foreground)';
  return (
    <Badge variant="outline" style={softStyle(c)} className="gap-1.5">
      {level === 'low' ? <ShieldCheck /> : level === 'critical' || level === 'high' ? <ShieldX /> : <AlertTriangle />}
      {band}
    </Badge>
  );
}

export function VerdictBadge({ verdict, label }: { verdict: string; label: string }) {
  const c = verdictVar[verdict] || 'var(--muted-foreground)';
  const meta = verdictMeta[verdict];
  return (
    <Badge variant="outline" style={softStyle(c)} className="gap-1.5 px-3 py-1 text-[13px]">
      {meta?.icon}
      {label}
    </Badge>
  );
}

export function ScoreRing({ score, color }: { score: number; color: string }) {
  const r = 62;
  const c = 2 * Math.PI * r;
  const frac = Math.max(0, Math.min(100, score)) / 100;
  return (
    <div className="relative size-36 shrink-0" role="img" aria-label={`Risk score ${score} out of 100`}>
      <svg width="144" height="144" viewBox="0 0 148 148" className="-rotate-90">
        <circle cx="74" cy="74" r={r} fill="none" stroke="var(--border)" strokeWidth="12" />
        <circle
          cx="74" cy="74" r={r} fill="none" stroke={color} strokeWidth="12" strokeLinecap="round"
          strokeDasharray={`${frac * c} ${c}`}
        />
      </svg>
      <div className="absolute inset-0 grid place-content-center text-center">
        <div>
          <span className="font-serif text-4xl font-extrabold tracking-tight tabular-nums">{score}</span>
          <br />
          <span className="text-xs text-muted-foreground">/ 100</span>
        </div>
      </div>
    </div>
  );
}

export function StateDot({ state }: { state: 'passed' | 'failed' | 'unverified' }) {
  const color = state === 'passed' ? 'var(--risk-low)' : state === 'failed' ? 'var(--risk-critical)' : 'var(--muted-foreground)';
  const Icon = state === 'passed' ? CheckCircle2 : state === 'failed' ? MinusCircle : HelpCircle;
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-extrabold tracking-wider" style={{ color }}>
      <Icon size={14} aria-hidden /> {state.toUpperCase()}
    </span>
  );
}

export function VerifyChip({ status }: { status: string }) {
  const color = status === 'verified' ? 'var(--risk-low)' : status === 'mismatch' ? 'var(--risk-critical)' : 'var(--muted-foreground)';
  return (
    <Badge variant="outline" style={softStyle(color)}>
      {status === 'verified' ? <CheckCircle2 /> : status === 'mismatch' ? <AlertTriangle /> : <Info />}
      {status.replace(/-/g, ' ')}
    </Badge>
  );
}

export function FindingSeverity({ severity }: { severity: string }) {
  const color = sevVar[severity] || 'var(--muted-foreground)';
  return (
    <Badge variant="outline" style={softStyle(color)}>
      {severity.toUpperCase()}
    </Badge>
  );
}

export function EmptyState({ icon, title, body, action }: { icon?: ReactNode; title: string; body: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center px-6 py-10 text-center">
      <div className="mb-3 text-primary [&_svg]:size-8">{icon || <Inbox />}</div>
      <h3 className="mb-1.5 font-serif text-lg font-semibold">{title}</h3>
      <p className="mb-3 max-w-md text-sm text-muted-foreground">{body}</p>
      {action}
    </div>
  );
}

export function PageHeader({ title, description, actions }: { title: ReactNode; description?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="max-w-2xl">
        <h1 className="font-serif text-2xl font-bold tracking-tight sm:text-3xl">{title}</h1>
        {description && <p className="mt-1.5 text-sm text-muted-foreground">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}

export function FieldNote({ children, className }: { children: ReactNode; className?: string }) {
  return <p className={cn('text-[13px] text-muted-foreground', className)}>{children}</p>;
}

export { Button };
