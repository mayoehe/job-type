import { MessageSquareText, Eraser, Send } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Textarea } from '../components/ui/textarea';
import { Label } from '../components/ui/label';
import { Badge } from '../components/ui/badge';
import { RiskBadge, ScoreRing, FindingSeverity, EmptyState, FieldNote, sevVar, riskVar } from '../components/ui';
import type { ScanResultFull } from '../lib/api';

const CHANNELS = [
  { id: 'whatsapp', label: 'WhatsApp' },
  { id: 'email', label: 'Email' },
  { id: 'offer', label: 'Offer letter' },
  { id: 'interview', label: 'Interview invite' },
  { id: 'payment', label: 'Payment request' },
];
const MSG_SAMPLES = [
  { name: 'Scam WhatsApp (Hinglish)', channel: 'whatsapp', text: 'Dear Candidate, apki selection ho gayi hai! ₹85000 salary, no interview. ₹2499 refundable fee UPI par bhejo aur Aadhaar + OTP WhatsApp par share karo. Offer sirf 2 hours ke liye!' },
  { name: 'Scam fee email', channel: 'email', text: 'Congratulations! You are selected for the back-office role. To release your appointment letter, pay Rs 1500 verification fee via the QR code attached and reply with your PAN card and bank details. HR Team (Gmail).' },
  { name: 'Genuine interview invite', channel: 'email', text: 'Hello, thank you for your application for Senior React Developer. We would like to invite you for a technical interview on Monday 11am at our Bengaluru office (address below) or over Google Meet. Please confirm your availability. No fees are involved at any stage. Regards, Priya Sharma, careers@company.com.' },
];

export function MessageForm({ channel, setChannel, msgText, setMsgText, loading, onScan, onClear, onSample }:
  { channel: string; setChannel: (v: string) => void; msgText: string; setMsgText: (v: string) => void; loading: boolean; onScan: () => void; onClear: () => void; onSample: (s: { channel: string; text: string }) => void }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 font-serif text-xl"><MessageSquareText size={18} className="text-primary" /> Recruiter message scanner</CardTitle>
        <CardDescription>Same detection engine, text-only. Nothing is sent to AI services — analysis stays local.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-2">
          <Label>Message type</Label>
          <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="Message type">
            {CHANNELS.map((c) => (
              <Button
                key={c.id} role="radio" aria-checked={channel === c.id} size="sm"
                variant={channel === c.id ? 'default' : 'secondary'}
                onClick={() => setChannel(c.id)}
              >
                {c.label}
              </Button>
            ))}
          </div>
        </div>
        <div className="space-y-2">
          <Label htmlFor="msg">Message text</Label>
          <Textarea id="msg" placeholder="Paste the WhatsApp message, email, offer letter, invite or payment request…" value={msgText} onChange={(e) => setMsgText(e.target.value)} className="min-h-[170px]" />
        </div>
        <div className="flex flex-wrap gap-2">
          <Button disabled={!msgText.trim() || loading} onClick={onScan} aria-busy={loading}>
            <Send /> {loading ? 'Analysing…' : 'Analyse message'}
          </Button>
          <Button variant="outline" onClick={onClear}><Eraser /> Clear</Button>
        </div>
        <div className="space-y-2">
          <Label>Samples</Label>
          <div className="flex flex-wrap gap-2">
            {MSG_SAMPLES.map((s, i) => <Button key={i} variant="secondary" size="sm" onClick={() => onSample(s)}>{s.name}</Button>)}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export function MessageResult({ result }: { result: ScanResultFull }) {
  const sa = result.safeApply;
  const levelColor = riskVar[result.level] || result.color;
  return (
    <Card style={{ borderColor: `color-mix(in srgb, ${levelColor} 55%, transparent)` }}>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <CardTitle className="font-serif text-xl">Message analysis</CardTitle>
          <Badge variant="secondary">{sa?.channel || 'message'}</Badge>
          <RiskBadge level={result.level} band={result.band} />
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-center gap-5">
          <ScoreRing score={result.score} color={levelColor} />
          <p className="min-w-[220px] flex-1 text-sm">{sa?.whyUnsafe}</p>
        </div>
        {result.overrides.map((o) => (
          <div key={o.id} className="rounded-xl border border-destructive/50 bg-destructive/10 px-4 py-3 text-sm shadow-xs">
            <b>⚠ {o.title}</b>
            <FieldNote>{o.detail}</FieldNote>
          </div>
        ))}
        {sa?.recommendedResponse && (
          <div>
            <h3 className="mb-2 text-sm font-semibold">Recommended response</h3>
            <div className="rounded-xl border bg-background px-4 py-3 text-sm shadow-xs" style={{ borderLeft: '3px solid var(--primary)' }}>
              {sa.recommendedResponse}
            </div>
          </div>
        )}
        <div>
          <h3 className="mb-2 text-sm font-semibold">Next steps</h3>
          <ol className="list-decimal space-y-2.5 pl-5 text-sm">
            {(sa?.steps || []).map((s, i) => (
              <li key={i} className={s.priority === 'urgent' ? 'rounded-r-lg border-l-[3px] border-destructive pl-2.5' : ''}>
                <b>{s.title}</b>
                <FieldNote>{s.detail}</FieldNote>
              </li>
            ))}
          </ol>
        </div>
        <div>
          <h3 className="mb-2 text-sm font-semibold">Evidence</h3>
          {result.allFindings.filter((f) => f.severity !== 'info').length === 0 && (
            <EmptyState title="No significant flags" body="Stay cautious and verify the sender through official channels." />
          )}
          <div className="space-y-2">
            {result.allFindings.filter((f) => f.severity !== 'info').map((f) => (
              <div key={f.id} className="rounded-xl border bg-background px-4 py-3 shadow-xs" style={{ borderLeft: `3px solid ${sevVar[f.severity] || 'var(--muted-foreground)'}` }}>
                <div className="flex flex-wrap items-center gap-2">
                  <FindingSeverity severity={f.severity} /> <b className="text-[13.5px]">{f.title}</b>
                </div>
                <div className="mt-2 whitespace-pre-wrap rounded-md border border-dashed bg-card px-3 py-2 font-mono text-xs text-muted-foreground">{f.evidence}</div>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
