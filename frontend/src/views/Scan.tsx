import { ScanLine, Eraser, FlaskConical } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Textarea } from '../components/ui/textarea';
import { Label } from '../components/ui/label';
import { Progress } from '../components/ui/progress';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table';
import { SAMPLES } from '../lib/api';
import LatticeLoader from '../components/LatticeLoader';

export default function ScanView({ url, setUrl, text, setText, loading, progress, onScan, onClear, onSample }:
  { url: string; setUrl: (v: string) => void; text: string; setText: (v: string) => void; loading: boolean; progress: number; onScan: () => void; onClear: () => void; onSample: (i: number) => void }) {
  const canScan = url.trim() !== '' || text.trim() !== '';
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle className="font-serif text-xl">Scan a job listing</CardTitle>
          <CardDescription>Paste a posting URL, the job text, or both. Behavioural evidence outweighs technical polish. Never paste your own Aadhaar, PAN, bank details or OTPs — evidence is redacted by default.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="url">Posting URL</Label>
            <Input id="url" placeholder="https://example.com/careers/apply…" value={url} onChange={(e) => setUrl(e.target.value)} inputMode="url" autoComplete="off" />
          </div>
          <div className="space-y-2">
            <Label htmlFor="txt">Job description / recruiter message</Label>
            <Textarea id="txt" placeholder="Paste the full job ad, WhatsApp message, or email…" value={text} onChange={(e) => setText(e.target.value)} className="min-h-[170px]" />
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button disabled={!canScan || loading} onClick={onScan} aria-busy={loading}>
              <ScanLine /> {loading ? 'Analysing…' : 'Scan for phishing risk'}
            </Button>
            <Button variant="outline" onClick={onClear}><Eraser /> Clear</Button>
            {loading && (
              <LatticeLoader
                status="working"
                label="Analysing"
                color="var(--primary)"
                doneColor="var(--risk-low)"
                errorColor="var(--destructive)"
                className="pl-1 text-muted-foreground"
              />
            )}
          </div>
          {loading && (
            <div role="status" aria-live="polite" className="space-y-2">
              <Progress value={progress} />
              <p className="text-[13px] text-muted-foreground">Running linguistic, behavioural, domain and verification checks…</p>
            </div>
          )}
          <div className="space-y-2">
            <Label className="flex items-center gap-1.5"><FlaskConical size={13} /> Sample cases</Label>
            <div className="flex flex-wrap gap-2">
              {SAMPLES.map((s, i) => (
                <Button key={i} variant="secondary" size="sm" onClick={() => onSample(i)} title={s.note}>{s.name}</Button>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="font-serif text-xl">How scoring works</CardTitle>
          <CardDescription>Transparent weights · behaviour-first floors</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Table>
            <TableHeader><TableRow><TableHead>Category</TableHead><TableHead className="w-16 text-right">Max</TableHead></TableRow></TableHeader>
            <TableBody>
              <TableRow><TableCell>Linguistic &amp; semantic red flags</TableCell><TableCell className="text-right font-bold tabular-nums">35</TableCell></TableRow>
              <TableRow><TableCell>Recruitment behaviour &amp; structure</TableCell><TableCell className="text-right font-bold tabular-nums">30</TableCell></TableRow>
              <TableRow><TableCell>URL &amp; domain anomalies</TableCell><TableCell className="text-right font-bold tabular-nums">15</TableCell></TableRow>
              <TableRow><TableCell>Technical security signals</TableCell><TableCell className="text-right font-bold tabular-nums">10</TableCell></TableRow>
              <TableRow><TableCell>Employer &amp; evidence verification</TableCell><TableCell className="text-right font-bold tabular-nums">10</TableCell></TableRow>
            </TableBody>
          </Table>
          <details className="rounded-xl border bg-background px-4 py-3 text-sm shadow-xs [&_summary]:cursor-pointer [&_summary]:font-semibold">
            <summary>Formula, overrides &amp; risk floors</summary>
            <div className="space-y-2 pt-2 text-[13px] text-muted-foreground">
              <p><b className="text-foreground">total</b> = linguistic + behavioural + domain + technical + employer; <b className="text-foreground">final</b> = max(total, highest floor).</p>
              <ul className="list-disc space-y-1 pl-5">
                <li>OTP / UPI PIN / banking password → floor <b className="text-foreground">80 (Critical)</b></li>
                <li>Payment demanded for job / offer → floor <b className="text-foreground">65 (High)</b></li>
                <li>≥2 credential-harvesting indicators → floor <b className="text-foreground">60 (High)</b></li>
                <li>Valid HTTPS, aged domain, clean reputation <b className="text-foreground">never subtract</b> behavioural risk.</li>
              </ul>
              <p>Bands: 0–19 Low · 20–39 Caution · 40–59 Suspicious · 60–79 High · 80–100 Critical.</p>
            </div>
          </details>
          <p className="text-[13px] text-muted-foreground">Backend adds SSRF-guarded static page inspection (no JS execution). Offline fallback uses the built-in local engine.</p>
        </CardContent>
      </Card>
    </div>
  );
}
