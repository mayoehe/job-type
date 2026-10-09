import type { ScanResult } from './engine';
import { localScan } from './engine';

export interface SafeApplyStep { title: string; detail: string; derivedFrom: string[]; priority: string; }
export interface ChecklistItem { id: string; label: string; state: 'passed' | 'failed' | 'unverified'; auto: boolean; detail: string; derivedFrom: string[]; }
export interface VerifyCheck { id: string; label: string; status: 'verified' | 'mismatch' | 'could-not-verify'; evidence: string; source: string; }
export interface Highlight { findingId: string; category: string; severity: string; title: string; why: string; recommendation: string; quote: string; start: number; end: number; }
export interface ProtectionGroup { id: string; label: string; risk: string; status: 'requested' | 'mentioned' | 'not-detected'; findings: { id: string; severity: string; title: string; evidence: string }[]; }
export interface SafeApply {
  mode: string; verdict: 'avoid' | 'verify' | 'proceed'; verdictLabel: string; verdictReason: string;
  score: number; band: string; level: string; color: string; whyUnsafe: string;
  steps: SafeApplyStep[];
  checklist: { items: ChecklistItem[]; counts: { passed: number; failed: number; unverified: number }; total: number };
  verification: { claimedEmployer: string | null; claimedPosition: string | null; officialDomain: string | null; careersUrl: string | null; listingDomain: string | null; isPlatform: boolean; overall: string; checks: VerifyCheck[]; source: string } | null;
  protection: ProtectionGroup[];
  highlights: Highlight[];
  alreadyShared: { money: string; identity: string; report: string };
  recommendedResponse: string | null;
  channel?: string;
}
export type ScanResultFull = ScanResult & { safeApply?: SafeApply | null };

export const SAMPLES: { name: string; kind: string; url: string; text: string; note: string }[] = [
  {
    name: 'Critical: OTP + fee scam (Hinglish)',
    kind: 'fraud',
    url: 'https://secure-naukri-verification.xyz/infosys-careers/apply?token=abc123sessionid99verify1',
    text: 'Dear Candidate, Congratulations! Your resume selected for Infosys Work From Home Data Entry. Salary ₹85000 per month, no interview, instant selection! Pay refundable registration fee ₹2499 via UPI and share your Aadhaar card, PAN card, bank account + OTP on WhatsApp to confirm offer within 2 hours. Last chance, act immediately! Contact on WhatsApp only.',
    note: 'Technically polished look, fraudulent behaviour → must stay Critical.',
  },
  {
    name: 'High: refundable govt-job fee (Hindi)',
    kind: 'fraud',
    url: 'https://sarkari-job-apply.club/railway-bharti-2026',
    text: 'सरकारी नौकरी! रेलवे में सीधी भर्ती, बिना परीक्षा नौकरी पक्की। रजिस्ट्रेशन फीस ₹1500 (refundable) UPI से भरो और आधार नंबर, बैंक विवरण WhatsApp पर भेजो। तुरंत apply करो, offer expires today!',
    note: 'Fake govt portal on non-gov domain.',
  },
  {
    name: 'High: Telegram + APK scam (Marathi)',
    kind: 'fraud',
    url: 'http://192.168.1.10/tcs-jobs', // note: blocked for live inspect; structure still scores
    text: 'TCS मध्ये घरबसल्या नोकरी, महिना ₹75000! Interview नाही, direct joining. आधी नोंदणी शुल्क ₹999 भरा आणि आधार कार्ड, PAN, बँक तपशील Telegram वर पाठवा. App download करून OTP sanga. तातडीने apply करा!',
    note: 'IP host + off-channel + fee + OTP.',
  },
  {
    name: 'Low: genuine private listing',
    kind: 'legit',
    url: 'https://www.infosys.com/careers/',
    text: 'Infosys is hiring a Senior React Developer in Bengaluru. Requirements: 4+ years experience, strong TypeScript, system design. Selection: online assessment, two technical interviews, HR round. Apply only via our official careers portal. We never ask for fees, OTPs or bank details during application. Contact: careers@infosys.com.',
    note: 'Appropriate-stage process, no money/credential requests.',
  },
  {
    name: 'Low: genuine govt listing',
    kind: 'legit',
    url: 'https://www.upsc.gov.in/',
    text: 'Union Public Service Commission advertisement for Civil Services Examination. Eligibility, syllabus and schedule per official notification. Apply online at upsconline.nic.in before the notified closing date. No application fee is collected over WhatsApp or Telegram.',
    note: 'Official domain + proper channel.',
  },
  {
    name: 'Caution: incomplete listing, unknown signals',
    kind: 'edge',
    url: '',
    text: 'Hiring delivery executives in Pune. Salary depends on shifts. Walk in with resume on Saturday.',
    note: 'Sparse info → uncertainty, not fraud.',
  },
];

/** API base: user override from Settings wins, else build-time env, else same-origin (dev proxy). */
export function apiBase(): string {
  try {
    const ov = localStorage.getItem('jobshield.apiBase');
    if (ov !== null) return ov.replace(/\/$/, '');
  } catch { /* storage unavailable */ }
  const env = (import.meta as unknown as { env: Record<string, string | undefined> }).env?.VITE_API_URL;
  return (env || '').replace(/\/$/, '');
}

export async function scanViaBackend(url: string, text: string): Promise<ScanResultFull | null> {
  const base = apiBase();
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 30000);
    const res = await fetch(base + '/api/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, text }), signal: ctrl.signal,
    }).finally(() => clearTimeout(t));
    if (!res.ok) return null;
    return (await res.json()) as ScanResultFull;
  } catch {
    return null;
  }
}

export async function scanMessageBackend(text: string, channel: string): Promise<ScanResultFull | null> {
  const base = apiBase();
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 30000);
    const res = await fetch(base + '/api/message', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text, channel }), signal: ctrl.signal,
    }).finally(() => clearTimeout(t));
    if (!res.ok) return null;
    return (await res.json()) as ScanResultFull;
  } catch {
    return null;
  }
}

/**
 * Minimal offline Safe Apply synthesis from the local engine result.
 * Clearly labelled local-only: verdict + steps from local findings, checklist
 * left unverified where live verification is impossible.
 */
export function localSafeApply(result: ScanResult, text: string): SafeApply {
  const confirmed = result.allFindings.filter((f) => ['critical', 'high'].includes(f.severity));
  const verdict = (result.score >= 60 || confirmed.some((f) => f.severity === 'critical')) ? 'avoid' : (result.score >= 40 || confirmed.length > 0) ? 'verify' : 'proceed';
  const labels = { avoid: 'Avoid This Listing', verify: 'Verify Employer', proceed: 'Proceed Carefully' } as const;
  const item = (id: string, label: string, state: ChecklistItem['state'], detail: string, derivedFrom: string[]): ChecklistItem => ({ id, label, state, auto: true, detail, derivedFrom });
  const has = (frag: string) => confirmed.some((f) => f.id.includes(frag));
  const items: ChecklistItem[] = [
    item('official-site', "Independently locate the employer's official website", 'unverified', 'Offline mode: locate the official site yourself.', []),
    item('vacancy', 'Confirm the vacancy through the official careers page or recruiter', 'unverified', 'Offline mode: confirm on the official careers page.', []),
    item('app-domain', 'Verify the application domain is legitimately associated with the employer', has('typosquat') || has('mismatch') || has('homoglyph') ? 'failed' : (result.meta.urlHost ? 'unverified' : 'unverified'), 'Derived from local URL-structure analysis.', []),
    item('recruiter', 'Confirm the recruiter’s identity using independently obtained contact info', has('recruiter-domain-mismatch') ? 'failed' : 'unverified', 'Derived from local analysis.', []),
    item('fees', 'Check whether any recruitment or interview fees are requested', has('payment') || has('fee-job') ? 'failed' : 'passed', 'Derived from local text analysis.', []),
    item('pii-collection', 'Review what personal information the application collects', has('aadhaar') || has('cred-pan') || has('cred-bank') || has('harvest') ? 'failed' : 'passed', 'Derived from local text analysis.', []),
    item('otp', 'Confirm that no OTP, UPI PIN, or banking password is requested', has('otp') ? 'failed' : 'passed', 'Derived from local text analysis.', []),
    item('offer-consistency', 'Review the offer letter and instructions for inconsistencies', result.score >= 40 ? 'unverified' : 'passed', 'Derived from local text analysis.', []),
  ];
  void text;
  return {
    mode: 'listing', verdict, verdictLabel: labels[verdict], verdictReason: 'Offline estimate from local engine — connect the backend for verification.',
    score: result.score, band: result.band, level: result.level, color: result.color,
    whyUnsafe: confirmed.length ? `Local analysis found ${confirmed.length} high-severity signal(s): ${confirmed.slice(0, 3).map((f) => f.title).join('; ')}.` : 'No strong fraud evidence in local analysis. Not a guarantee — verify independently.',
    steps: result.recommendations.map((r) => ({ title: r.split('.')[0].slice(0, 60), detail: r, derivedFrom: ['local-engine'], priority: 'normal' })),
    checklist: { items, counts: { passed: items.filter((i) => i.state === 'passed').length, failed: items.filter((i) => i.state === 'failed').length, unverified: items.filter((i) => i.state === 'unverified').length }, total: items.length },
    verification: null, protection: [], highlights: [],
    alreadyShared: { money: 'If you shared financial details, call your bank immediately via its official helpline.', identity: 'If you shared documents, lock Aadhaar biometrics via myaadhaar.uidai.gov.in and monitor for misuse.', report: 'Report at https://cybercrime.gov.in or call 1930.' },
    recommendedResponse: null,
  };
}

export { localScan };
