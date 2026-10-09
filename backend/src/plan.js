/**
 * Safe Apply action planner (Safe Apply Assistant).
 * Builds verdict + explanation + next steps SOLELY from the scan's evidence
 * records (findings, overrides, verification, checklist). No generic fillers:
 * every step cites the finding/verification ids it was derived from.
 * Verdicts: 'avoid' (Avoid This Listing) | 'verify' (Verify Employer) |
 * 'proceed' (Proceed Carefully). There is deliberately no "safe" verdict —
 * low risk never guarantees legitimacy.
 */
import { excerpt } from './utils/redact.js';

const WHY_TEMPLATES = {
  'override-otp': 'it asks for OTPs, UPI PINs or banking passwords, which legitimate recruiters never request',
  'override-payment': 'it demands payment (registration/security/verification fee) to secure the job or release the offer',
  'override-harvest-multi': 'it independently requests multiple types of sensitive identity/financial data, indicating credential harvesting',
};

export function buildVerdict(scan) {
  const confirmed = (scan.allFindings || []).filter((f) => ['critical', 'high'].includes(f.severity));
  if (scan.score >= 60 || confirmed.some((f) => f.severity === 'critical')) return { verdict: 'avoid', label: 'Avoid This Listing', reason: 'critical/high-severity evidence or high risk score' };
  if (scan.score >= 40 || confirmed.length > 0) return { verdict: 'verify', label: 'Verify Employer', reason: 'suspicious signals require independent verification before any further step' };
  const unverified = (scan.allFindings || []).filter((f) => f.severity === 'info' && /unknown|unverif|could not be/i.test(f.title)).length;
  if (unverified >= 2) return { verdict: 'verify', label: 'Verify Employer', reason: 'key facts could not be independently confirmed' };
  return { verdict: 'proceed', label: 'Proceed Carefully', reason: 'no strong fraud evidence, but low risk does not guarantee safety' };
}

/** Plain-language explanation assembled from the top confirmed findings. */
export function explainWhy(scan) {
  const confirmed = (scan.allFindings || []).filter((f) => ['critical', 'high'].includes(f.severity)).slice(0, 3);
  if (!confirmed.length) {
    if (scan.score >= 20) return 'Several weaker signals were found, but nothing conclusive. Treat the listing as unproven and verify the employer independently.';
    return 'No strong fraud evidence was detected in this listing. That is reassuring but not a guarantee — verify the employer and stay alert for later money or credential requests.';
  }
  const bits = confirmed.map((f) => {
    const o = (scan.overrides || []).find((x) => (x.evidence || []).some((e) => e && f.evidence && e.slice(0, 30) === f.evidence.slice(0, 30)));
    if (o && WHY_TEMPLATES[o.id]) return WHY_TEMPLATES[o.id];
    return `it shows “${f.title.charAt(0).toLowerCase() + f.title.slice(1)}”`;
  });
  return `This listing may be unsafe because ${bits.join('; and ')}.`;
}

function has(scan, frag, sevs = ['critical', 'high']) {
  return (scan.allFindings || []).filter((f) => f.id.includes(frag) && sevs.includes(f.severity));
}

/** Contextual next steps — each grounded in finding/verification ids. */
export function buildSteps({ scan, verification, checklist, mode = 'listing' }) {
  const steps = [];
  const add = (title, detail, derivedFrom, priority = 'normal') => steps.push({ title, detail, derivedFrom, priority });
  const otp = [...has(scan, 'otp-critical'), ...has(scan, 'otp-pin-harvest')];
  const pay = [...has(scan, 'payment-for-job'), ...has(scan, 'fee-job')];
  const harvest = [...has(scan, 'early-sensitive-harvest'), ...has(scan, 'cred-aadhaar'), ...has(scan, 'cred-pan'), ...has(scan, 'cred-bank'), ...has(scan, 'excessive-collection')];
  const domain = [...has(scan, 'typosquat'), ...has(scan, 'misleading-subdomain'), ...has(scan, 'brand-identity-mismatch'), ...has(scan, 'brand-contains-mismatch'), ...has(scan, 'homoglyph'), ...has(scan, 'shortener'), ...has(scan, 'ip-host')];

  if (pay.length) add('Do not pay any money', 'Do not pay registration, security, verification or training fees by UPI, QR or transfer — genuine employers in India do not charge candidates to hire them. Break contact if payment is insisted upon.', pay.map((f) => f.id), 'urgent');
  if (otp.length) add('Do not share OTPs, PINs or passwords', 'Never share OTPs, UPI PINs, CVV, netbanking or card passwords. No genuine hiring step needs them — not even for “verification” or “salary activation”.', otp.map((f) => f.id), 'urgent');
  if (harvest.length) add('Do not send identity/financial documents yet', 'Do not share Aadhaar, PAN, bank details, passbook or card copies at this application stage. Such documents, if ever needed, are verified in person after a provisional offer — never over WhatsApp/Telegram forms.', harvest.map((f) => f.id), 'urgent');
  if (domain.length) {
    const ev = domain[0];
    add('Check the web address character by character', `“${ev.title}.” Open the employer's real site by typing its address yourself; do not click links in the message. A familiar brand name in a link does not make it official.`, domain.map((f) => f.id));
  }
  if (verification?.overall === 'mismatch') add('Resolve the identity mismatch', verification.checks.filter((c) => c.status === 'mismatch').map((c) => `Mismatch: ${c.label} — ${c.evidence}`).join(' ').slice(0, 280) + ' Contact the company through independently found details before continuing.', ['verify:domain-comparison', 'verify:recruiter-email']);
  if (verification?.overall === 'could-not-verify') add('Verify the employer independently', `Independently locate the official website${verification.officialDomain ? ` (directory lead: ${verification.officialDomain})` : ''} and confirm this vacancy there or with HR reached via official contact details — not the phone/email in this message.`, ['verify:official-website', 'verify:vacancy-corroboration']);
  if (verification?.overall === 'verified') add('Keep the verified trail', 'You have partial independent corroboration — still apply only through the official channel and re-check if anyone later asks for money or credentials.', ['verify:domain-comparison', 'verify:vacancy-corroboration']);
  if (has(scan, 'offchannel', ['medium', 'high', 'critical']).length) add('Stay on official channels', 'Do not move the conversation to personal WhatsApp/Telegram accounts or install apps/APKs the recruiter sends. Keep communication on the official portal or corporate email.', has(scan, 'offchannel', ['medium', 'high', 'critical']).map((f) => f.id));
  if (has(scan, 'urgency', ['medium', 'high', 'critical']).length || has(scan, 'guarantee-salary', ['medium', 'high']).length) add('Slow down — pressure is a tactic', 'Countdowns, “last chance” offers and guaranteed high salaries without interviews are pressure tactics. A real offer will survive you taking a day to verify it.', [...has(scan, 'urgency', ['medium', 'high', 'critical']), ...has(scan, 'guarantee-salary', ['medium', 'high'])].map((f) => f.id));
  const failedChecks = (checklist?.items || []).filter((i) => i.state === 'failed');
  if (!steps.length && failedChecks.length) add('Work through the failed safety checks', failedChecks.map((c) => c.label).join('; ').slice(0, 260), failedChecks.map((c) => c.id));
  if (!steps.length) add('Apply standard caution', mode === 'message' ? 'Even without red flags: verify the sender independently, keep communication on official channels, and never share money or credentials.' : 'Even without red flags: verify the vacancy on the official careers site, use official contact details, and never share money or credentials during application.', []);
  return steps;
}

/** PII protection summary grouped by data category, from actual findings. */
export function buildProtection(scan) {
  const F = (scan.allFindings || []);
  const pick = (frags, sevs) => F.filter((f) => frags.some((g) => f.id.includes(g)) && (!sevs || sevs.includes(f.severity)));
  const groups = [
    { id: 'aadhaar-pan', label: 'Aadhaar & PAN', risk: 'Sharing enables identity theft and SIM/bank fraud in your name.', findings: pick(['cred-aadhaar', 'cred-pan', 'early-sensitive-harvest']) },
    { id: 'bank-cards', label: 'Bank accounts & cards', risk: 'Account numbers, IFSC, passbook/cheque copies and card details enable unauthorised withdrawals.', findings: pick(['cred-bank', 'early-sensitive-harvest']) },
    { id: 'otp-pin', label: 'OTPs, UPI PINs & passwords', risk: 'Never share — these authorise transactions instantly and cannot be undone. No hiring step needs them.', findings: pick(['otp-critical', 'otp-pin-harvest']) },
    { id: 'documents', label: 'Identity documents & uploads', risk: 'Photos, signatures, passports and salary slips fuel impersonation. Share only in person, after a provisional offer, through official channels.', findings: pick(['excessive-collection', 'early-sensitive-harvest']) },
    { id: 'payments', label: 'Fees & deposits', risk: 'Registration, security, training or “refundable” fees for a job are a hallmark of recruitment fraud. Do not pay.', findings: pick(['payment-for-job', 'fee-job']) },
  ];
  return groups.map((g) => ({
    ...g,
    status: g.findings.some((f) => ['critical', 'high'].includes(f.severity)) ? 'requested' : g.findings.length ? 'mentioned' : 'not-detected',
    findings: g.findings.map((f) => ({ id: f.id, severity: f.severity, title: f.title, evidence: f.evidence })),
  }));
}

/**
 * Highlight spans in the ORIGINAL text for the red-flag highlighter.
 * Derived from each finding's own evidence (longest stable chunk located in
 * the source, expanded to sentence boundaries) — display-only, no new verdicts.
 */
export function buildHighlights(text, findings) {
  const src = String(text || '');
  const slow = src.toLowerCase();
  const out = [];
  for (const f of findings || []) {
    if (!['critical', 'high', 'medium'].includes(f.severity)) continue;
    // Longest redaction-tolerant substring of the evidence present in source.
    const clean = String(f.evidence || '')
      .replace(/X{3,}(?:[-\s]*X{3,})*/g, ' ')
      .replace(/\[REDACTED-[A-Z-]+\]/g, ' ')
      .replace(/•+/g, ' ')
      .replace(/\s+/g, ' ').trim();
    let hit = null;
    for (let len = Math.min(70, clean.length); len >= 25 && !hit; len -= 5) {
      for (let i = 0; i + len <= clean.length && !hit; i += 10) {
        const probe = clean.slice(i, i + len).toLowerCase();
        if (/[a-z\u0900-\u097f]{4}/.test(probe)) {
          const idx = slow.indexOf(probe);
          if (idx >= 0) hit = { idx, len };
        }
      }
    }
    if (!hit) continue;
    // expand to sentence boundaries
    const before = src.slice(0, hit.idx);
    const bs = Math.max(before.lastIndexOf('. '), before.lastIndexOf('।'), before.lastIndexOf('\n'), before.lastIndexOf('! '), before.lastIndexOf('? '));
    const start = bs < 0 ? Math.max(0, hit.idx - 40) : bs + 1;
    const after = src.slice(hit.idx);
    const m = after.match(/[.!?।\n]/);
    const end = m && m.index !== undefined ? hit.idx + Math.min(m.index + 1, 280) : Math.min(src.length, hit.idx + 160);
    out.push({
      findingId: f.id, category: f.category, severity: f.severity,
      title: f.title, why: WHY_MAP[f.id] || whyFor(f), recommendation: REC_MAP[f.id] || recFor(f),
      quote: excerpt(src.slice(start, end).trim(), 280), start, end,
    });
  }
  // de-duplicate overlapping spans (keep higher severity)
  const rank = { critical: 3, high: 2, medium: 1 };
  out.sort((a, b) => a.start - b.start || rank[b.severity] - rank[a.severity]);
  return out.filter((h, i) => !out.slice(0, i).some((p) => h.start < p.end - 10 && h.end > p.start + 10));
}

const WHY_MAP = {
  'ling-fee-job': 'Genuine employers do not charge candidates to hire them. Upfront or “refundable” fees are the classic advance-fee job scam.',
  'beh-payment-for-job': 'Payment demanded to release a job or offer letter is a hallmark of recruitment fraud.',
  'ling-cred-otp-critical': 'OTPs, UPI PINs and banking passwords authorise money movement. No hiring step ever needs them.',
  'beh-otp-pin-harvest': 'Requests for OTPs/PINs/passwords during hiring are credential harvesting, not verification.',
  'ling-cred-aadhaar': 'Aadhaar enables identity theft. Early collection before the employer is verified indicates harvesting.',
  'ling-cred-pan': 'PAN misuse enables financial fraud. It is never needed at the application stage.',
  'ling-cred-bank': 'Bank/card details at application stage enable unauthorised withdrawals.',
  'beh-early-sensitive-harvest': 'Sensitive documents requested before employer identity is established indicate harvesting.',
};
function whyFor(f) {
  if (f.category === 'domain') return 'The web address itself shows deception markers (lookalike spelling, misleading subdomain, shortener), independent of page content.';
  if (f.category === 'technical') return 'Infrastructure signals (missing HTTPS, long redirects, threat-listing) raise caution but never decide alone.';
  if (f.category === 'employer') return 'The employer connection could not be independently corroborated — uncertainty to resolve, not proof of fraud.';
  if (f.id.includes('urgency')) return 'Countdowns and threats of losing the offer are pressure tactics to stop you verifying.';
  if (f.id.includes('offchannel')) return 'Moving you to personal chat apps evades official records and verification.';
  if (f.id.includes('guarantee')) return 'Guaranteed jobs and disproportionate salaries without a selection process are bait.';
  return 'This behaviour deviates from standard, verifiable hiring practice.';
}
const REC_MAP = {
  'ling-fee-job': 'Do not pay. Independently verify the recruiter and report fee demands.',
  'beh-payment-for-job': 'Do not pay. Break contact if payment is insisted upon.',
  'ling-cred-otp-critical': 'Do not share. End the conversation if pressed.',
  'beh-otp-pin-harvest': 'Do not share any OTP, PIN or password.',
  'ling-cred-aadhaar': 'Do not share Aadhaar now; in-person verification only after a provisional offer.',
  'ling-cred-pan': 'Do not share PAN at this stage.',
  'ling-cred-bank': 'Do not share bank/card details during application.',
};
function recFor(f) {
  if (f.category === 'domain') return 'Type the official address yourself; do not click message links.';
  if (f.category === 'employer') return 'Corroborate through the official careers page or HR.';
  return 'Pause, verify independently, and do not share money or credentials.';
}

/** Guidance for users who already shared information (shown on demand in UI). */
export function alreadySharedGuidance(scan) {
  const money = (scan.allFindings || []).some((f) => /otp|upi|bank|card|cvv|password|payment|fee/i.test(f.id) && f.severity !== 'info');
  return {
    money: money
      ? 'You may have exposed financial credentials. Immediately: (1) call your bank’s official customer-care number (from the bank website or card, not the recruiter) to block/freeze affected accounts and cards; (2) change UPI PIN and netbanking passwords from the official app; (3) review recent transactions and dispute unknown ones in writing.'
      : 'If you shared any financial details (OTP, PIN, card, bank login) or paid money: call your bank immediately via its official helpline to freeze/block, reset credentials from the official app, and dispute unknown transactions.',
    identity: 'If you shared Aadhaar, PAN or document copies: (1) lock your Aadhaar biometrics via myaadhaar.uidai.gov.in; (2) monitor for misuse — check your CIBIL/credit report and watch for unknown SIMs or accounts; (3) keep copies of everything the recruiter sent.',
    report: 'Report the fraud at the National Cybercrime Reporting Portal — https://cybercrime.gov.in — or call the national cybercrime helpline 1930. Preserve message screenshots, UPI transaction IDs, phone numbers and URLs. General guidance, not legal advice.',
  };
}

/** Recommended reply for a recruiter message, by channel + findings. */
export function recommendedResponse({ scan, channel }) {
  const danger = scan.score >= 40 || (scan.allFindings || []).some((f) => ['critical', 'high'].includes(f.severity));
  const where = { whatsapp: 'WhatsApp', email: 'email', offer: 'offer letter', interview: 'interview invitation', payment: 'payment request' }[channel] || 'message';
  if (danger) return `Do not reply with any money, documents, OTPs or credentials. Safe response: “I apply only through official company channels. Please share your corporate email ID and the vacancy link on the company’s official careers page so I can verify and proceed there.” Then verify independently — and report at cybercrime.gov.in / 1930 if fraud is confirmed. This ${where} shows strong fraud signals (score ${scan.score}/100).`;
  return `No strong fraud signals (score ${scan.score}/100), but stay cautious. Safe response: “Thanks — I’ll verify this vacancy on the company’s official careers page and continue there. Please share your official contact details.” Never share OTPs, PINs or fees at any stage.`;
}

export function buildSafeApply({ scan, verification, checklist, text = '', mode = 'listing', channel = null }) {
  const verdict = buildVerdict(scan);
  return {
    mode, verdict: verdict.verdict, verdictLabel: verdict.label, verdictReason: verdict.reason,
    score: scan.score, band: scan.band, level: scan.level, color: scan.color,
    whyUnsafe: explainWhy(scan),
    steps: buildSteps({ scan, verification, checklist, mode }),
    checklist, verification,
    protection: buildProtection(scan),
    highlights: buildHighlights(text, scan.allFindings || []),
    alreadyShared: alreadySharedGuidance(scan),
    recommendedResponse: mode === 'message' ? recommendedResponse({ scan, channel }) : null,
  };
}
