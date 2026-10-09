/**
 * Risk aggregation — transparent weighted scoring + behaviour-first overrides.
 *
 * Formula: total = linguistic(35) + behavioural(30) + domain(15) + technical(10) + employer(10)
 * Each category already normalised to its max by its detector.
 *
 * BEHAVIOUR-FIRST PROTECTION:
 *  1. Technical-trust adjustment is BOUNDED and one-directional: clean HTTPS / aged
 *     domain / clean reputation contribute 0 points but NEVER subtract points.
 *  2. Severity overrides impose RISK FLOORS when strong behavioural evidence exists:
 *     - OTP / UPI PIN / banking password request      -> floor 80 (Critical) + critical warning
 *     - Payment demanded to secure job / release offer -> floor 65 (High) + high warning
 *     - >=2 independent credential-harvesting signals  -> floor 60 (High)
 *     Floors use max(rawTotal, floor). They never fabricate evidence — the
 *     triggering finding is always cited.
 *  3. Documented in code + UI (frontend renders scoring panel from /api/scoring-info).
 *
 * Risk bands: 0-19 Low, 20-39 Caution, 40-59 Suspicious, 60-79 High, 80-100 Critical.
 */
import { analyseLinguistic } from './detectors/linguistic.js';
import { analyseBehaviour } from './detectors/behavioural.js';
import { analyseUrl } from './detectors/urlAnalysis.js';
import { analyseTechnical } from './detectors/technical.js';
import { analyseEmployer } from './detectors/employer.js';

export const WEIGHTS = { linguistic: 35, behavioural: 30, domain: 15, technical: 10, employer: 10 };

export function bandFor(score) {
  if (score >= 80) return { band: 'Critical risk', level: 'critical', color: '#dc2626' };
  if (score >= 60) return { band: 'High risk', level: 'high', color: '#ea580c' };
  if (score >= 40) return { band: 'Suspicious', level: 'suspicious', color: '#d97706' };
  if (score >= 20) return { band: 'Caution', level: 'caution', color: '#ca8a04' };
  return { band: 'Low apparent risk', level: 'low', color: '#16a34a' };
}

export function computeOverrides({ linguistic, behavioural }) {
  const overrides = [];
  // Only CONFIRMED (high/critical) findings can trigger overrides — info-level
  // safety-disclaimer notes must never raise the floor.
  const all = [...(linguistic?.findings || []), ...(behavioural?.findings || [])].filter((f) => ['critical', 'high'].includes(f.severity));
  const has = (frag) => all.some((f) => f.id.includes(frag));

  if (has('otp-critical') || has('otp-pin-harvest')) {
    overrides.push({
      id: 'override-otp', severity: 'critical',
      title: 'Immediate warning: OTP / UPI PIN / banking password requested',
      detail: 'Legitimate recruiters never ask for OTPs, UPI PINs or banking passwords. Stop and do not share these under any circumstance.',
      floor: 80, evidence: all.filter((f) => f.id.includes('otp')).map((f) => f.evidence).slice(0, 2),
    });
  }
  if (has('payment-for-job') || has('fee-job')) {
    overrides.push({
      id: 'override-payment', severity: 'high',
      title: 'High-severity warning: payment demanded to secure employment',
      detail: 'Demanding a registration / security / verification fee for a job or offer release is a hallmark of recruitment fraud in India.',
      floor: 65, evidence: all.filter((f) => f.id.includes('payment') || f.id.includes('fee')).map((f) => f.evidence).slice(0, 2),
    });
  }
  // multiple independent credential-harvesting indicators
  const harvestIds = ['cred-aadhaar', 'cred-pan', 'cred-bank', 'early-sensitive-harvest', 'excessive-collection'];
  const harvestCount = all.filter((f) => harvestIds.some((h) => f.id.includes(h))).length;
  if (harvestCount >= 2 && !overrides.some((o) => o.floor >= 80)) {
    overrides.push({
      id: 'override-harvest-multi', severity: 'high',
      title: `Multiple credential-harvesting indicators (${harvestCount}) elevate risk despite any clean technical signals`,
      detail: 'Independent requests for identity/financial data collectively indicate harvesting.',
      floor: 60, evidence: all.filter((f) => harvestIds.some((h) => f.id.includes(h))).map((f) => f.evidence).slice(0, 3),
    });
  }
  return overrides;
}

export function buildRecommendations(result) {
  const recs = [];
  const sev = new Set(result.allFindings.map((f) => f.severity));
  const hasOtp = result.overrides.some((o) => o.id === 'override-otp');
  const hasPay = result.overrides.some((o) => o.id === 'override-payment');
  if (hasOtp) recs.push('Do NOT share OTPs, UPI PINs, passwords or banking credentials with anyone — no genuine hiring process needs them.');
  if (hasPay) recs.push('Do NOT pay any recruiter to secure a job, release an offer letter, or refund a "verification fee".');
  recs.push('Verify the vacancy through the employer\'s independently located official careers website (type the address yourself; do not click links in the message).');
  recs.push('Contact the employer through independently verified contact information, not the phone/email in the suspicious message.');
  if (result.categories.domain.score > 5) recs.push('Check the domain carefully: look for typosquatting, extra brand words, misleading subdomains, or URL shorteners.');
  if (result.categories.employer.score >= 5) recs.push('Ask the recruiter for verifiable company details (official email domain, CIN/registered office) and cross-check them.');
  recs.push('Report suspected fraud to the National Cybercrime Reporting Portal (cybercrime.gov.in) or call helpline 1930. This is general guidance, not legal advice.');
  if (result.score < 20) recs.push('Low apparent risk does NOT guarantee safety — stay alert for any new requests for money or credentials as the process continues.');
  return recs;
}

const KNOWN_OFFICIAL = ['infosys.com', 'tcs.com', 'wipro.com', 'hcltech.com', 'techmahindra.com', 'reliance.com', 'tata.com', 'tatamotors.com', 'flipkart.com', 'amazon.in', 'amazon.com', 'google.com', 'microsoft.com', 'ibm.com', 'accenture.com', 'cognizant.com', 'icici.com', 'hdfcbank.com', 'sbi.co.in', 'statebankofindia.com', 'naukri.com', 'linkedin.com', 'indeed.com', 'upsc.gov.in', 'ssc.gov.in', 'ibps.in', 'upsconline.nic.in', 'employmentnews.gov.in', 'iitb.ac.in', 'iitd.ac.in'];

/**
 * Derive employer-verification hints from the listing itself so genuine posts
 * that cite official domains / corporate emails get corroborated instead of
 * scoring full "unverified" points. Heuristic + labelled as such in output.
 */
export function deriveEmployerHints({ text = '', url = '' }) {
  const hints = {};
  let host = '';
  try { host = new URL(String(url)).hostname.toLowerCase(); } catch { /* no url */ }
  const t = String(text || '');
  const emails = [...t.matchAll(/[\w.+-]+@([\w.-]+\.[a-z]{2,})/gi)].map((m) => m[1].toLowerCase());
  const corpMail = emails.find((d) => !/gmail|yahoo|rediffmail|outlook|hotmail|protonmail/i.test(d));
  const officialRef = KNOWN_OFFICIAL.find((d) => t.toLowerCase().includes(d));
  if (officialRef && host && (host === officialRef || host.endsWith('.' + officialRef))) {
    hints.officialDomain = officialRef;
    hints.vacancyOnOfficialSite = true;
    hints.vacancyUrl = url;
    hints.applicationDomainLinked = officialRef;
  } else if (officialRef) {
    hints.officialDomain = officialRef; // cited but applied elsewhere -> still a lead
  }
  if (corpMail && host && (host === corpMail || host.endsWith('.' + corpMail) || (officialRef && corpMail === officialRef))) {
    hints.contactMatches = corpMail;
  } else if (corpMail && KNOWN_OFFICIAL.includes(corpMail)) {
    hints.contactMatches = `${corpMail} (known official domain; confirm the sender address independently)`;
  } else if (corpMail) {
    hints.contactPresent = corpMail;
  } else if (emails.length) {
    hints.contactPresent = emails[0];
  }
  if (/(sarkari|सरकारी|शासकीय|govt|government job|upsc|ssc|ibps|railway recruitment)/i.test(t)) {
    hints.govtClaim = true;
    if (host && (/gov\.in$|nic\.in$/.test(host))) hints.govtCorroborated = host;
  }
  return hints;
}

/**
 * Full scan pipeline. Pure + deterministic given identical inputs.
 */
export function runScan({ text = '', url = '', intel = {}, employer = {}, pageText = '' }) {
  const combined = [text, pageText].filter(Boolean).join('\n\n');
  const linguistic = analyseLinguistic(combined);
  const urlRes = analyseUrl(url);
  const behInput = {
    text: combined, url, urlHost: safeHost(url), registrableDomain: urlRes.parsed?.registrableDomain,
    pageText, redirectCrossDomain: Boolean(intel.redirectCrossDomain), finalRegistrable: intel.finalRegistrable,
  };
  const behavioural = analyseBehaviour(behInput);
  const technical = analyseTechnical(intel);
  const autoHints = deriveEmployerHints({ text: combined, url });
  const employerRes = analyseEmployer({ hasUrl: Boolean(url), hasText: Boolean(combined), ...autoHints, ...employer });

  const rawTotal = round1(linguistic.score + behavioural.score + urlRes.score + technical.score + employerRes.score);
  const overrides = computeOverrides({ linguistic, behavioural });
  const floor = overrides.reduce((m, o) => Math.max(m, o.floor || 0), 0);
  const score = Math.min(100, Math.max(rawTotal, floor));
  const band = bandFor(score);
  const allFindings = [...linguistic.findings, ...behavioural.findings, ...urlRes.findings, ...technical.findings, ...employerRes.findings]
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.points - a.points);
  const result = {
    score, band: band.band, level: band.level, color: band.color, rawTotal, floor,
    categories: {
      linguistic: { score: linguistic.score, max: 35 },
      behavioural: { score: behavioural.score, max: 30 },
      domain: { score: urlRes.score, max: 15 },
      technical: { score: technical.score, max: 10 },
      employer: { score: employerRes.score, max: 10 },
    },
    overrides, allFindings,
    counts: { confirmed: allFindings.filter((f) => ['critical', 'high'].includes(f.severity)).length, suspicious: allFindings.filter((f) => f.severity === 'medium').length, info: allFindings.filter((f) => ['low', 'info'].includes(f.severity)).length },
    meta: { urlHost: safeHost(url), registrableDomain: urlRes.parsed?.registrableDomain || null },
  };
  result.recommendations = buildRecommendations(result);
  return result;
}

function safeHost(url) {
  try { return new URL(String(url)).hostname.toLowerCase(); } catch { return ''; }
}
function round1(n) { return Math.round(n * 10) / 10; }
function severityRank(s) { return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s] || 0; }

export const SCORING_DOC = {
  formula: 'total = linguistic(≤35) + behavioural(≤30) + domain(≤15) + technical(≤10) + employer(≤10); final = max(total, maxFloor)',
  weights: WEIGHTS,
  bands: ['0–19 Low apparent risk', '20–39 Caution', '40–59 Suspicious', '60–79 High risk', '80–100 Critical risk'],
  overrides: [
    { when: 'OTP / UPI PIN / banking password requested', floor: 80, severity: 'critical' },
    { when: 'Payment demanded to secure job / release offer', floor: 65, severity: 'high' },
    { when: '≥2 independent credential-harvesting indicators', floor: 60, severity: 'high' },
  ],
  behaviourFirst: 'Technical trust (HTTPS, domain age, clean reputation) only adds risk for negative signals and can never subtract behavioural risk. Unknown checks count as unknown, not safe.',
};
