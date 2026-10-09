/**
 * B. Recruitment behaviour & structural analysis — max 30 points.
 * Distinguishes genuine hiring steps from credential harvesting:
 *  - OTP / UPI PIN / banking password / payment-for-job => severe, regardless of stage.
 *  - Document requests (Aadhaar/PAN/bank) are scored by STAGE: early/unknown stage
 *    without established employer identity = high; late stage with verified employer = low.
 */
import { excerpt } from '../utils/redact.js';
import { hasNegationAround } from './linguistic.js';

export const MAX = 30;

const KNOWN_BRANDS = [
  'infosys', 'tcs', 'wipro', 'hcl', 'techmahindra', 'reliance', 'tata', 'tata motors',
  ' Flipkart'.trim(), 'amazon', 'google', 'microsoft', 'ibm', 'accenture', 'cognizant',
  'icici', 'hdfc', 'sbi', 'axis', 'maruti', 'hindustan unilever', 'isro', 'railway',
  'ssc', 'upsc', 'ibps', 'naukri', 'linkedin', 'indeed',
];

export function detectBrandMentions(text) {
  const t = String(text || '').toLowerCase();
  return KNOWN_BRANDS.filter((b) => t.includes(b));
}

function hasEmployerIdentityEstablished({ text, urlHost, employerHints }) {
  const t = String(text || '').toLowerCase();
  const signals = [
    /about (us|the company)/i, /founded in \d{4}/i, /cin\s*[:\-]?\s*[lu]\d{5}/i,
    /registered office/i, /careers@|hr@|jobs@/i, /www\.[a-z0-9\-]+\.(com|in|org)/i,
    /interview\s+(venue|address|schedule)/i,
  ];
  let score = 0;
  for (const s of signals) if (s.test(t)) score++;
  if (employerHints && employerHints.officialDomain) score += 2;
  if (urlHost && /gov\.in$|nic\.in$|\.ac\.in$/.test(urlHost)) score += 1;
  return score >= 2;
}

/**
 * @param {Object} input { text, url, urlHost, registrableDomain, pageText, employerHints }
 */
export function analyseBehaviour(input = {}) {
  const text = String(input.text || input.pageText || '');
  const t = text.toLowerCase();
  const findings = [];
  const signals = {};
  let raw = 0;
  const add = (id, severity, title, evidence, weight) => {
    raw += weight;
    findings.push({ id: `beh-${id}`, category: 'behavioural', severity, title, evidence: excerpt(evidence), points: weight });
    signals[id] = true;
  };

  const identityEstablished = hasEmployerIdentityEstablished({ text, urlHost: input.urlHost, employerHints: input.employerHints });

  // A fee mention is only a "demand" when paired with payment-action context.
  // Strong cues: explicit pay words, UPI/QR rails, currency, refundable, demand verbs.
  // "Salary via bank transfer" payroll language is deliberately NOT a cue.
  const DEMAND_CUE = /\b(pay|paid|payable|deposit|upi|qr|phonepe|gpay|paytm|refundable|₹|\brs\.?\b|\binr\b|भरो|भरा|bhejo|bhej|pay karo)\b/i;
  const NO_FEE_DISCLAIMER = /\bno\s+(fees?|charges?|advance|payment|money)\b|without\s+(any\s+)?(fees?|charge|payment|advance)/i;
  const STRONG_CUE = /\bpay\b|upi|qr|₹|\brs\.?\b|\binr\b|refundable|bhejo|bhej|भरो|भरा/i;
  // B1: payment to secure employment — always severe (unless safety disclaimer)
  // NOTE: \bpay\b (word boundary) so "payment gateway" alone never matches.
  const payMatch = text.match(/(refundable|registration|security|processing|verification|training|placement|interview|offer|appointment|joining).{0,30}(fee|deposit|charge|amount|payment)|\bpay\b.{0,30}(fee|deposit|₹|\brs\.?\b|\binr\b|upi|qr)/i);
  if (payMatch && payMatch.index !== undefined) {
    const window = text.slice(Math.max(0, payMatch.index - 100), payMatch.index + payMatch[0].length + 100);
    if (hasNegationAround(text, payMatch.index, payMatch[0].length)
      || (NO_FEE_DISCLAIMER.test(window) && !STRONG_CUE.test(window))
      || !DEMAND_CUE.test(window)) {
      findings.push({ id: 'beh-payment-disclaimer', category: 'behavioural', severity: 'info', title: 'Fee mentioned without a payment demand (e.g. "no fees" / official-gateway note / payroll mention) — not a demand', evidence: excerpt(payMatch[0]), points: 0 });
      signals['payment-for-job'] = false;
    } else {
      const m = text.match(/(.{0,60}(refundable|registration|security|processing|verification|training|placement|interview|offer|appointment|joining).{0,60})/i);
      add('payment-for-job', 'critical', 'Payment demanded to secure the job / release the offer', m ? m[0] : 'fee/payment keywords present', 10);
    }
  } else signals['payment-for-job'] = false;

  // B2: OTP/UPI PIN/password harvesting (unless safety disclaimer)
  const otpMatch = text.match(/\botp\b|upi\s*pin|\bmpin\b|banking password|netbanking password|card pin|cvv/i);
  if (otpMatch && otpMatch.index !== undefined) {
    if (hasNegationAround(text, otpMatch.index, otpMatch[0].length)) {
      findings.push({ id: 'beh-otp-pin-harvest', category: 'behavioural', severity: 'info', title: 'OTP/PIN language appears in a safety warning — not a request', evidence: excerpt(otpMatch[0]), points: 0 });
      signals['otp-pin-harvest'] = false;
    } else {
      const m = text.match(/.{0,60}(\botp\b|upi\s*pin|banking password|netbanking password|cvv).{0,60}/i);
      add('otp-pin-harvest', 'critical', 'OTP / UPI PIN / banking password requested — credential harvesting', m ? m[0] : 'otp/pin keywords', 10);
    }
  } else signals['otp-pin-harvest'] = false;

  // B3: early-stage Aadhaar/PAN/bank harvesting
  const asksAadhaar = /aadhaar|aadhar|आधार/i.test(t);
  const asksPan = /pan\s*(card|number|details)|पैन|पॅन/i.test(t);
  const asksBank = /bank account|account number|ifsc|passbook|cancelled cheque|debit card|credit card/i.test(t);
  const sensitiveCount = [asksAadhaar, asksPan, asksBank].filter(Boolean).length;
  signals['early-sensitive-harvest'] = false;
  if (sensitiveCount > 0) {
    const span = text.match(/.{0,80}(aadhaar|pan\s*(card|number)|bank account|ifsc).{0,80}/i)?.[0] || '';
    const inperson = /\bin[- ]person\b|walk[- ]?in|originals?\b|verification (at|in) .{0,20}(office|hub|centre|center|venue|branch)|nothing collected online/i.test(span + ' ' + text.slice(0, 400));
    if (!identityEstablished && !inperson) {
      const m = text.match(/.{0,60}(aadhaar|pan\s*(card|number)|bank account|ifsc).{0,60}/i);
      add('early-sensitive-harvest', sensitiveCount >= 2 ? 'critical' : 'high',
        `Sensitive identity/financial data requested before employer identity is established (${sensitiveCount} type${sensitiveCount > 1 ? 's' : ''})`,
        m ? m[0] : 'sensitive data keywords', sensitiveCount >= 2 ? 8 : 5);
    } else if (inperson && !identityEstablished) {
      // In-person / walk-in channel with nothing collected online: notably lower
      // risk than remote harvesting, but identity should still be verified first.
      const m2 = text.match(/.{0,60}(aadhaar|pan\s*(card|number)|bank account|ifsc).{0,60}/i);
      findings.push({ id: 'beh-inperson-doc', category: 'behavioural', severity: 'medium', title: 'Identity document mentioned with an in-person verification channel — lower risk than remote harvesting; verify employer first', evidence: excerpt(m2 ? m2[0] : 'document keyword'), points: 2 });
      raw += 2;
    } else {
      // Late/established stage — still note but low weight; genuine hiring may request docs.
      findings.push({ id: 'beh-doc-late-stage', category: 'behavioural', severity: 'info', title: 'Document request at a stage where employer identity appears established — verify channel before sharing', evidence: excerpt(text.slice(0, 140)), points: 1 });
      raw += 1; signals['late-stage-doc'] = true;
    }
  }

  // B4: brand impersonation hints (behavioural side; URL side scores separately).
  // EXEMPTION: well-known third-party job platforms (LinkedIn, Naukri, Indeed…)
  // legitimately host other employers' postings, so a brand/domain difference
  // there is expected — note it as info (verify the recruiter profile instead).
  const JOB_PLATFORMS = ['linkedin.com', 'naukri.com', 'indeed.com', 'foundit.in', 'shine.com', 'timesjobs.com', 'apna.co', 'freshersworld.com', 'cutshort.io', 'wellfound.com'];
  const brands = detectBrandMentions(text);
  if (brands.length && input.registrableDomain) {
    const reg = String(input.registrableDomain).toLowerCase();
    const mismatch = brands.every((b) => !reg.includes(b.replace(/\s+/g, '')));
    if (mismatch && JOB_PLATFORMS.some((p) => reg === p || reg.endsWith('.' + p))) {
      findings.push({ id: 'beh-platform-posting', category: 'behavioural', severity: 'info', title: `Job posted via third-party platform (${input.registrableDomain}) — brand difference is expected; verify the recruiter profile and vacancy on the employer's official site`, evidence: excerpt(`brands: ${brands.slice(0, 3).join(', ')} via ${input.registrableDomain}`), points: 0 });
      signals['brand-identity-mismatch'] = false;
    } else if (mismatch) {
      add('brand-identity-mismatch', 'high', `Advertised brand (${brands.slice(0, 3).join(', ')}) does not match application domain ${input.registrableDomain}`, `brands: ${brands.slice(0, 3).join(', ')} vs domain: ${input.registrableDomain}`, 6);
    } else signals['brand-identity-mismatch'] = false;
  }

  // B5: excessive data collection (form-like enumeration)
  const dataItems = ['photo', 'signature', 'aadhaar', 'pan', 'passport', 'voter', 'ration card', 'bank', 'salary slip', 'mother', 'father', 'spouse', 'nominee'].filter((w) => t.includes(w));
  if (dataItems.length >= 4) {
    add('excessive-collection', 'medium', `Application collects excessive personal data (${dataItems.length} sensitive item types: ${dataItems.slice(0, 5).join(', ')})`, dataItems.join(', '), 4);
  } else signals['excessive-collection'] = false;

  // B6: unverifiable employer + implausible salary/requirement ratio
  const salaryMatch = text.match(/₹\s?([\d,]+)/);
  const lowReq = /(8th|10th|12th)\s*pass|no experience|fresher/i.test(t);
  if (salaryMatch) {
    const amount = Number(salaryMatch[1].replace(/,/g, ''));
    if (lowReq && amount >= 50000) {
      add('implausible-salary', 'medium', `Implausible salary (₹${amount.toLocaleString('en-IN')}) for stated low requirements`, salaryMatch[0] + ' + ' + (text.match(/(8th|10th|12th)\s*pass|no experience|fresher/i) || [''][0]), 4);
    } else signals['implausible-salary'] = false;
  }

  // B7: suspicious redirect / portal mismatch hint (from inspection metadata)
  if (input.redirectCrossDomain) {
    add('redirect-to-unrelated-portal', 'high', `Legitimate-looking job page redirects to unrelated data-collection domain (${input.finalRegistrable || 'unknown'})`, `redirect chain crosses registrable domains`, 6);
  } else signals['redirect-to-unrelated-portal'] = false;

  // B8: fake govt-job claim
  if (/(sarkari|सरकारी|शासकीय).{0,20}(naukri|job|bharti|vacancy)|govt.{0,20}job|government job/i.test(t) && input.urlHost && !/gov\.in$|nic\.in$/.test(input.urlHost)) {
    add('fake-govt-portal', 'high', 'Government-job claim made from a non-government domain — verify on official .gov.in portal', text.match(/.{0,50}(sarkari|सरकारी|शासकीय|govt|government).{0,50}/i)?.[0] || 'govt job claim', 5);
  } else signals['fake-govt-portal'] = false;

  // B9: contact mismatch (free-mail recruiter for big brand)
  const freeMail = text.match(/[\w.]+@(gmail|yahoo|rediffmail|outlook|hotmail|protonmail)\.com/i);
  if (freeMail && brands.length) {
    add('recruiter-domain-mismatch', 'medium', `Recruiter uses free-mail address (${freeMail[0]}) while advertising brand (${brands[0]})`, freeMail[0], 3);
  } else signals['recruiter-domain-mismatch'] = false;

  const score = text ? Math.round(MAX * (1 - Math.exp(-raw / 14)) * 10) / 10 : 0;
  return { score, max: MAX, findings, signals, rawWeight: raw, identityEstablished };
}
