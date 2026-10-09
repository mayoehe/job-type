/**
 * JobShield local detection engine (frontend mirror of backend/src/*).
 * Runs fully offline for URL-structure + text analysis. When the backend is
 * reachable, App.tsx prefers backend results (which add safe page inspection).
 * Scoring formula, weights, floors, bands, disclaimer guards and in-person
 * mitigations are identical to the backend.
 */

export interface Finding { id: string; category: string; severity: 'critical'|'high'|'medium'|'low'|'info'; title: string; evidence: string; points: number; }
export interface ScanResult {
  score: number; band: string; level: string; color: string; rawTotal: number; floor: number;
  categories: Record<string, { score: number; max: number }>;
  overrides: { id: string; severity: string; title: string; detail: string; floor: number; evidence: string[] }[];
  allFindings: Finding[]; recommendations: string[];
  counts: { confirmed: number; suspicious: number; info: number };
  meta: { urlHost: string; registrableDomain: string | null };
  intelligence?: Record<string, unknown>; local?: boolean;
}

export function redactText(text: string): string {
  let out = String(text || '');
  out = out.replace(/\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g, 'XXXX-XXXX-XXXX');
  out = out.replace(/\b[A-Z]{5}\d{4}[A-Z]\b/gi, 'XXXXX0000X');
  out = out.replace(/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, 'XXXX-XXXX-XXXX-XXXX');
  out = out.replace(/(\botp\b[\s:.-]*)\d{4,8}/gi, '$1••••••');
  out = out.replace(/[\w.\-]{2,}@[a-zA-Z]{2,}/g, '[REDACTED-UPI]');
  out = out.replace(/(\+?91[\s-]?)?[6-9]\d{9}\b/g, '[REDACTED-PHONE]');
  return out;
}
const excerpt = (t: string, n = 160) => { const r = redactText(t); return r.length <= n ? r : r.slice(0, n).trimEnd() + '…'; };

const NEG_WORD = /\b(never|not|n't|without|beware|caution|alert|free|nil)\b|कभी नहीं|नहीं|नही|नका\b|नाही|बिना|मुफ्त|निःशुल्क|निशुल्क|मोफत/;
const ASK_WORD = /\b(ask|asks|asked|request|demand|charge|collect|share|need|take|pay)\b|मांगा|मांगते|मागितले|विचारले|घेतले|घेत नाही|शुल्क/;
function hasNegationAround(text: string, idx: number, len = 0): boolean {
  const ctx = text.slice(Math.max(0, idx - 90), idx) + ' ' + text.slice(idx + len, idx + len + 70);
  return NEG_WORD.test(ctx) && ASK_WORD.test(ctx);
}
const INPERSON_CUE = /\bin[- ]person\b|walk[- ]?in|originals?\b|verification (at|in) .{0,20}(office|hub|centre|center|venue|branch)|nothing collected online/i;
const OFFCHANNEL_DISCLAIMER = /\bno\b.{0,25}(documents?|details?|data|money|payment|fees?|charges?|application).{0,30}\b(whatsapp|telegram|online)\b|nothing collected online|\bnever\b.{0,25}\b(whatsapp|telegram)\b/i;
const NO_FEE_DISCLAIMER = /\bno\s+(\w{1,12}\s)?(fees?|charges?|advance|payment|money)\b|without\s+(any\s+)?(fees?|charge|payment|advance)/i;
const STRONG_CUE = /\bpay\b|upi|qr|₹|\brs\.?\b|\binr\b|refundable|bhejo|bhej|भरो|भरा/i;
const DEMAND_CUE = /\b(pay|paid|payable|deposit|upi|qr|phonepe|gpay|paytm|refundable|₹|\brs\.?\b|\binr\b|भरो|भरा|bhejo|bhej|pay karo)\b/i;

function findFirst(text: string, patterns: string[]): { snippet: string; context: string; negated: boolean } | null {
  for (const p of patterns) {
    try {
      const m = text.match(new RegExp(p, 'i'));
      if (m && m.index !== undefined) {
        const start = Math.max(0, m.index - 60);
        const context = text.slice(Math.max(0, m.index - 90), m.index + m[0].length + 70);
        return { snippet: text.slice(start, m.index + Math.min(m[0].length + 60, 220)), context, negated: hasNegationAround(text, m.index, m[0].length) };
      }
    } catch { /* noop */ }
  }
  return null;
}

// ---------- A. linguistic (35) ----------
const LING_RULES: { id: string; severity: Finding['severity']; weight: number; title: string; patterns: string[] }[] = [
  { id: 'cred-aadhaar', severity: 'high', weight: 7, title: 'Requests Aadhaar number / copy before hiring need is established', patterns: ['aadhaar','aadhar','adhaar','आधार','aadhaar card','aadhar number','share your aadhaar','aadhaar details','आधार नंबर'] },
  { id: 'cred-pan', severity: 'high', weight: 6, title: 'Requests PAN details upfront', patterns: ['\\bpan\\b.{0,20}(card|number|details|copy)','pan card','पॅन कार्ड','पैन कार्ड','pan number','share your pan'] },
  { id: 'cred-bank', severity: 'high', weight: 7, title: 'Requests bank account / card / IFSC details during application', patterns: ['bank account','account number','खाते नंबर','ifsc','bank details','passbook','cancelled cheque','cancelled check','debit card','credit card','cvv','card number','बँक तपशील','बैंक विवरण'] },
  { id: 'cred-otp-critical', severity: 'critical', weight: 12, title: 'Requests OTP / UPI PIN / banking password — never legitimate in hiring', patterns: ['\\botp\\b','one[- ]time password','upi pin','mpin','netbanki?ng passwords?','banking passwords?','(share|send|forward|tell|provide|disclose|submit|demand|bata|bhejo)[^.!?।\\n]{0,40}passwords?','passwords?[^.!?।\\n]{0,40}(share|send|forward|tell|bata|bhejo|disclose|demand)','पिन','ओटीपी','otp share','otp bhejo','otp bhej','otp batayen','otp sanga','share[^.!?।\\n]{0,40}otp','forward[^.!?।\\n]{0,40}otp'] },
  { id: 'fee-job', severity: 'high', weight: 9, title: 'Demands registration / security / training / verification fee for the job', patterns: ['registration fee','registration charge','security deposit','refundable[^.!?।\\n]{0,60}(fee|deposit|amount)','processing fee','verification fee','training fee','interview fee','placement fee','joining.{0,10}(fee|charge)','application.{0,10}(fee|charge)','jobs?[^.!?।\\n]{0,40}fees?','रजिस्ट्रेशन फीस','सिक्युरिटी डिपॉजिट','नोंदणी शुल्क','सुरक्षा ठेव','refundable','(registration|verification|processing|training|placement|security|refundable|joining|interview|application)\\s+(fee|fees|charge|deposit)\\s+(rs\\.?|inr|₹)\\s?\\d','(fee|charge|deposit|advance|शुल्क|फीस).{0,15}(₹|\\bupi\\b|\\bqr\\b)','(₹|\\bupi\\b).{0,25}(fee|charge|deposit|भरो|bhejo|karo)','\\bpay\\b.{0,20}(fee|charge|deposit|₹|\\brs\\b)','फीस भरो','पैसे भरो','पैसे भरा'] },
  { id: 'guarantee-salary', severity: 'medium', weight: 4, title: 'Guaranteed job / unrealistic salary / instant selection without process', patterns: ['guaranteed job','100%[^.!?।\\n]{0,40}(job|placement|selection)','no interview','without interview','instant selection','spot offer','earn[^.!?।\\n]{0,40}₹[^.!?।\\n]{0,40}(per day|daily|weekly)','₹\\s?\\d{5,}','घर बैठे कमाएं','घरी बसून कमवा','paisa kamao','bina interview'] },
  { id: 'urgency', severity: 'medium', weight: 4, title: 'Excessive urgency / countdown / threat of losing offer', patterns: ['act (now|immediately|fast)','urgent[^.!?।\\n]{0,20}(join|apply|respond|reply)','last chance','offer expires','limited slots','only[^.!?।\\n]{0,40}(slot|vacanc|seat)[^.!?।\\n]{0,40}left','immediately','तुरंत','तातडीने','ताबडतोब','last date[^.!?।\\n]{0,40}today','join[^.!?।\\n]{0,40}today'] },
  { id: 'offchannel', severity: 'medium', weight: 5, title: 'Pushes conversation to unofficial WhatsApp / Telegram without verifiable identity', patterns: ['whatsapp','telegram','व्हॉट्सअ‍ॅप','व्हाट्सएप','वॉट्सअ‍ॅप','टेलिग्राम','\\bwa\\.me\\b','t\\.me/'] },
  { id: 'generic-copy', severity: 'low', weight: 2, title: 'Suspiciously generic / copied recruiter message', patterns: ['dear candidate','dear applicant','greetings from','both fresher[^.!?।\\n]{0,40}experienced[^.!?।\\n]{0,20}can apply','no experience needed[^.!?।\\n]{0,30}high salary','dear[^.!?।\\n]{0,60}resume[^.!?।\\n]{0,40}selected','congratulations[^.!?।\\n]{0,40}selected'] },
  { id: 'malware-install', severity: 'high', weight: 8, title: 'Asks to install unknown app / APK / open attachment', patterns: ['download[^.!?।\\n]{0,40}(apk|app|application|software)','install[^.!?।\\n]{0,40}(app|application|apk|software)','open[^.!?।\\n]{0,30}attachment','anydesk','teamviewer','remote access','एपीके'] },
  { id: 'bypass-channel', severity: 'medium', weight: 4, title: 'Instructs to bypass official recruitment channels', patterns: ['bypass','do not apply[^.!?।\\n]{0,40}(portal|website|official)',"don't apply[^.!?।\\n]{0,40}official",'direct joining','direct bharti','direct placement'] },
  { id: 'contradiction', severity: 'low', weight: 2, title: 'Contradictory requirements / vague role with high pay', patterns: ['no qualification[^.!?।\\n]{0,40}₹','8th pass[^.!?।\\n]{0,40}₹\\s?\\d{5}','fresher[^.!?।\\n]{0,40}₹\\s?[5-9]\\d{4}'] },
];

function analyseLinguistic(text: string) {
  const findings: Finding[] = []; let raw = 0;
  for (const r of LING_RULES) {
    const hit = text ? findFirst(text, r.patterns) : null;
    if (!hit) continue;
    if (hit.negated) {
      findings.push({ id: `ling-${r.id}`, category: 'linguistic', severity: 'info', title: `${r.title} — mentioned in a safety disclaimer, not requested`, evidence: excerpt(hit.snippet), points: 0 });
      continue;
    }
    if (r.id === 'offchannel' && OFFCHANNEL_DISCLAIMER.test(hit.context)) {
      findings.push({ id: `ling-${r.id}`, category: 'linguistic', severity: 'info', title: 'WhatsApp/Telegram mentioned in a cautionary context — not a push off-channel', evidence: excerpt(hit.snippet), points: 0 });
      continue;
    }
    if (r.id === 'fee-job') {
      const at = text.indexOf(hit.snippet.slice(0, 24));
      const win = text.slice(Math.max(0, at - 100), at + 220);
      if (NO_FEE_DISCLAIMER.test(win) && !STRONG_CUE.test(win)) {
        findings.push({ id: `ling-${r.id}`, category: 'linguistic', severity: 'info', title: 'Fee language appears in a no-fee / no-charge statement — not a demand', evidence: excerpt(hit.snippet), points: 0 });
        continue;
      }
    }
    if (['cred-aadhaar', 'cred-pan', 'cred-bank'].includes(r.id) && INPERSON_CUE.test(hit.snippet + ' ' + hit.context)) {
      raw += 3;
      findings.push({ id: `ling-${r.id}`, category: 'linguistic', severity: 'medium', title: `${r.title} — but an in-person verification channel is mentioned (lower risk; still verify identity first)`, evidence: excerpt(hit.snippet), points: 3 });
      continue;
    }
    raw += r.weight;
    findings.push({ id: `ling-${r.id}`, category: 'linguistic', severity: r.severity, title: r.title, evidence: excerpt(hit.snippet), points: r.weight });
  }
  return { score: text ? Math.round(35 * (1 - Math.exp(-raw / 18)) * 10) / 10 : 0, findings, raw };
}

// ---------- URL helpers ----------
function parseReg(host: string): { reg: string; sub: string } {
  const h = host.toLowerCase().replace(/\.$/, '');
  const parts = h.split('.');
  const multi = ['co.in','org.in','net.in','gov.in','nic.in','ac.in','edu.in','co.uk','com.au','co.jp'];
  for (const s of multi) if (h.endsWith('.' + s) || h === s) {
    const rest = h.slice(0, h.length - s.length).split('.').filter(Boolean);
    return { reg: rest.length ? rest[rest.length-1] + '.' + s : s, sub: rest.length > 1 ? rest.slice(0, -1).join('.') : '' };
  }
  return { reg: parts.length >= 2 ? parts.slice(-2).join('.') : h, sub: parts.length > 2 ? parts.slice(0, -2).join('.') : '' };
}
function lev(a: string, b: string): number {
  const m = a.length, n = b.length; if (!m) return n; if (!n) return m;
  const dp: number[][] = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++) dp[i][j] = Math.min(dp[i-1][j]+1, dp[i][j-1]+1, dp[i-1][j-1]+(a[i-1]===b[j-1]?0:1));
  return dp[m][n];
}
const TRUSTED = ['infosys.com','tcs.com','wipro.com','hcltech.com','techmahindra.com','reliance.com','tata.com','flipkart.com','amazon.in','google.com','microsoft.com','ibm.com','accenture.com','cognizant.com','naukri.com','linkedin.com','indeed.com','upsc.gov.in','ssc.gov.in'];

function analyseUrl(rawUrl: string) {
  const findings: Finding[] = []; let raw = 0;
  const add = (id: string, severity: Finding['severity'], title: string, evidence: string, w: number) => { raw += w; findings.push({ id: `url-${id}`, category: 'domain', severity, title, evidence: evidence.slice(0,160), points: w }); };
  if (!rawUrl.trim()) return { score: 0, findings, reg: null as string | null, host: '' };
  let u: URL; try { u = new URL(rawUrl.trim()); } catch { add('unparseable','medium','URL could not be parsed', rawUrl.slice(0,120), 4); return { score: 4, findings, reg: null, host: '' }; }
  const host = u.hostname.toLowerCase(); const { reg, sub } = parseReg(host);
  if (['bit.ly','tinyurl.com','t.co','cutt.ly','rb.gy'].includes(reg)) add('shortener','medium',`URL shortener hides the real destination (${host})`,host,4);
  if (/xn--|[^\x00-\x7F]/.test(host)) add('homoglyph','high','Suspicious hostname encoding (punycode/non-ASCII, possible homoglyph)',host,6);
  const brandInSub = TRUSTED.map(d=>d.split('.')[0]).find(b=>sub.includes(b));
  if (brandInSub && !TRUSTED.includes(reg)) add('misleading-subdomain','high',`Trusted brand "${brandInSub}" appears as a subdomain of unrelated domain ${reg}`,host,6);
  const pathQ = (u.pathname + ' ' + u.search).toLowerCase();
  const brandInPath = TRUSTED.map(d=>d.split('.')[0]).find(b=>pathQ.includes(b));
  if (brandInPath && !TRUSTED.includes(reg) && !reg.includes(brandInPath)) add('brand-in-path','medium',`Brand name "${brandInPath}" appears in URL path but domain is ${reg}`,u.pathname.slice(0,120),3);
  const label = reg.split('.')[0]; let best = Infinity, closest = '';
  for (const td of TRUSTED) { const d = lev(label, td.split('.')[0]); if (d < best) { best = d; closest = td; } }
  if (best === 1 || (best === 2 && label.length >= 6)) add('typosquat','high',`Domain "${reg}" is ${best} edit(s) from trusted "${closest}" (possible typosquat)`,`${reg} ↔ ${closest}`,6);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) add('ip-host','high','URL uses a raw IP address instead of a domain name',host,5);
  if (host.split('.').length >= 5) add('obfuscated-host','low','Unusually deep hostname (possible obfuscation)',host.slice(0,120),2);
  const score = Math.round(Math.min(15, 15 * (1 - Math.exp(-raw / 7))) * 10) / 10;
  return { score, findings, reg, host };
}

// ---------- behavioural (30) ----------
function analyseBehaviour(text: string, reg: string | null) {
  const findings: Finding[] = []; let raw = 0; const t = text.toLowerCase();
  const add = (id: string, severity: Finding['severity'], title: string, evidence: string, w: number) => { raw += w; findings.push({ id: `beh-${id}`, category: 'behavioural', severity, title, evidence: excerpt(evidence), points: w }); };
  const established = [/about (us|the company)/i,/founded in \d{4}/i,/registered office/i,/careers@|hr@|jobs@/i].filter(re=>re.test(text)).length >= 2;
  const payMatch = text.match(/(refundable|registration|security|processing|verification|training|placement|interview|offer|appointment|joining).{0,30}(fee|deposit|charge|amount|payment)|\bpay\b.{0,30}(fee|deposit|₹|\brs\.?\b|\binr\b|upi|qr)/i);
  if (payMatch && payMatch.index !== undefined) {
    const win = text.slice(Math.max(0, payMatch.index - 100), payMatch.index + payMatch[0].length + 100);
    if (hasNegationAround(text, payMatch.index, payMatch[0].length) || (NO_FEE_DISCLAIMER.test(win) && !STRONG_CUE.test(win)) || !DEMAND_CUE.test(win)) {
      findings.push({ id: 'beh-payment-disclaimer', category: 'behavioural', severity: 'info', title: 'Fee mentioned without a payment demand — not a demand', evidence: excerpt(payMatch[0]), points: 0 });
    } else {
      const m = text.match(/(.{0,60}(refundable|registration|security|processing|verification|training|placement|interview|offer|appointment|joining).{0,60})/i);
      add('payment-for-job','critical','Payment demanded to secure the job / release the offer', m?.[0] || 'fee/payment keywords', 10);
    }
  }
  const otpMatch = text.match(/\botp\b|upi\s*pin|\bmpin\b|banking password|netbanking password|cvv/i);
  if (otpMatch && otpMatch.index !== undefined) {
    if (hasNegationAround(text, otpMatch.index, otpMatch[0].length)) {
      findings.push({ id: 'beh-otp-pin-harvest', category: 'behavioural', severity: 'info', title: 'OTP/PIN language appears in a safety warning — not a request', evidence: excerpt(otpMatch[0]), points: 0 });
    } else {
      const m = text.match(/.{0,60}(\botp\b|upi\s*pin|banking password|netbanking password|cvv).{0,60}/i);
      add('otp-pin-harvest','critical','OTP / UPI PIN / banking password requested — credential harvesting', m?.[0] || 'otp/pin keywords', 10);
    }
  }
  const n = [/aadhaar|aadhar|आधार/i.test(t),/pan\s*(card|number|details)|पैन|पॅन/i.test(t),/bank account|account number|ifsc|passbook|cancelled cheque|debit card|credit card/i.test(t)].filter(Boolean).length;
  if (n > 0 && !established) {
    const span = (text.match(/.{0,80}(aadhaar|pan\s*(card|number)|bank account|ifsc).{0,80}/i)?.[0] || '');
    if (INPERSON_CUE.test(span + ' ' + text.slice(0, 400))) {
      findings.push({ id: 'beh-inperson-doc', category: 'behavioural', severity: 'medium', title: 'Identity document mentioned with an in-person verification channel — lower risk; verify employer first', evidence: excerpt(span), points: 2 }); raw += 2;
    } else {
      const m = text.match(/.{0,60}(aadhaar|pan\s*(card|number)|bank account|ifsc).{0,60}/i);
      add('early-sensitive-harvest', n >= 2 ? 'critical' : 'high', `Sensitive identity/financial data requested before employer identity is established (${n} type${n>1?'s':''})`, m?.[0] || 'sensitive keywords', n >= 2 ? 8 : 5);
    }
  } else if (n > 0) { findings.push({ id: 'beh-doc-late-stage', category: 'behavioural', severity: 'info', title: 'Document request where employer identity appears established — verify channel before sharing', evidence: excerpt(text.slice(0,140)), points: 1 }); raw += 1; }
  const brands = TRUSTED.map(d=>d.split('.')[0]).filter(b=>t.includes(b));
  const PLATFORMS = ['linkedin.com','naukri.com','indeed.com','foundit.in','shine.com','timesjobs.com','apna.co','freshersworld.com','cutshort.io','wellfound.com'];
  if (brands.length && reg && brands.every(b=>!reg.includes(b))) {
    if (PLATFORMS.some(p=>reg === p || reg.endsWith('.' + p))) findings.push({ id: 'beh-platform-posting', category: 'behavioural', severity: 'info', title: `Job posted via third-party platform (${reg}) — brand difference is expected; verify the recruiter profile`, evidence: `brands vs ${reg}`, points: 0 });
    else add('brand-identity-mismatch','high',`Advertised brand (${brands.slice(0,3).join(', ')}) does not match application domain ${reg}`,`brands vs ${reg}`,6);
  }
  const items = ['photo','signature','aadhaar','pan','passport','voter','ration card','bank','salary slip'].filter(w=>t.includes(w));
  if (items.length >= 4) add('excessive-collection','medium',`Application collects excessive personal data (${items.length} types)`,items.join(', '),4);
  const sm = text.match(/₹\s?([\d,]+)/);
  if (sm && /(8th|10th|12th)\s*pass|no experience|fresher/i.test(t) && Number(sm[1].replace(/,/g,'')) >= 50000) add('implausible-salary','medium','Implausible salary for stated low requirements',sm[0],4);
  if (/(sarkari|सरकारी|शासकीय).{0,20}(naukri|job|bharti|vacancy)|govt.{0,20}job|government job/i.test(t)) add('fake-govt-portal','high','Government-job claim — verify on official .gov.in portal',(text.match(/.{0,50}(sarkari|सरकारी|शासकीय|govt|government).{0,50}/i)?.[0]) || 'govt claim',5);
  const fm = text.match(/[\w.]+@(gmail|yahoo|rediffmail|outlook|hotmail)\.com/i);
  if (fm && brands.length) add('recruiter-domain-mismatch','medium',`Recruiter uses free-mail (${fm[0]}) while advertising brand (${brands[0]})`,fm[0],3);
  return { score: text ? Math.round(30 * (1 - Math.exp(-raw / 14)) * 10) / 10 : 0, findings, raw };
}

function bandFor(s: number) {
  if (s >= 80) return { band: 'Critical risk', level: 'critical', color: '#dc2626' };
  if (s >= 60) return { band: 'High risk', level: 'high', color: '#ea580c' };
  if (s >= 40) return { band: 'Suspicious', level: 'suspicious', color: '#d97706' };
  if (s >= 20) return { band: 'Caution', level: 'caution', color: '#ca8a04' };
  return { band: 'Low apparent risk', level: 'low', color: '#16a34a' };
}

export function localScan(text: string, url: string): ScanResult {
  const ling = analyseLinguistic(text || '');
  const urlR = analyseUrl(url || '');
  const beh = analyseBehaviour(text || '', urlR.reg);
  const techF: Finding[] = [{ id: 'tech-local-info', category: 'technical', severity: 'info', title: 'Local mode: live TLS/reputation checks unavailable — treated as unknown, not safe', evidence: 'connect backend for live inspection', points: 0 }];
  const empF: Finding[] = [];
  let empScore = 0;
  if (!url.trim() && !text.trim()) empScore = 2;
  else {
    empScore = 5;
    empF.push({ id: 'emp-vacancy-unverified', category: 'employer', severity: 'low', title: 'Vacancy could not be corroborated on an official careers page (local mode) — uncertainty', evidence: 'unverified', points: 3 });
    empF.push({ id: 'emp-domain-unlinked', category: 'employer', severity: 'low', title: 'Application domain is not demonstrably linked from a trusted employer source', evidence: 'unlinked', points: 2 });
  }
  const rawTotal = Math.round((ling.score + beh.score + urlR.score + 0 + empScore) * 10) / 10;
  const all = [...ling.findings, ...beh.findings, ...urlR.findings, ...techF, ...empF];
  const confirmed = all.filter(x => ['critical', 'high'].includes(x.severity));
  const has = (f: string) => confirmed.some(x => x.id.includes(f));
  const overrides: ScanResult['overrides'] = [];
  if (has('otp-critical') || has('otp-pin-harvest')) overrides.push({ id: 'override-otp', severity: 'critical', title: 'Immediate warning: OTP / UPI PIN / banking password requested', detail: 'Legitimate recruiters never ask for these. Stop and do not share.', floor: 80, evidence: confirmed.filter(f=>f.id.includes('otp')).map(f=>f.evidence).slice(0,2) });
  if (has('payment-for-job') || has('fee-job')) overrides.push({ id: 'override-payment', severity: 'high', title: 'High-severity warning: payment demanded to secure employment', detail: 'Fee-for-job demands are a hallmark of recruitment fraud.', floor: 65, evidence: confirmed.filter(f=>f.id.includes('payment')||f.id.includes('fee')).map(f=>f.evidence).slice(0,2) });
  const harvest = confirmed.filter(f=>['cred-aadhaar','cred-pan','cred-bank','early-sensitive-harvest','excessive-collection'].some(h=>f.id.includes(h))).length;
  if (harvest >= 2 && !overrides.some(o=>o.floor >= 80)) overrides.push({ id: 'override-harvest-multi', severity: 'high', title: `Multiple credential-harvesting indicators (${harvest}) elevate risk`, detail: 'Independent requests for identity/financial data indicate harvesting.', floor: 60, evidence: [] });
  const floor = overrides.reduce((m, o) => Math.max(m, o.floor), 0);
  const score = Math.min(100, Math.max(rawTotal, floor));
  const b = bandFor(score);
  const rank: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  all.sort((x, y) => rank[y.severity] - rank[x.severity] || y.points - x.points);
  const recs = [
    ...(overrides.some(o=>o.id==='override-otp') ? ['Do NOT share OTPs, UPI PINs, passwords or banking credentials — no genuine hiring process needs them.'] : []),
    ...(overrides.some(o=>o.id==='override-payment') ? ['Do NOT pay any recruiter to secure a job or release an offer letter.'] : []),
    "Verify the vacancy through the employer's independently located official careers website.",
    'Contact the employer through independently verified contact information.',
    'Report suspected fraud at cybercrime.gov.in or helpline 1930. General guidance, not legal advice.',
  ];
  if (score < 20) recs.push('Low apparent risk does NOT guarantee safety — stay alert for later money/credential requests.');
  return { score, band: b.band, level: b.level, color: b.color, rawTotal, floor,
    categories: { linguistic: { score: ling.score, max: 35 }, behavioural: { score: beh.score, max: 30 }, domain: { score: urlR.score, max: 15 }, technical: { score: 0, max: 10 }, employer: { score: empScore, max: 10 } },
    overrides, allFindings: all, recommendations: recs,
    counts: { confirmed: all.filter(f=>['critical','high'].includes(f.severity)).length, suspicious: all.filter(f=>f.severity==='medium').length, info: all.filter(f=>['low','info'].includes(f.severity)).length },
    meta: { urlHost: urlR.host, registrableDomain: urlR.reg }, local: true };
}
