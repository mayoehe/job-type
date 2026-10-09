/**
 * A. Linguistic & semantic analysis — max 35 points.
 * Phrase patterns + contextual rules across English, Hindi, Marathi, Hinglish.
 * NOTE: grammar mistakes / informal tone alone are NOT strong fraud signals
 * (handled by keeping a small weight for that rule and requiring corroboration).
 */
import { excerpt } from '../utils/redact.js';

export const MAX = 35;

// Each rule: id, weight (points if matched, scaled), severity, title, patterns (regex source, flags)
// Evidence = first matching excerpt.
const RULES = [
  {
    id: 'cred-aadhaar', severity: 'high', weight: 7, title: 'Requests Aadhaar number / copy before hiring need is established',
    patterns: ['aadhaar', 'aadhar', 'adhaar', 'आधार', 'आधार कार्ड', 'aadhaar card', 'aadhar number', 'share your aadhaar', 'aadhaar details', 'आधार नंबर'],
  },
  {
    id: 'cred-pan', severity: 'high', weight: 6, title: 'Requests PAN details upfront',
    patterns: ['\\bpan\\b.{0,20}(card|number|details|copy)', 'pan card', 'पॅन कार्ड', 'पैन कार्ड', 'pan number', 'share your pan'],
  },
  {
    id: 'cred-bank', severity: 'high', weight: 7, title: 'Requests bank account / card / IFSC details during application',
    patterns: ['bank account', 'account number', 'खाते नंबर', 'ifsc', 'bank details', 'passbook', 'cancelled cheque', 'cancelled check', 'debit card', 'credit card', 'cvv', 'card number', 'बँक तपशील', 'बैंक विवरण'],
  },
  {
    id: 'cred-otp-critical', severity: 'critical', weight: 12, title: 'Requests OTP / UPI PIN / banking password — never legitimate in hiring',
    patterns: ['\\botp\\b', 'one[- ]time password', 'upi pin', 'upi\\.pin', 'mpin', 'm-pin', 'netbanki?ng passwords?', 'banking passwords?', '(share|send|forward|tell|provide|disclose|submit|demand|bata|bhejo)[^.!?।\n]{0,40}passwords?', 'passwords?[^.!?।\n]{0,40}(share|send|forward|tell|bata|bhejo|disclose|demand)', 'पिन', 'ओटीपी', 'otp share', 'otp bhejo', 'otp bhej', 'otp batayen', 'otp sanga', 'share[^.!?।\n]{0,40}otp', 'forward[^.!?।\n]{0,40}otp', 'upi[^.!?।\n]{0,20}pin[^.!?।\n]{0,30}(share|enter|bata)', 'card[^.!?।\n]{0,30}(pin|cvv)'],
  },
  {
    id: 'fee-job', severity: 'high', weight: 9, title: 'Demands registration / security / training / verification fee for the job',
    patterns: ['registration fee', 'registration charge', 'security deposit', 'refundable[^.!?।\n]{0,60}(fee|deposit|amount)', 'processing fee', 'verification fee', 'training fee', 'interview fee', 'placement fee', 'joining.{0,10}(fee|charge)', 'application.{0,10}(fee|charge)', 'jobs?[^.!?।\n]{0,40}fees?', 'pay[^.!?।\n]{0,40}(to|for)[^.!?।\n]{0,40}(job|offer|appointment|selection)', 'रजिस्ट्रेशन फीस', 'सिक्युरिटी डिपॉजिट', 'नोंदणी शुल्क', 'सुरक्षा ठेव', 'refundable', '(registration|verification|processing|training|placement|security|refundable|joining|interview|application)\\s+(fee|fees|charge|deposit)\\s+(rs\\.?|inr|₹)\\s?\\d', '(fee|charge|deposit|advance|शुल्क|फीस).{0,15}(₹|\\bupi\\b|\\bqr\\b)', '(₹|\\bupi\\b).{0,25}(fee|charge|deposit|भरो|bhejo|karo)', '\\bpay\\b.{0,20}(fee|charge|deposit|₹|\\brs\\b)', 'फीस भरो', 'पैसे भरो', 'पैसे भरा'],
  },
  {
    id: 'guarantee-salary', severity: 'medium', weight: 4, title: 'Guaranteed job / unrealistic salary / instant selection without process',
    patterns: ['guaranteed job', '100%[^.!?।\n]{0,40}(job|placement|selection)', 'no interview', 'without interview', 'instant selection', 'spot offer', 'earn[^.!?।\n]{0,40}₹[^.!?।\n]{0,40}(per day|daily|weekly)', 'salary[^.!?।\n]{0,30}₹\\s?\\d', '₹\\s?\\d{5,}', 'work from home[^.!?।\n]{0,40}earn', 'घर बैठे कमाएं', 'घरी बसून कमवा', 'paisa kamao', 'bina interview'],
  },
  {
    id: 'urgency', severity: 'medium', weight: 4, title: 'Excessive urgency / countdown / threat of losing offer',
    patterns: ['act (now|immediately|fast)', 'urgent[^.!?।\n]{0,20}(join|apply|respond|reply)', 'last chance', 'offer expires', 'limited slots', 'only[^.!?।\n]{0,40}(slot|vacanc|seat)[^.!?।\n]{0,40}left', 'immediately', 'तुरंत', 'तातडीने', 'ताबडतोब', 'last date[^.!?।\n]{0,40}today', 'join[^.!?।\n]{0,40}today', 'within[^.!?।\n]{0,20}(1|2|24)\\s?(hour|hr)'],
  },
  {
    id: 'offchannel', severity: 'medium', weight: 5, title: 'Pushes conversation to unofficial WhatsApp / Telegram without verifiable identity',
    patterns: ['whatsapp', 'telegram', 'व्हॉट्सअ‍ॅप', 'व्हाट्सएप', 'वॉट्सअ‍ॅप', 'टेलिग्राम', 'contact[^.!?।\n]{0,40}(whatsapp|telegram)', 'message[^.!?।\n]{0,40}(whatsapp|telegram)', 'chat[^.!?।\n]{0,40}(whatsapp|telegram)', '\\bwa\\.me\\b', 't\\.me/'],
  },
  {
    id: 'generic-copy', severity: 'low', weight: 2, title: 'Suspiciously generic / copied recruiter message',
    patterns: ['dear candidate', 'dear applicant', 'greetings from', 'we are hiring[^.!?।\n]{0,40}(male|female|boys|girls)', 'both fresher[^.!?।\n]{0,40}experienced[^.!?।\n]{0,20}can apply', 'no experience needed[^.!?।\n]{0,30}high salary', 'priya mam', 'dear[^.!?।\n]{0,60}resume[^.!?।\n]{0,40}selected', 'congratulations[^.!?।\n]{0,40}selected'],
  },
  {
    id: 'malware-install', severity: 'high', weight: 8, title: 'Asks to install unknown app / APK / open attachment',
    patterns: ['download[^.!?।\n]{0,40}(apk|app|application|software)', 'install[^.!?।\n]{0,40}(app|application|apk|software)', 'open[^.!?।\n]{0,30}attachment', 'enable[^.!?।\n]{0,40}(screen share|anydesk|teamviewer)', 'anydesk', 'teamviewer', 'remote access', 'एपीके', 'ॲप डाउनलोड'],
  },
  {
    id: 'bypass-channel', severity: 'medium', weight: 4, title: 'Instructs to bypass official recruitment channels',
    patterns: ['bypass', 'do not apply[^.!?।\n]{0,40}(portal|website|official)', "don't apply[^.!?।\n]{0,40}official", 'skip[^.!?।\n]{0,30}(hr|portal|official)', 'direct joining', 'direct bharti', 'direct placement', 'without[^.!?।\n]{0,40}(registration|application)[^.!?।\n]{0,20}portal'],
  },
  {
    id: 'contradiction', severity: 'low', weight: 2, title: 'Contradictory requirements / vague role with high pay',
    patterns: ['no qualification[^.!?।\n]{0,40}₹', '8th pass[^.!?।\n]{0,40}₹\\s?\\d{5}', '10th pass[^.!?।\n]{0,40}manager', 'fresher[^.!?।\n]{0,40}₹\\s?[5-9]\\d{4}', 'age[^.!?।\n]{0,30}18[^.!?।\n]{0,20}60[^.!?।\n]{0,20}salary'],
  },
];

/** In-person / walk-in verification channel lowers (not erases) document-request risk. */
const INPERSON_CUE = /\bin[- ]person\b|walk[- ]?in|originals?\b|bring .* (document|certificate)|verification (at|in) .{0,20}(office|hub|centre|center|venue|branch)/i;
/** "No documents over WhatsApp / nothing collected online" is good practice, not off-channel pushing. */
const OFFCHANNEL_DISCLAIMER = /\bno\b.{0,25}(documents?|details?|data|money|payment|fees?|charges?|application).{0,30}\b(whatsapp|telegram|online)\b|nothing collected online|\bnever\b.{0,25}\b(whatsapp|telegram)\b|\bdon't\b.{0,25}\b(whatsapp|telegram)\b/i;

function findFirst(text, patterns) {
  for (const p of patterns) {
    try {
      const re = new RegExp(p, 'i');
      const m = text.match(re);
      if (m && m.index !== undefined) {
        const start = Math.max(0, m.index - 60);
        // context: wide window (incl. the keyword itself) for disclaimer checks;
        // snippet: narrow excerpt shown as evidence.
        const context = text.slice(Math.max(0, m.index - 90), m.index + m[0].length + 70);
        return { snippet: text.slice(start, m.index + Math.min(m[0].length + 60, 220)), context, negated: hasNegationAround(text, m.index, m[0].length) || isNegatedDisclaimer(context) };
      }
    } catch { /* ignore bad pattern */ }
  }
  return null;
}

/**
 * Safety-disclaimer guard: phrases like "we never ask for OTP/fees" or
 * "OTP कभी नहीं मांगा जाता" describe good practice; they must NOT score as a
 * request. Checks ~90 chars before AND ~70 chars after a keyword hit for
 * negation + request language (Hindi/Marathi negation often follows the noun).
 */
const NEG_WORD = /\b(never|not|n't|without|beware|caution|alert|free|nil)\b|कभी नहीं|नहीं|नही|नका\b|नाही|बिना|मुफ्त|निःशुल्क|निशुल्क|मोफत/;
const ASK_WORD = /\b(ask|asks|asked|request|demand|charge|collect|share|need|take|pay)\b|मांगा|मांगते|मागितले|विचारले|घेतले|घेत नाही|शुल्क/;
export function hasNegationAround(text, idx, len = 0) {
  const before = String(text).slice(Math.max(0, idx - 90), idx);
  const after = String(text).slice(idx + len, idx + len + 70);
  const ctx = before + ' ' + after;
  return NEG_WORD.test(ctx) && ASK_WORD.test(ctx);
}
/** Back-compat: disclaimer check on preceding context only. */
export function isNegatedDisclaimer(before) {
  const ctx = String(before);
  return NEG_WORD.test(ctx) && ASK_WORD.test(ctx);
}

/**
 * @param {string} text job description / message / page text
 * @returns {{score:number, max:number, findings:Array, signals:Object}}
 */
export function analyseLinguistic(text = '') {
  const t = String(text || '');
  const findings = [];
  const signals = {};
  let raw = 0;
  for (const rule of RULES) {
    const hit = t ? findFirst(t, rule.patterns) : null;
    signals[rule.id] = Boolean(hit && !hit.negated);
    if (hit && hit.negated) {
      // Mentioned inside a safety disclaimer — informational only, 0 points.
      findings.push({
        id: `ling-${rule.id}`, category: 'linguistic', severity: 'info',
        title: `${rule.title} — mentioned in a safety disclaimer, not requested`, evidence: excerpt(hit.snippet), points: 0,
      });
    } else if (hit) {
      const inperson = ['cred-aadhaar', 'cred-pan', 'cred-bank'].includes(rule.id) && INPERSON_CUE.test(hit.snippet + ' ' + hit.context);
      const offDisclaimer = rule.id === 'offchannel' && OFFCHANNEL_DISCLAIMER.test(hit.context);
      // "No joining charge / no advance / no fees" without payment rails nearby
      // is a disclaimer, not a demand (mirrors the behavioural demand-cue rule).
      const winStart = Math.max(0, t.indexOf(hit.snippet.slice(0, 24)) - 100);
      const feeWindow = rule.id === 'fee-job' ? t.slice(winStart, winStart + 320) : '';
      const feeDisclaimer = rule.id === 'fee-job'
        && /\bno\s+(\w{1,12}\s)?(fees?|charges?|advance|payment|money)\b|without\s+(any\s+)?(fees?|charge|payment|advance)/i.test(feeWindow)
        && !/\bpay\b|upi|qr|₹|\brs\.?\b|\binr\b|refundable|bhejo|bhej|भरो|भरा/i.test(feeWindow);
      if (offDisclaimer || feeDisclaimer) {
        findings.push({ id: `ling-${rule.id}`, category: 'linguistic', severity: 'info', title: rule.id === 'fee-job' ? 'Fee language appears in a no-fee / no-charge statement — not a demand' : 'WhatsApp/Telegram mentioned in a cautionary context — not a push off-channel', evidence: excerpt(hit.snippet), points: 0 });
      } else if (inperson) {
        raw += 3;
        findings.push({ id: `ling-${rule.id}`, category: 'linguistic', severity: 'medium', title: `${rule.title} — but an in-person verification channel is mentioned (lower risk; still verify identity first)`, evidence: excerpt(hit.snippet), points: 3 });
      } else {
        raw += rule.weight;
        findings.push({
          id: `ling-${rule.id}`, category: 'linguistic', severity: rule.severity,
          title: rule.title, evidence: excerpt(hit.snippet), points: rule.weight,
        });
      }
    }
  }
  // Cap raw to a scale then normalise to MAX 35 with diminishing returns:
  // score = MAX * (1 - exp(-raw / 18)). Deterministic.
  const score = t ? Math.round(MAX * (1 - Math.exp(-raw / 18)) * 10) / 10 : 0;
  return { score, max: MAX, findings, signals, rawWeight: raw };
}
