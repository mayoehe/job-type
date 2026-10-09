/**
 * C. URL & domain analysis — max 15 points.
 * PSL-aware parsing, typosquat edit-distance, homoglyph/punycode, misleading
 * subdomains, shorteners, suspicious TLD/paths, brand-vs-domain mismatch.
 * Domain AGE is supporting evidence only — never subtracts behavioural risk
 * (enforced in scoring.js via floors + no-negative-trust rule).
 */
import { parseDomain } from '../utils/psl.js';

export const MAX = 15;

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'rb.gy']);
const SUSPICIOUS_TLDS = new Set(['xyz', 'top', 'club', 'live', 'click', 'link', 'world', 'buzz', 'rest', 'quest']);
const TRUSTED_EMPLOYER_DOMAINS = ['infosys.com', 'tcs.com', 'wipro.com', 'hcltech.com', 'techmahindra.com', 'reliance.com', 'tata.com', 'tatamotors.com', 'flipkart.com', 'amazon.in', 'amazon.com', 'google.com', 'microsoft.com', 'ibm.com', 'accenture.com', 'cognizant.com', 'icici.com', 'hdfcbank.com', 'onlinesbi.com', 'statebankofindia.com', 'naukri.com', 'linkedin.com', 'indeed.com', 'upsc.gov.in', 'ssc.gov.in', 'ibps.in', 'employmentnews.gov.in'];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) for (let j = 1; j <= n; j++) {
    dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  }
  return dp[m][n];
}

function hasHomoglyphOrPunycode(host) {
  if (/xn--/.test(host)) return 'punycode-encoded label (possible homoglyph attack)';
  // non-ASCII letters in hostname
  if (/[^\x00-\x7F]/.test(host)) return 'non-ASCII characters in hostname (possible homoglyph)';
  return null;
}

export function analyseUrl(rawUrl) {
  const findings = [];
  const signals = {};
  let raw = 0;
  const add = (id, severity, title, evidence, weight) => {
    raw += weight;
    findings.push({ id: `url-${id}`, category: 'domain', severity, title, evidence, points: weight });
    signals[id] = true;
  };
  if (!rawUrl || !String(rawUrl).trim()) {
    return { score: 0, max: MAX, findings, signals, rawWeight: 0, parsed: null, note: 'no-url' };
  }
  let u;
  try { u = new URL(String(rawUrl).trim()); }
  catch { add('unparseable', 'medium', 'URL could not be parsed', String(rawUrl).slice(0, 120), 4); return { score: Math.min(MAX, raw), max: MAX, findings, signals, rawWeight: raw, parsed: null }; }

  const host = u.hostname.toLowerCase();
  const parsed = parseDomain(host);
  const reg = parsed.registrableDomain;

  // shortener
  if (SHORTENERS.has(reg) || SHORTENERS.has(host)) add('shortener', 'medium', `URL shortener hides the real destination (${host})`, host, 4);
  else signals.shortener = false;

  // punycode/homoglyph
  const hg = hasHomoglyphOrPunycode(host);
  if (hg) add('homoglyph', 'high', `Suspicious hostname encoding: ${hg}`, host, 6);
  else signals.homoglyph = false;

  // misleading subdomain: trusted brand as subdomain of unknown root, e.g. infosys.jobs-apply.xyz
  const sub = parsed.subdomain;
  const brandInSub = TRUSTED_EMPLOYER_DOMAINS.map((d) => d.split('.')[0]).find((b) => sub.includes(b));
  if (brandInSub && !TRUSTED_EMPLOYER_DOMAINS.includes(reg)) {
    add('misleading-subdomain', 'high', `Trusted brand "${brandInSub}" appears as a subdomain of unrelated domain ${reg}`, host, 6);
  } else signals['misleading-subdomain'] = false;

  // brand-in-path/query deception: e.g. example.xyz/infosys-careers
  const pathQ = (u.pathname + ' ' + u.search).toLowerCase();
  const brandInPath = TRUSTED_EMPLOYER_DOMAINS.map((d) => d.split('.')[0]).find((b) => pathQ.includes(b));
  if (brandInPath && !TRUSTED_EMPLOYER_DOMAINS.includes(reg) && !reg.includes(brandInPath)) {
    add('brand-in-path', 'medium', `Brand name "${brandInPath}" appears in URL path but domain is ${reg}`, u.pathname.slice(0, 120), 3);
  } else signals['brand-in-path'] = false;

  // typosquat edit distance on registrable label
  let closest = null, best = Infinity;
  const label = reg.split('.')[0];
  for (const td of TRUSTED_EMPLOYER_DOMAINS) {
    const tl = td.split('.')[0];
    if (label === tl) { best = 0; closest = td; break; }
    const d = levenshtein(label, tl);
    if (d < best) { best = d; closest = td; }
  }
  if (best === 1 || (best === 2 && label.length >= 6)) {
    add('typosquat', 'high', `Domain "${reg}" is ${best} edit(s) from trusted "${closest}" (possible typosquat)`, `${reg} ↔ ${closest}`, 6);
  } else signals.typosquat = false;

  // company-name-contains but wrong registrable: e.g. infosys-careers-apply.xyz
  if (best > 2) {
    const contains = TRUSTED_EMPLOYER_DOMAINS.map((d) => d.split('.')[0]).find((b) => b.length >= 4 && label.includes(b) && reg !== [...TRUSTED_EMPLOYER_DOMAINS].find((t) => t.split('.')[0] === b));
    if (contains) add('brand-contains-mismatch', 'medium', `Domain contains brand "${contains}" but is not the official domain (${reg})`, reg, 4);
    else signals['brand-contains-mismatch'] = false;
  }

  // suspicious TLD
  const tld = parsed.suffix.split('.').pop();
  if (SUSPICIOUS_TLDS.has(tld)) add('suspicious-tld', 'low', `Uncommon/low-reputation TLD ".${tld}" often abused in job scams`, '.' + tld, 2);
  else signals['suspicious-tld'] = false;

  // IP literal host
  if (parsed.isIp) add('ip-host', 'high', 'URL uses a raw IP address instead of a domain name', host, 5);
  else signals['ip-host'] = false;

  // excessive subdomains / long hostname
  if (host.split('.').length >= 5 || host.length > 60) add('obfuscated-host', 'low', 'Unusually deep/long hostname (possible obfuscation)', host.slice(0, 120), 2);
  else signals['obfuscated-host'] = false;

  // suspicious query: tokens, tracking ids for phishing kits
  if (/token=|sessionid=|account=|verify=|login/i.test(u.search) && u.search.length > 40) add('suspicious-query', 'low', 'Long tracking/verification query string typical of phishing kits', u.search.slice(0, 120), 2);
  else signals['suspicious-query'] = false;

  const score = Math.round(Math.min(MAX, MAX * (1 - Math.exp(-raw / 7))) * 10) / 10;
  return { score, max: MAX, findings, signals, rawWeight: raw, parsed };
}
