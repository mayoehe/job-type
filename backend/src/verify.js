/**
 * Employer verification module (Safe Apply Assistant).
 * - Identifies the claimed employer + advertised position from listing text.
 * - Resolves the official domain ONLY from the curated offline directory
 *   (src/data/employers.json). Never guesses from names, HTTPS, or appearance.
 * - Compares listing domain vs official domain; classifies recruiter emails.
 * - Optionally corroborates the vacancy against the official careers page
 *   using the same SSRF-guarded static fetch as the main scanner.
 * - Every check returns { status: 'verified'|'mismatch'|'could-not-verify',
 *   evidence, source }. Absence of evidence is NEVER reported as fraud.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseDomain } from './utils/psl.js';
import { excerpt } from './utils/redact.js';

const dir = dirname(fileURLToPath(import.meta.url));
const DB = JSON.parse(readFileSync(join(dir, 'data/employers.json'), 'utf8'));
const SOURCE = `JobShield curated employer directory v${DB.version} (offline heuristic — absence means unknown, not illegitimate)`;

const FREE_MAIL = /gmail|yahoo|rediffmail|outlook|hotmail|protonmail|zoho|gmx/i;

export function findEmployerEntry(text) {
  const t = String(text || '').toLowerCase();
  const sorted = [...DB.employers].flatMap((e) => e.names.map((n) => ({ name: n, entry: e }))).sort((a, b) => b.name.length - a.name.length);
  for (const { name, entry } of sorted) {
    if (name.length >= 3 && t.includes(name)) return { name, entry };
  }
  return null;
}

/** Best-effort claimed-employer + position extraction (labelled as heuristic). */
export function extractClaim(text = '') {
  const t = String(text || '');
  const dirHit = findEmployerEntry(t);
  let employer = dirHit ? dirHit.name : null;
  if (!employer) {
    const m = t.match(/([A-Z][A-Za-z&., ]{2,50}?)\s+(is hiring|hiring for|is looking for|invites applications)/)
      || t.match(/(?:greetings|hello|hi)\s+from\s+([A-Z][A-Za-z&., ]{2,50})/i)
      || t.match(/careers?\s+(?:at|with)\s+([A-Z][A-Za-z&., ]{2,50})/i);
    if (m) employer = m[1].trim();
  }
  let position = null;
  const pm = t.match(/hiring\s+(?:a|an)\s+([A-Z][\w /&.,-]{2,60})/)
    || t.match(/(?:role|position|opening(?:s)?\s+for)\s*[:\-]\s*([^\n.]{3,80})/i)
    || t.match(/opening[s]?\s+for\s+([^\n.]{3,80})/i);
  if (pm) position = pm[1].trim().replace(/\s+/g, ' ').slice(0, 80);
  const ref = (t.match(/(?:advt|advertisement|notification|circular|ref(?:erence)?)\s*(?:no|number|#)?\s*[:\-]?\s*([A-Z0-9/\-]{3,30})/i) || [])[1] || null;
  const emails = [...t.matchAll(/[\w.+-]+@([\w.-]+\.[a-z]{2,})/gi)].map((m) => ({ address: m[0].toLowerCase(), domain: m[1].toLowerCase() }));
  return { employer, position, ref, emails };
}

function registrableOfUrl(url) {
  try { return parseDomain(new URL(String(url)).hostname).registrableDomain; } catch { return null; }
}

/** Significant vacancy keywords for careers-page corroboration. */
export function vacancyKeywords({ position, ref }) {
  const words = new Set();
  if (ref) words.add(String(ref).toLowerCase());
  for (const w of String(position || '').toLowerCase().split(/[^a-z0-9+]+/)) {
    if (w.length >= 4 && !['with', 'from', 'role', 'post', 'hiring', 'senior', 'junior'].includes(w)) words.add(w);
  }
  return [...words].slice(0, 6);
}

/**
 * @param {Object} opts { text, url, finalUrl, inspection, fetchCareers=true, inspectFn }
 * inspectFn defaults to the SSRF-guarded inspectUrl (injectable for tests).
 */
export async function verifyEmployer(opts = {}) {
  const { text = '', url = '', finalUrl = '', inspection = {}, fetchCareers = true, inspectFn = null } = opts;
  const checks = [];
  const push = (id, label, status, evidence, source) => checks.push({ id, label, status, evidence: excerpt(String(evidence || '').slice(0, 220)), source });

  const claim = extractClaim(text);
  push('claimed-employer', 'Claimed employer identified', claim.employer ? 'verified' : 'could-not-verify',
    claim.employer ? `Claimed employer mention: "${claim.employer}"${claim.position ? `; advertised position: "${claim.position}"` : '; no clear position title found'}` : 'No identifiable employer name in the listing text.',
    'Listing text (heuristic extraction)');
  if (claim.position) push('claimed-position', 'Advertised position identified', 'verified', `Position: "${claim.position}"${claim.ref ? ` (ref ${claim.ref})` : ''}`, 'Listing text (heuristic extraction)');
  else push('claimed-position', 'Advertised position identified', 'could-not-verify', 'No clear position title or reference number found in the listing.', 'Listing text (heuristic extraction)');

  const dirHit = claim.employer ? findEmployerEntry(claim.employer + ' ' + text) : null;
  const officialDomain = dirHit?.entry?.officialDomain || null;
  if (officialDomain) push('official-website', "Employer's official website", 'verified', `Official domain ${officialDomain} (${dirHit.entry.type})`, SOURCE);
  else push('official-website', "Employer's official website", 'could-not-verify', claim.employer ? `“${claim.employer}” is not in the curated directory, so no independent official domain can be stated. Locate it yourself (search the company name; do not trust links in the message).` : 'No employer identified, so no official website can be resolved.', SOURCE);

  const listingReg = registrableOfUrl(finalUrl || url);
  const isPlatform = listingReg && DB.platforms.some((p) => listingReg === p || listingReg.endsWith('.' + p));
  if (!listingReg) push('domain-comparison', 'Portal domain vs official domain', 'could-not-verify', 'No application URL was provided, so no domain comparison is possible.', 'Scan input');
  else if (!officialDomain) push('domain-comparison', 'Portal domain vs official domain', 'could-not-verify', `Listing domain is ${listingReg}, but no independent official domain is established for comparison.`, 'Scan input + ' + SOURCE);
  else if (listingReg === officialDomain || listingReg.endsWith('.' + officialDomain)) push('domain-comparison', 'Portal domain vs official domain', 'verified', `Listing domain ${listingReg} matches the official domain ${officialDomain}.`, 'Scan input + ' + SOURCE);
  else if (isPlatform) push('domain-comparison', 'Portal domain vs official domain', 'could-not-verify', `Listing is on third-party platform ${listingReg} while the employer domain is ${officialDomain} — expected for platform postings; verify the recruiter profile and the vacancy on the official site.`, 'Scan input + ' + SOURCE);
  else push('domain-comparison', 'Portal domain vs official domain', 'mismatch', `Listing domain ${listingReg} does NOT match the official domain ${officialDomain}. Type the official address yourself to compare.`, 'Scan input + ' + SOURCE);

  if (!claim.emails.length) push('recruiter-email', 'Recruiter email vs official domain', 'could-not-verify', 'No recruiter email address found in the listing.', 'Listing text');
  else {
    const lines = [];
    let verdict = 'could-not-verify';
    for (const e of claim.emails.slice(0, 4)) {
      if (officialDomain && (e.domain === officialDomain || e.domain.endsWith('.' + officialDomain))) { lines.push(`${e.address} — matches official domain`); verdict = 'verified'; }
      else if (FREE_MAIL.test(e.domain)) { lines.push(`${e.address} — free-mail provider${officialDomain ? `, not ${officialDomain}` : ''}`); if (verdict !== 'verified') verdict = officialDomain ? 'mismatch' : 'could-not-verify'; }
      else if (officialDomain) { lines.push(`${e.domain} — does not match ${officialDomain}`); if (verdict !== 'verified') verdict = 'mismatch'; }
      else lines.push(`${e.address} — no official domain to compare against`);
    }
    push('recruiter-email', 'Recruiter email vs official domain', verdict, lines.join('; '), 'Listing text' + (officialDomain ? ' + ' + SOURCE : ''));
  }

  // Vacancy corroboration against the official careers page (best-effort, safe fetch).
  const keywords = vacancyKeywords(claim);
  const careersUrl = dirHit?.entry?.careersUrl || (officialDomain ? `https://www.${officialDomain}/careers` : null);
  const careersIsCandidate = Boolean(officialDomain && !dirHit?.entry?.careersUrl);
  if (!officialDomain) push('vacancy-corroboration', 'Vacancy on official careers page', 'could-not-verify', 'No official website established, so corroboration is not possible. This is uncertainty, not proof of fraud.', SOURCE);
  else if (!keywords.length) push('vacancy-corroboration', 'Vacancy on official careers page', 'could-not-verify', `Official site: ${officialDomain}${careersUrl ? ` (careers: ${careersUrl}${careersIsCandidate ? ' — candidate path, unverified' : ''})` : ''}. No position title/reference found to search for — check manually.`, SOURCE);
  else if (!fetchCareers) push('vacancy-corroboration', 'Vacancy on official careers page', 'could-not-verify', `Official careers page: ${careersUrl}${careersIsCandidate ? ' (candidate path, unverified)' : ''}. Automatic check skipped — open it yourself (type the address) and search for “${keywords.slice(0, 3).join(' / ')}”.`, SOURCE);
  else {
    try {
      const inspect = inspectFn || (await import('./inspect.js')).inspectUrl;
      const res = await inspect(careersUrl);
      const hay = String(res.pageText || '').toLowerCase();
      const hits = keywords.filter((k) => hay && hay.includes(k));
      if (hits.length >= Math.min(2, keywords.length) && hits.length > 0) push('vacancy-corroboration', 'Vacancy on official careers page', 'verified', `Found ${hits.length}/${keywords.length} vacancy keyword(s) (${hits.slice(0, 3).join(', ')}) on ${careersUrl}.`, `Live fetch of official careers page at ${res.timestamps?.at || 'check time'} (SSRF-guarded static fetch)`);
      else if (keywords.length === 1 && hits.length === 1) push('vacancy-corroboration', 'Vacancy on official careers page', 'verified', `Found vacancy reference “${hits[0]}” on ${careersUrl}.`, `Live fetch of official careers page at ${res.timestamps?.at || 'check time'} (SSRF-guarded static fetch)`);
      else push('vacancy-corroboration', 'Vacancy on official careers page', 'could-not-verify', `Checked ${careersUrl} but vacancy keywords (${keywords.slice(0, 3).join(', ')}) were not found there (${res.intel?.inspectNote || 'page fetched, no match'}). Listings are often absent from public pages — check with the employer directly.`, `Live fetch of official careers page at ${res.timestamps?.at || 'check time'} (SSRF-guarded static fetch)`);
    } catch (e) {
      push('vacancy-corroboration', 'Vacancy on official careers page', 'could-not-verify', `Could not fetch ${careersUrl} (${String(e?.message || e).slice(0, 100)}). Check manually — do not treat this as safe or fraudulent.`, SOURCE);
    }
  }

  const overall = checks.some((c) => c.status === 'mismatch' && ['domain-comparison', 'recruiter-email'].includes(c.id))
    ? 'mismatch'
    : checks.some((c) => c.status === 'verified' && ['domain-comparison', 'vacancy-corroboration', 'recruiter-email'].includes(c.id))
      ? 'verified' : 'could-not-verify';

  return {
    claimedEmployer: claim.employer, claimedPosition: claim.position, reference: claim.ref,
    officialDomain, careersUrl, isPlatform: Boolean(isPlatform), listingDomain: listingReg,
    overall, checks, source: SOURCE,
  };
}
