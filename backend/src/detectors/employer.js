/**
 * E. Employer & evidence verification — max 10 points.
 * Scores FAILURE TO VERIFY as uncertainty (partial points), never as proof
 * of fraud on its own. Verified presence REDUCES this category's points
 * (it is the only category allowed to go down with positive evidence, and it
 * cannot offset other categories — floors in scoring.js enforce that).
 */
export const MAX = 10;

export function analyseEmployer(ev = {}) {
  const findings = [];
  const signals = {};
  let raw = 0;
  const add = (id, severity, title, evidence, weight) => {
    raw += weight;
    findings.push({ id: `emp-${id}`, category: 'employer', severity, title, evidence, points: weight });
    signals[id] = true;
  };
  const ok = (id, title, evidence) => {
    findings.push({ id: `emp-${id}`, category: 'employer', severity: 'info', title, evidence, points: 0 });
    signals[id] = false;
  };

  const hasUrl = Boolean(ev.hasUrl);
  const hasText = Boolean(ev.hasText);

  if (!hasUrl && !hasText) {
    add('no-input', 'low', 'Nothing verifiable provided', 'empty scan', 2);
    return { score: 2, max: MAX, findings, signals, rawWeight: raw };
  }

  // official website verifiability (heuristic from supplied hints / inspection)
  if (ev.officialDomain) ok('official-known', `Employer official domain noted: ${ev.officialDomain}`, ev.officialDomain);
  else add('no-official-domain', 'low', 'No verifiable official employer website could be established from the listing', 'no official domain reference found', 3);

  if (ev.vacancyOnOfficialSite) ok('vacancy-verified', 'Vacancy appears on the employer official careers page (as reported by verification check)', ev.vacancyUrl || 'careers page');
  else if (hasUrl || hasText) add('vacancy-unverified', 'low', 'Vacancy could not be corroborated on an official careers page — uncertainty, not proof of fraud', 'unverified', 3);

  if (ev.contactMatches) ok('contact-match', 'Recruiter contact matches independently verifiable company information', ev.contactMatches);
  else if (ev.contactPresent) add('contact-unverifiable', 'medium', 'Recruiter contact could not be matched to verifiable company information', String(ev.contactPresent).slice(0, 120), 3);
  else add('contact-missing', 'low', 'No verifiable recruiter contact information present', 'missing contact', 2);

  if (ev.govtClaim && !ev.govtCorroborated) add('govt-uncorroborated', 'medium', 'Government-recruitment claim could not be corroborated on an official .gov.in domain', 'uncorroborated govt claim', 4);
  else if (ev.govtClaim && ev.govtCorroborated) ok('govt-verified', 'Government vacancy corroborated on official domain', ev.govtCorroborated);
  else signals['govt-uncorroborated'] = false;

  if (ev.applicationDomainLinked) ok('domain-linked', 'Application domain is linked from a trusted employer source', ev.applicationDomainLinked);
  else if (hasUrl) add('domain-unlinked', 'low', 'Application domain is not demonstrably linked from a trusted employer source', 'unlinked', 2);

  const score = Math.round(Math.min(MAX, raw) * 10) / 10;
  return { score, max: MAX, findings, signals, rawWeight: raw };
}
