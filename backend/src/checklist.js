/**
 * Safe-application checklist generator (Safe Apply Assistant).
 * Every item is derived from actual scan evidence — never hardcoded pass/fail.
 * States: 'passed' (evidence supports safety) | 'failed' (evidence of risk) |
 * 'unverified' (insufficient evidence). All auto items carry auto:true plus the
 * finding/verification ids they were derived from, so the UI can distinguish
 * automatic results from later user confirmations.
 */

export function buildChecklist({ scan, verification }) {
  const findings = scan?.allFindings || [];
  const has = (frag, sevs = ['critical', 'high']) => findings.filter((f) => f.id.includes(frag) && sevs.includes(f.severity));
  const hasAny = (frag) => findings.filter((f) => f.id.includes(frag));
  const items = [];
  const item = (id, label, state, detail, derivedFrom) => items.push({ id, label, state, auto: true, detail, derivedFrom });

  // 1. official website
  if (verification?.officialDomain) item('official-site', "Independently locate the employer's official website", 'passed', `Official domain established: ${verification.officialDomain}. Still type it yourself rather than clicking message links.`, ['verify:official-website']);
  else item('official-site', "Independently locate the employer's official website", 'unverified', 'No official website could be established from the listing. Search the company name independently.', ['verify:official-website']);

  // 2. vacancy corroboration
  const corr = verification?.checks?.find((c) => c.id === 'vacancy-corroboration');
  if (corr?.status === 'verified') item('vacancy', 'Confirm the vacancy through the official careers page or recruiter', 'passed', corr.evidence, ['verify:vacancy-corroboration']);
  else item('vacancy', 'Confirm the vacancy through the official careers page or recruiter', 'unverified', corr?.evidence || 'Vacancy could not be corroborated — check with the employer directly.', ['verify:vacancy-corroboration']);

  // 3. application domain
  const domainBad = [...has('typosquat'), ...has('misleading-subdomain'), ...has('brand-identity-mismatch'), ...has('homoglyph'), ...has('brand-contains-mismatch'), ...has('ip-host')];
  const cmp = verification?.checks?.find((c) => c.id === 'domain-comparison');
  if (domainBad.length) item('app-domain', 'Verify the application domain is legitimately associated with the employer', 'failed', domainBad.map((f) => f.title).join(' | ').slice(0, 240), domainBad.map((f) => f.id));
  else if (cmp?.status === 'verified') item('app-domain', 'Verify the application domain is legitimately associated with the employer', 'passed', cmp.evidence, ['verify:domain-comparison']);
  else if (!verification?.listingDomain) item('app-domain', 'Verify the application domain is legitimately associated with the employer', 'unverified', 'No application URL was provided.', ['verify:domain-comparison']);
  else item('app-domain', 'Verify the application domain is legitimately associated with the employer', 'unverified', cmp?.evidence || 'Domain association could not be confirmed — compare carefully with the official domain.', ['verify:domain-comparison']);

  // 4. recruiter identity
  const recBad = has('recruiter-domain-mismatch');
  const recCheck = verification?.checks?.find((c) => c.id === 'recruiter-email');
  if (recBad.length || recCheck?.status === 'mismatch') item('recruiter', 'Confirm the recruiter’s identity using independently obtained contact info', 'failed', [...recBad.map((f) => f.title), recCheck?.status === 'mismatch' ? recCheck.evidence : ''].filter(Boolean).join(' | ').slice(0, 240), [...recBad.map((f) => f.id), 'verify:recruiter-email']);
  else if (recCheck?.status === 'verified') item('recruiter', 'Confirm the recruiter’s identity using independently obtained contact info', 'passed', recCheck.evidence, ['verify:recruiter-email']);
  else item('recruiter', 'Confirm the recruiter’s identity using independently obtained contact info', 'unverified', 'No verifiable recruiter contact found — obtain one from the official website, not the message.', ['verify:recruiter-email']);

  // 5. fees
  const feeBad = [...has('payment-for-job'), ...has('fee-job')];
  if (feeBad.length) item('fees', 'Check whether any recruitment or interview fees are requested', 'failed', 'A payment is demanded to secure the job or release the offer. Do not pay — genuine employers do not charge candidates.', feeBad.map((f) => f.id));
  else item('fees', 'Check whether any recruitment or interview fees are requested', 'passed', 'No recruitment-fee demand was detected in this listing. Stay alert if one appears later.', hasAny('fee-job').map((f) => f.id));

  // 6. personal-information collection
  const piiBad = [...has('early-sensitive-harvest'), ...has('cred-aadhaar'), ...has('cred-pan'), ...has('cred-bank'), ...has('excessive-collection')];
  if (piiBad.length) item('pii-collection', 'Review what personal information the application collects', 'failed', piiBad.map((f) => f.title).join(' | ').slice(0, 240), piiBad.map((f) => f.id));
  else item('pii-collection', 'Review what personal information the application collects', 'passed', 'No premature harvesting of identity/financial documents was detected.', []);

  // 7. OTP / PIN / passwords
  const otpBad = [...has('otp-critical'), ...has('otp-pin-harvest')];
  if (otpBad.length) item('otp', 'Confirm that no OTP, UPI PIN, or banking password is requested', 'failed', 'This listing asks for OTPs, UPI PINs or banking credentials. Never share these — no genuine hiring process needs them.', otpBad.map((f) => f.id));
  else item('otp', 'Confirm that no OTP, UPI PIN, or banking password is requested', 'passed', 'No OTP / UPI PIN / password request was detected.', []);

  // 8. offer consistency
  const incBad = [...has('implausible-salary'), ...has('fake-govt-portal'), ...hasAny('contradiction').filter((f) => f.severity !== 'info')];
  if (incBad.length) item('offer-consistency', 'Review the offer letter and instructions for inconsistencies', 'failed', incBad.map((f) => f.title).join(' | ').slice(0, 240), incBad.map((f) => f.id));
  else if (scan?.score >= 40) item('offer-consistency', 'Review the offer letter and instructions for inconsistencies', 'unverified', 'Other risk signals are present — re-read the offer critically before proceeding.', []);
  else item('offer-consistency', 'Review the offer letter and instructions for inconsistencies', 'passed', 'No salary/requirement contradictions or impersonation markers were detected.', []);

  const counts = {
    passed: items.filter((i) => i.state === 'passed').length,
    failed: items.filter((i) => i.state === 'failed').length,
    unverified: items.filter((i) => i.state === 'unverified').length,
  };
  return { items, counts, total: items.length };
}
