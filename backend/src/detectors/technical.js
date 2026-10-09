/**
 * D. Technical security signals — max 10 points.
 * CRITICAL RULE: valid HTTPS / old domain / clean reputation NEVER subtract
 * behavioural risk. This detector only ADDS points for negative signals and
 * reports clean/unknown checks as informational (0 points).
 */
export const MAX = 10;

/**
 * @param {Object} intel { https, certValid, certExpired, hostnameMismatch, tlsError,
 *   dnsOk, redirects, reputationListed, hostingSuspicious, domainAgeDays, inspected, inspectNote }
 */
export function analyseTechnical(intel = {}) {
  const findings = [];
  const signals = {};
  let raw = 0;
  const add = (id, severity, title, evidence, weight) => {
    raw += weight;
    findings.push({ id: `tech-${id}`, category: 'technical', severity, title, evidence, points: weight });
    signals[id] = true;
  };
  const info = (id, title, evidence) => {
    findings.push({ id: `tech-${id}`, category: 'technical', severity: 'info', title, evidence, points: 0 });
    signals[id] = false;
  };

  if (intel.inspected === false) {
    info('not-inspected', 'Page could not be inspected — treated as UNKNOWN, not safe', intel.inspectNote || 'inspection unavailable');
    return { score: 0, max: MAX, findings, signals, rawWeight: 0 };
  }

  if (intel.tlsError || intel.certExpired || intel.hostnameMismatch) {
    add('tls-problem', 'medium', `TLS/certificate problem${intel.certExpired ? ' (expired)' : ''}${intel.hostnameMismatch ? ' (hostname mismatch)' : ''}`, intel.tlsError || 'certificate invalid', 4);
  } else if (intel.https && intel.certValid) {
    info('https-valid', 'Valid HTTPS observed — encrypts the connection but does NOT prove the recruiter is legitimate', 'https + valid cert');
  } else if (intel.https === false) {
    add('no-https', 'medium', 'Site does not use HTTPS for its application page', 'http only', 4);
  } else signals['tls-problem'] = false;

  if (intel.dnsOk === false) add('dns-anomaly', 'low', 'DNS resolution anomaly during inspection', intel.inspectNote || 'dns failed', 2);
  else signals['dns-anomaly'] = false;

  if (typeof intel.redirects === 'number' && intel.redirects >= 3) add('redirect-chain', 'medium', `Long redirect chain (${intel.redirects} hops)`, `${intel.redirects} redirects`, 3);
  else if (typeof intel.redirects === 'number') info('redirects-ok', `Redirect chain length: ${intel.redirects}`, `${intel.redirects} hop(s)`);

  if (intel.reputationListed) add('reputation-listed', 'high', `Domain/IP appears in threat-intel feed (${intel.reputationSource || 'local feed'})`, intel.reputationListed, 6);
  else info('reputation-clean', 'No threat-intel listing in checked local feeds — absence of listing is not proof of safety', 'checked: local blocklist');

  if (intel.hostingSuspicious) add('hosting-suspicious', 'low', 'Hosting/IP anomaly noted (e.g. freshly seen host, parking ASN)', String(intel.hostingSuspicious), 2);

  // Domain age: supporting context ONLY. Never negative points, never trust credit.
  if (typeof intel.domainAgeDays === 'number') {
    if (intel.domainAgeDays <= 90) add('new-domain', 'low', `Recently created domain (~${intel.domainAgeDays} days old) — weak supporting signal`, `${intel.domainAgeDays} days`, 2);
    else info('domain-aged', `Domain age ~${intel.domainAgeDays} days — age alone does not establish legitimacy`, `${intel.domainAgeDays} days`);
  }

  const score = Math.round(Math.min(MAX, MAX * (1 - Math.exp(-raw / 5))) * 10) / 10;
  return { score, max: MAX, findings, signals, rawWeight: raw };
}
