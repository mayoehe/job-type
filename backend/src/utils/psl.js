/**
 * Minimal Public-Suffix-List-aware domain parsing.
 * We ship a compact suffix list (common + Indian suffixes) so the scanner
 * has no hard dependency on network access. For full PSL coverage operators
 * can drop in the `psl` npm package — the interface matches it.
 */

const SUFFIXES = new Set([
  // Indian / common multi-level suffixes
  'co.in', 'org.in', 'net.in', 'gen.in', 'firm.in', 'ind.in', 'ac.in', 'edu.in',
  'res.in', 'gov.in', 'nic.in', 'mil.in',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.jp', 'co.kr', 'com.au', 'net.au',
  'org.au', 'co.nz', 'com.br', 'com.mx', 'co.za',
  // common single-level
  'com', 'org', 'net', 'io', 'ai', 'dev', 'app', 'in', 'uk', 'us', 'info',
  'biz', 'co', 'me', 'tech', 'jobs', 'work', 'site', 'online', 'store',
  'top', 'xyz', 'club', 'live', 'world', 'link', 'click', 'gov', 'edu',
]);

/** Lower-case, strip trailing dot, strip port handling left to caller. */
export function normaliseHost(host) {
  return String(host || '').trim().toLowerCase().replace(/\.$/, '');
}

export function isIpHost(host) {
  const h = normaliseHost(host).replace(/^\[|\]$/g, '');
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return true;
  if (h.includes(':')) return true; // IPv6 literal
  return false;
}

/**
 * Split host into { subdomain, registrableDomain, suffix }.
 * e.g. "careers.infosys-secure.example.co.in" -> suffix co.in, registrable example.co.in
 */
export function parseDomain(host) {
  const h = normaliseHost(host);
  if (!h || isIpHost(h)) return { host: h, subdomain: '', registrableDomain: h, suffix: '', isIp: true };
  const parts = h.split('.').filter(Boolean);
  if (parts.length < 2) return { host: h, subdomain: '', registrableDomain: h, suffix: '', isIp: false };
  // longest suffix match
  for (let len = 3; len >= 1; len--) {
    const cand = parts.slice(-len).join('.');
    if (SUFFIXES.has(cand)) {
      const suffix = cand;
      const rest = parts.slice(0, -len);
      const registrable = rest.length ? rest[rest.length - 1] + '.' + suffix : suffix;
      const subdomain = rest.length > 1 ? rest.slice(0, -1).join('.') : '';
      return { host: h, subdomain, registrableDomain: registrable, suffix, isIp: false };
    }
  }
  // fallback: last label is suffix
  const suffix = parts[parts.length - 1];
  const registrable = parts.slice(-2).join('.');
  const subdomain = parts.length > 2 ? parts.slice(0, -2).join('.') : '';
  return { host: h, subdomain, registrableDomain: registrable, suffix, isIp: false };
}

export function registrableOf(host) {
  return parseDomain(host).registrableDomain;
}
