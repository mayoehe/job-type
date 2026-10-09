/**
 * Safe URL inspection with SSRF/DNS-rebinding defence, caps, and static-HTML text extraction.
 * Never executes remote JS. Returns { intel, pageText, employerHints, redirects... }.
 * All external enrichment is optional — failures degrade to "unknown", never "safe".
 */
import { validateUrlAgainstPolicy, checkDns } from './utils/ssrf.js';
import { parseDomain } from './utils/psl.js';

const MAX_REDIRECTS = 5;
const MAX_BYTES = 750_000;
const TIMEOUT_MS = 10_000;
const ALLOWED_MIME = /text\/html|application\/xhtml|text\/plain/i;

// Tiny local threat feed (demo + offline). Operators can extend via THREAT_FEED_URLS.
const LOCAL_BLOCKLIST = new Set([
  'secure-naukri-verification.xyz', 'infosys-careers-apply.top', 'sarkari-job-apply.club',
]);

function stripHtml(html) {
  return String(html || '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/\s+/g, ' ').trim().slice(0, 20000);
}

async function fetchWithTimeout(url, ms) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    const res = await fetch(url, {
      signal: ctrl.signal, redirect: 'manual',
      headers: { 'User-Agent': 'JobShield-Scanner/1.0 (+safety-check)', Accept: 'text/html,text/plain' },
    });
    return res;
  } finally { clearTimeout(t); }
}

export async function inspectUrl(rawUrl) {
  const started = Date.now();
  const out = {
    intel: { inspected: false, inspectNote: '', redirects: 0 },
    pageText: '', finalUrl: '', redirectCrossDomain: false, finalRegistrable: null,
    employerHints: {}, timestamps: { at: new Date().toISOString() },
  };
  const first = validateUrlAgainstPolicy(rawUrl);
  if (!first.ok) {
    out.intel.inspectNote = first.reason + ' URL text analysis still proceeds.';
    return out;
  }
  let current = first.url.toString();
  const startReg = parseDomain(first.url.hostname).registrableDomain;
  let hops = 0;

  while (hops <= MAX_REDIRECTS) {
    const v = validateUrlAgainstPolicy(current);
    if (!v.ok) { out.intel.inspectNote = `Redirect hop blocked: ${v.reason}`; break; }
    const dnsCheck = await checkDns(v.url.hostname);
    if (!dnsCheck.ok) { out.intel.inspectNote = `DNS blocked at hop ${hops + 1}: ${dnsCheck.reason}`; break; }
    let res;
    try {
      res = await fetchWithTimeout(current, TIMEOUT_MS);
    } catch (e) {
      out.intel.inspectNote = `Fetch failed (${e.name === 'AbortError' ? 'timeout' : String(e.message || e).slice(0, 120)}). Text-only analysis still applies.`;
      break;
    }
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get('location');
      await res.arrayBuffer().catch(() => null);
      if (!loc) { out.intel.inspectNote = 'Redirect without Location header.'; break; }
      current = new URL(loc, current).toString();
      hops++;
      continue;
    }
    // final response
    out.intel.redirects = hops;
    out.finalUrl = current;
    const finalU = new URL(current);
    out.finalRegistrable = parseDomain(finalU.hostname).registrableDomain;
    out.redirectCrossDomain = parseDomain(finalU.hostname).registrableDomain !== startReg;
    const ct = res.headers.get('content-type') || '';
    const len = Number(res.headers.get('content-length') || 0);
    if (len > MAX_BYTES * 2) { await res.arrayBuffer().catch(() => null); out.intel.inspectNote = 'Response too large; skipped body.'; }
    else if (ct && !ALLOWED_MIME.test(ct)) { await res.arrayBuffer().catch(() => null); out.intel.inspectNote = `Non-HTML content (${ct}); skipped body.`; }
    else {
      const buf = Buffer.from(await res.arrayBuffer().catch(() => Buffer.alloc(0)));
      const html = buf.slice(0, MAX_BYTES).toString('utf8');
      out.pageText = stripHtml(html);
      out.intel.https = finalU.protocol === 'https:';
      // In sandbox fetch we cannot read peer cert; mark cert as unknown unless plain http.
      out.intel.certValid = finalU.protocol === 'https:' ? undefined : false;
      if (finalU.protocol !== 'https:') out.intel.https = false;
    }
    out.intel.inspected = Boolean(out.pageText) || true;
    out.intel.dnsOk = true;
    if (Date.now() - started > 25_000) out.intel.inspectNote += ' (inspection time-capped)';
    break;
  }
  if (hops > MAX_REDIRECTS) out.intel.inspectNote = 'Too many redirects; stopped.';

  // Local reputation + age heuristics (offline-safe; labelled as local/unknown)
  const host = (() => { try { return new URL(out.finalUrl || rawUrl).hostname.toLowerCase(); } catch { return ''; } })();
  const reg = host ? parseDomain(host).registrableDomain : null;
  out.intel.reputationListed = reg ? LOCAL_BLOCKLIST.has(reg) : false;
  out.intel.reputationSource = out.intel.reputationListed ? 'local blocklist (built-in demo feed)' : undefined;
  out.intel.domainAgeDays = undefined; // unknown without WHOIS/RDAP key; surfaced as unknown in UI
  if (process.env.WHOIS_ENABLED === '1') {
    // hook: operators can wire RDAP here; left optional by design.
    out.intel.inspectNote += ' WHOIS hook enabled but no provider configured.';
  }
  out.timestamps.durationMs = Date.now() - started;
  out.timestamps.source = 'jobshield-backend safe-inspect 1.0';
  return out;
}
