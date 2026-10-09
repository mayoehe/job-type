/**
 * SSRF + DNS-rebinding protections for safe URL inspection.
 * - Only http/https allowed.
 * - Block localhost, private ranges, link-local, CGNAT, multicast, cloud metadata IPs.
 * - Every redirect hop is re-validated (URL + resolved IP).
 * - Response size / MIME / timeout / redirect-count caps enforced in inspect.js.
 */
import dns from 'node:dns/promises';
import net from 'node:net';

const METADATA_IPS = new Set(['169.254.169.254', 'fd00:ec2::254']);

export function isBlockedIp(ip) {
  if (!ip || !net.isIP(ip)) return true; // fail closed
  if (METADATA_IPS.has(ip)) return true;
  if (net.isIP(ip) === 4) {
    const o = ip.split('.').map(Number);
    const [a, b] = o;
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true; // link-local (incl. metadata)
    if (a === 0) return true;
    if (a >= 224) return true; // multicast/reserved
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    if (a === 192 && (b === 0 || b === 2)) return true; // documentation/benchmark edge
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a === 203 && b === 0 && o[2] === 113) return true;
  } else {
    const low = ip.toLowerCase();
    if (low === '::1' || low === '::') return true;
    if (low.startsWith('fc') || low.startsWith('fd')) return true; // unique local
    if (low.startsWith('fe80')) return true; // link-local
    if (low.startsWith('ff')) return true; // multicast
  }
  return false;
}

export function validateUrlAgainstPolicy(raw) {
  let u;
  try {
    u = new URL(String(raw).trim());
  } catch {
    return { ok: false, reason: 'URL is not parseable.' };
  }
  if (!['http:', 'https:'].includes(u.protocol)) return { ok: false, reason: `Blocked protocol "${u.protocol}". Only http/https are inspected.` };
  if (!u.hostname) return { ok: false, reason: 'URL has no hostname.' };
  const host = u.hostname.toLowerCase();
  if (['localhost'].includes(host) || host.endsWith('.localhost')) return { ok: false, reason: 'Localhost targets are blocked.' };
  if (host.endsWith('.internal') || host.endsWith('.local') || host.endsWith('.invalid')) return { ok: false, reason: 'Internal hostnames are blocked.' };
  if (u.username || u.password) return { ok: false, reason: 'URLs with embedded credentials are blocked.' };
  if (net.isIP(host) && isBlockedIp(host)) return { ok: false, reason: `IP literal ${host} is in a blocked range.` };
  if (host === '169.254.169.254' || host === 'metadata.google.internal') return { ok: false, reason: 'Cloud metadata endpoints are blocked.' };
  return { ok: true, url: u };
}

/** Resolve hostname to IPs and ensure none are blocked. Returns {ok, ips, reason}. */
export async function checkDns(host) {
  if (net.isIP(host)) {
    return isBlockedIp(host) ? { ok: false, ips: [host], reason: `IP ${host} is blocked.` } : { ok: true, ips: [host] };
  }
  let records = [];
  try {
    records = await dns.lookup(host, { all: true });
  } catch (e) {
    return { ok: false, ips: [], reason: `DNS resolution failed for ${host}.` };
  }
  const ips = records.map((r) => r.address);
  const blocked = ips.filter(isBlockedIp);
  if (blocked.length) return { ok: false, ips, reason: `Hostname resolves to blocked IP(s): ${blocked.join(', ')}.` };
  return { ok: true, ips };
}
