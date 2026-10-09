import express from 'express';
import cors from 'cors';
import { runScan, SCORING_DOC } from './scoring.js';
import { inspectUrl } from './inspect.js';
import { verifyEmployer } from './verify.js';
import { buildChecklist } from './checklist.js';
import { buildSafeApply } from './plan.js';
import { redactText } from './utils/redact.js';

export const app = express();
const PORT = process.env.PORT || 8787;
const ORIGIN = process.env.CORS_ORIGIN || '*';

app.use(cors({ origin: ORIGIN === '*' ? '*' : ORIGIN.split(',') }));
app.use(express.json({ limit: '256kb' }));
app.disable('x-powered-by');

// In-memory aggregate stats only (no personal data persistence).
const stats = { scans: 0, messages: 0, byLevel: { low: 0, caution: 0, suspicious: 0, high: 0, critical: 0 }, lastAt: null };

function redactResult(result) {
  // Belt & braces: redact all displayed evidence. Logs never include raw input.
  result.allFindings = result.allFindings.map((f) => ({ ...f, evidence: redactText(f.evidence) }));
  result.overrides = result.overrides.map((o) => ({ ...o, evidence: (o.evidence || []).map(redactText) }));
  if (result.safeApply) {
    result.safeApply.highlights = (result.safeApply.highlights || []).map((h) => ({ ...h, quote: redactText(h.quote) }));
    result.safeApply.steps = (result.safeApply.steps || []).map((s) => ({ ...s, detail: redactText(s.detail) }));
    result.safeApply.checklist.items = (result.safeApply.checklist?.items || []).map((i) => ({ ...i, detail: redactText(i.detail) }));
    if (result.safeApply.verification) {
      result.safeApply.verification.checks = (result.safeApply.verification.checks || []).map((c) => ({ ...c, evidence: redactText(c.evidence) }));
    }
    result.safeApply.protection = (result.safeApply.protection || []).map((g) => ({ ...g, findings: (g.findings || []).map((f) => ({ ...f, evidence: redactText(f.evidence) })) }));
  }
  return result;
}

function countScan(result, isMessage = false) {
  stats.scans++;
  if (isMessage) stats.messages++;
  if (stats.byLevel[result.level] !== undefined) stats.byLevel[result.level]++;
  stats.lastAt = new Date().toISOString();
}

/** Full listing-scan pipeline: inspect → score → verify → checklist → plan. */
export async function scanListing({ url = '', text = '', verifyOptions = {} }) {
  let inspection = { intel: { inspected: false, inspectNote: 'No URL provided; text-only analysis.' }, pageText: '', finalUrl: '', redirectCrossDomain: false, finalRegistrable: null, employerHints: {}, timestamps: { at: new Date().toISOString(), source: 'none' } };
  if (String(url).trim()) inspection = await inspectUrl(String(url).trim());
  const result = runScan({ text: String(text || ''), url: String(url || ''), intel: inspection.intel, pageText: inspection.pageText, employer: {} });
  const verification = await verifyEmployer({ text: String(text || '') + '\n' + (inspection.pageText || ''), url: String(url || ''), finalUrl: inspection.finalUrl || '', inspection: inspection.intel, ...verifyOptions });
  const checklist = buildChecklist({ scan: result, verification });
  result.safeApply = buildSafeApply({ scan: result, verification, checklist, text: String(text || ''), mode: 'listing' });
  result.safeApply.checklist = checklist;
  redactResult(result);
  result.intelligence = {
    domain: result.meta.registrableDomain, host: result.meta.urlHost,
    redirects: inspection.intel.redirects ?? null,
    https: inspection.intel.https ?? null,
    certValid: inspection.intel.certValid ?? null,
    reputationListed: inspection.intel.reputationListed ?? false,
    reputationSource: inspection.intel.reputationSource || null,
    domainAgeDays: inspection.intel.domainAgeDays ?? null,
    inspected: inspection.intel.inspected ?? false,
    inspectNote: inspection.intel.inspectNote || null,
    finalUrl: inspection.finalUrl || null,
    source: inspection.timestamps.source || 'jobshield-backend',
    at: inspection.timestamps.at,
  };
  return result;
}

/** Recruiter-message pipeline: same engine, text-only, no URL inspection. */
export async function scanMessage({ text = '', channel = 'whatsapp' }) {
  const allowed = ['whatsapp', 'email', 'offer', 'interview', 'payment'];
  const ch = allowed.includes(String(channel)) ? String(channel) : 'whatsapp';
  const result = runScan({ text: String(text || ''), url: '', intel: { inspected: false, inspectNote: `Message scan (${ch}): no URL inspection by design; analysis is local text + behaviour only.` }, pageText: '', employer: {} });
  const verification = await verifyEmployer({ text: String(text || ''), url: '', finalUrl: '', inspection: {}, fetchCareers: false });
  const checklist = buildChecklist({ scan: result, verification });
  result.safeApply = buildSafeApply({ scan: result, verification, checklist, text: String(text || ''), mode: 'message', channel: ch });
  result.safeApply.checklist = checklist;
  result.safeApply.channel = ch;
  redactResult(result);
  return result;
}

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'jobshield-backend', version: '1.0.0', time: new Date().toISOString() }));
app.get('/api/scoring-info', (_req, res) => res.json(SCORING_DOC));

app.post('/api/scan', async (req, res) => {
  try {
    const { url = '', text = '' } = req.body || {};
    if (!String(url).trim() && !String(text).trim()) {
      return res.status(400).json({ error: 'Provide a URL, pasted job text, or both.' });
    }
    if (String(text).length > 60_000) return res.status(413).json({ error: 'Text too long (max 60k chars).' });
    const result = await scanListing({ url: String(url || ''), text: String(text || '') });
    countScan(result);
    res.json(result);
  } catch (e) {
    console.error('[scan-error]', e?.message || e);
    res.status(500).json({ error: 'Scan failed safely. Try text-only analysis.' });
  }
});

app.post('/api/message', async (req, res) => {
  try {
    const { text = '', channel = 'whatsapp' } = req.body || {};
    if (!String(text).trim()) {
      return res.status(400).json({ error: 'Paste a recruiter message to scan it.' });
    }
    if (String(text).length > 60_000) return res.status(413).json({ error: 'Text too long (max 60k chars).' });
    const result = await scanMessage({ text: String(text || ''), channel });
    countScan(result, true);
    res.json(result);
  } catch (e) {
    console.error('[message-error]', e?.message || e);
    res.status(500).json({ error: 'Message scan failed safely. Please retry.' });
  }
});

app.get('/api/stats', (_req, res) => res.json({ ...stats, note: 'Anonymised aggregate counts only. No scanned content is retained.' }));

// Exported for integration tests; only listens when run directly.
if (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/').split('/').pop())) {
  app.listen(PORT, () => console.log(`[jobshield] backend listening on http://localhost:${PORT}`));
}
