/**
 * Safe Apply Assistant acceptance tests (spec section 10).
 * Uses pipeline functions directly (no network) plus one ephemeral-HTTP check.
 * Run: node --test "tests/*.test.js"  (via npm test)
 */
import { describe, it, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { scanListing, scanMessage, app } from '../src/index.js';

const SCAM = 'Dear Candidate, Congratulations! Selected for Infosys work from home, salary Rs 85000, no interview. Pay refundable registration fee Rs 2499 via UPI and share Aadhaar card, PAN, bank account plus OTP on WhatsApp within 2 hours.';
const CLEAN_INTEL_URL = ''; // text-only keeps tests hermetic (no network)
const LEGIT = 'Infosys is hiring a Senior React Developer in Bengaluru. Requirements: 4+ years experience, TypeScript. Process: online assessment, two technical interviews, HR round. Apply via infosys.com/careers. Original documents verified in person after provisional selection. We never ask for fees or OTPs. Contact: careers@infosys.com. About the company: founded in 1981, registered office Bengaluru.';

async function listing(text, url = '') {
  return scanListing({ url, text, verifyOptions: { fetchCareers: false } });
}

describe('Safe Apply Assistant acceptance criteria', () => {
  it('1. high-risk listing produces relevant warnings + actionable steps', async () => {
    const r = await listing(SCAM);
    assert.ok(['high', 'critical'].includes(r.level), `level=${r.level} score=${r.score}`);
    assert.equal(r.safeApply.verdict, 'avoid');
    assert.ok(r.safeApply.whyUnsafe.length > 20);
    assert.ok(r.safeApply.steps.length >= 2, 'expected multiple steps');
    for (const s of r.safeApply.steps) assert.ok(s.derivedFrom.length > 0, 'every step must cite evidence');
    const titles = r.safeApply.steps.map((s) => s.title).join('|');
    assert.match(titles, /Do not pay/i);
    assert.match(titles, /OTP/i);
  });

  it('2. technically clean but behaviourally fraudulent listing remains high-risk', async () => {
    // cred + fee text, clean-looking URL, no live inspection (worst case for us)
    const r = await listing(SCAM, 'https://careers-infosys-apply.com/apply');
    assert.ok(r.score >= 60, `score=${r.score}`);
    assert.ok(['avoid', 'verify'].includes(r.safeApply.verdict));
  });

  it('3. legitimate appropriate-stage documentation is not labelled fraudulent', async () => {
    const r = await listing(LEGIT, 'https://www.infosys.com/careers/');
    assert.ok(r.score < 40, `score=${r.score}`);
    assert.equal(r.safeApply.verdict, 'proceed');
    const crit = r.allFindings.filter((f) => f.severity === 'critical');
    assert.equal(crit.length, 0);
  });

  it('4. missing employer evidence yields Could Not Verify, never fabricated verification', async () => {
    const r = await listing('Hiring delivery executives in Pune. Walk in Saturday with resume.', '');
    const v = r.safeApply.verification;
    assert.equal(v.officialDomain, null);
    assert.ok(['could-not-verify'].includes(v.overall), `overall=${v.overall}`);
    assert.ok(!v.checks.some((c) => c.status === 'verified' && c.id === 'vacancy-corroboration'));
    // and a positive control: known employer + matching domain verifies honestly
    const r2 = await listing(LEGIT, 'https://www.infosys.com/careers/');
    assert.equal(r2.safeApply.verification.officialDomain, 'infosys.com');
  });

  it('5. checklist reflects evidence; auto checks distinguished from user confirmations', async () => {
    const r = await listing(SCAM);
    const cl = r.safeApply.checklist;
    assert.equal(cl.total, 8);
    assert.ok(cl.items.every((i) => i.auto === true), 'all backend items must be marked auto');
    assert.ok(cl.items.every((i) => Array.isArray(i.derivedFrom)), 'every item cites derivation');
    const byId = Object.fromEntries(cl.items.map((i) => [i.id, i]));
    assert.equal(byId.fees.state, 'failed');
    assert.equal(byId.otp.state, 'failed');
    assert.equal(byId['pii-collection'].state, 'failed');
    const ok = await listing(LEGIT, 'https://www.infosys.com/careers/');
    assert.equal(ok.safeApply.checklist.items.find((i) => i.id === 'otp').state, 'passed');
  });

  it('6. recruiter messages scan independently of URLs', async () => {
    const m = await scanMessage({ text: 'Share your OTP and pay Rs 999 verification fee on WhatsApp to confirm your offer today.', channel: 'whatsapp' });
    assert.ok(m.score >= 60, `score=${m.score}`);
    assert.ok(m.safeApply.recommendedResponse && m.safeApply.recommendedResponse.length > 50);
    assert.match(m.safeApply.recommendedResponse, /verify/i);
    assert.equal(m.safeApply.channel, 'whatsapp');
    const benign = await scanMessage({ text: 'Hello, we would like to invite you for a technical interview on Monday at our Bengaluru office. Please confirm your availability. Regards, HR.', channel: 'email' });
    assert.ok(benign.score < 40, `score=${benign.score}`);
  });

  it('7. sensitive identifiers are redacted from evidence', async () => {
    const t = 'Share Aadhaar 2345 6789 0123 and PAN ABCDE1234F plus account 50100234567890 on +919876543210 to confirm.';
    const r = await listing(t);
    const blob = JSON.stringify({ f: r.allFindings, h: r.safeApply.highlights, s: r.safeApply.steps, p: r.safeApply.protection });
    assert.ok(!blob.includes('2345 6789 0123'), 'raw Aadhaar leaked');
    assert.ok(!blob.includes('ABCDE1234F'), 'raw PAN leaked');
    assert.ok(!blob.includes('50100234567890'), 'raw account leaked');
    assert.ok(!blob.includes('919876543210'), 'raw phone leaked');
  });

  it('8. external-source failures do not crash or produce false trust', async () => {
    const r = await scanListing({ url: 'https://nonexistent-domain-xyz-12345.invalid/jobs', text: SCAM });
    assert.ok(r.score >= 60, `score=${r.score}`);
    assert.ok(r.safeApply.verification.checks.some((c) => c.status === 'could-not-verify'));
    assert.ok(!r.safeApply.verification.checks.some((c) => c.status === 'verified' && c.id === 'vacancy-corroboration'));
  });

  it('9. API contracts for empty/oversize/error states', async () => {
    const srv = await new Promise((resolve) => { const s = app.listen(0, () => resolve(s)); });
    const base = `http://localhost:${srv.address().port}`;
    try {
      const e1 = await (await fetch(base + '/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({}) })).json();
      assert.ok(e1.error, 'empty scan must error');
      const e2 = await (await fetch(base + '/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: 'x'.repeat(61000) }) })).json();
      assert.ok(e2.error, 'oversize must error');
      const e3 = await (await fetch(base + '/api/message', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: '' }) })).json();
      assert.ok(e3.error, 'empty message must error');
      const ok = await (await fetch(base + '/api/message', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: 'Interview on Monday at our office.', channel: 'email' }) })).json();
      assert.ok(typeof ok.score === 'number' && ok.safeApply, 'valid message scan must return safeApply');
    } finally { srv.close(); }
  });

  it('10. highlights locate real phrases in the source text', async () => {
    const r = await listing(SCAM);
    assert.ok(r.safeApply.highlights.length >= 3, `highlights=${r.safeApply.highlights.length}`);
    for (const h of r.safeApply.highlights) {
      assert.ok(h.quote.length > 10 && h.why.length > 10 && h.recommendation.length > 5);
      assert.ok(['critical', 'high', 'medium'].includes(h.severity));
      assert.ok(SCAM.toLowerCase().includes(h.quote.toLowerCase().slice(0, 25)), `quote not from source: ${h.quote.slice(0, 40)}`);
    }
  });
});
