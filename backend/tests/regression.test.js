/**
 * Regression tests — the 8 behaviour-first guarantees from the spec.
 * Run: npm test  (node built-in test runner, no extra deps)
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/scoring.js';

const CLEAN_INTEL = { inspected: true, https: true, certValid: true, dnsOk: true, redirects: 0, reputationListed: false, domainAgeDays: 1200, inspectNote: 'simulated clean' };
const SCAM_FEE_OTP = 'Dear Candidate, selected for Infosys work from home, salary Rs 85000. Pay refundable registration fee Rs 2499 via UPI and share Aadhaar card, PAN, bank account plus OTP on WhatsApp within 2 hours.';

describe('behaviour-first regression guarantees', () => {
  it('1. valid SSL does not drag strong behavioural risk into low band', () => {
    const r = runScan({ text: SCAM_FEE_OTP, url: 'https://careers-infosys-apply.com/apply', intel: CLEAN_INTEL, employer: {} });
    assert.ok(r.score >= 40, `expected >=40, got ${r.score}`);
  });

  it('2. aged domain does not neutralise OTP/UPI-PIN/payment requests', () => {
    const r = runScan({ text: 'Share your OTP and UPI PIN to confirm the offer. Pay Rs 999 verification fee.', url: 'https://example-jobs.com/apply', intel: { ...CLEAN_INTEL, domainAgeDays: 3000 }, employer: {} });
    assert.ok(r.score >= 80, `expected >=80 floor, got ${r.score}`);
    assert.ok(r.overrides.some((o) => o.id === 'override-otp'));
  });

  it('3. strong behavioural evidence outweighs clean hosting reputation', () => {
    const r = runScan({ text: SCAM_FEE_OTP, url: 'https://clean-host-example.com/jobs', intel: CLEAN_INTEL, employer: {} });
    assert.ok(r.level === 'high' || r.level === 'critical', `got ${r.level} (${r.score})`);
  });

  it('4. legitimate appropriate-stage documentation is not auto-phishing', () => {
    const legit = 'Infosys hiring Senior Developer in Bengaluru. Process: assessment, two technical interviews, HR round. Apply via infosys.com/careers. Original documents verified in person after provisional selection. We never ask for fees or OTPs. Contact careers@infosys.com. About the company: founded in 1981, registered office Bengaluru, CIN L85110KA1981PLC013115.';
    const r = runScan({ text: legit, url: 'https://www.infosys.com/careers/', intel: CLEAN_INTEL, employer: { officialDomain: 'infosys.com', contactMatches: 'careers@infosys.com', vacancyOnOfficialSite: true, applicationDomainLinked: true } });
    assert.ok(r.score < 40, `expected <40, got ${r.score}`);
  });

  it('5. unknown technical signals are not positive trust evidence', () => {
    const r = runScan({ text: SCAM_FEE_OTP, url: 'https://some-new-portal.com/apply', intel: { inspected: false, inspectNote: 'blocked' }, employer: {} });
    assert.ok(r.score >= 60, `expected >=60, got ${r.score}`);
    assert.ok(r.allFindings.some((f) => f.id === 'tech-not-inspected'));
  });

  it('6. identical inputs produce deterministic scores', () => {
    const a = runScan({ text: SCAM_FEE_OTP, url: 'https://x.com/a', intel: CLEAN_INTEL, employer: {} });
    const b = runScan({ text: SCAM_FEE_OTP, url: 'https://x.com/a', intel: CLEAN_INTEL, employer: {} });
    assert.equal(a.score, b.score);
    assert.equal(JSON.stringify(a.allFindings), JSON.stringify(b.allFindings));
  });

  it('7. missing URL access does not prevent text-only analysis', () => {
    const r = runScan({ text: SCAM_FEE_OTP, url: '', intel: { inspected: false, inspectNote: 'no URL' }, employer: {} });
    assert.ok(r.score >= 60, `expected >=60, got ${r.score}`);
  });

  it('8. every major score contribution has an explainable evidence record', () => {
    const r = runScan({ text: SCAM_FEE_OTP, url: 'https://secure-naukri-verification.xyz/infosys-careers/apply', intel: CLEAN_INTEL, employer: {} });
    for (const [k, v] of Object.entries(r.categories)) {
      if (v.score >= 2) {
        const ev = r.allFindings.filter((f) => f.category === (k === 'domain' ? 'domain' : k) && f.evidence && f.evidence.length > 0);
        assert.ok(ev.length > 0, `category ${k} scored ${v.score} without evidence`);
      }
    }
  });
});
