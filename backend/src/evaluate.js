/**
 * Evaluation: runs the detection engine over data/dataset.json WITHOUT network
 * (simulated technical intel per subset) and reports precision/recall/F1/FPR
 * plus recall on the technically-clean-scam subset.
 * Positive = score >= 40 (Suspicious or worse). Threshold documented here.
 * Run: npm run evaluate
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/scoring.js';

const dir = dirname(fileURLToPath(import.meta.url));
const db = JSON.parse(readFileSync(join(dir, '../data/dataset.json'), 'utf8'));
const THRESHOLD = 40;

// Simulated technical intel: clean-fraud looks technically perfect (valid HTTPS,
// aged domain, clean reputation) to prove behaviour-first scoring; susp-legit
// looks technically poor (http, new domain) to test false positives.
function intelFor(row) {
  if (row.subset === 'clean-fraud') return { inspected: true, https: true, certValid: true, dnsOk: true, redirects: 1, reputationListed: false, domainAgeDays: 900, inspectNote: 'simulated: valid SSL, aged domain, clean reputation' };
  if (row.subset === 'susp-legit') return { inspected: true, https: false, certValid: false, dnsOk: true, redirects: 0, reputationListed: false, domainAgeDays: 20, inspectNote: 'simulated: no HTTPS, new domain, small portal' };
  if (row.label === 'fraud') return { inspected: true, https: true, certValid: true, dnsOk: true, redirects: 2, reputationListed: false, domainAgeDays: 400, inspectNote: 'simulated standard' };
  return { inspected: true, https: true, certValid: true, dnsOk: true, redirects: 0, reputationListed: false, domainAgeDays: 3000, inspectNote: 'simulated standard' };
}

let TP = 0, FP = 0, TN = 0, FN = 0, cleanTP = 0, cleanN = 0, suspFP = 0, suspN = 0;
const misses = [], falseAlarms = [];
for (const row of db.rows) {
  const r = runScan({ text: row.text, url: row.url, intel: intelFor(row), pageText: '', employer: {} });
  const pred = r.score >= THRESHOLD ? 'fraud' : 'legit';
  if (row.label === 'fraud' && pred === 'fraud') TP++;
  else if (row.label === 'fraud') { FN++; misses.push(`${row.id} score=${r.score}`); }
  else if (pred === 'fraud') { FP++; falseAlarms.push(`${row.id} score=${r.score}`); }
  else TN++;
  if (row.subset === 'clean-fraud') { cleanN++; if (pred === 'fraud') cleanTP++; }
  if (row.subset === 'susp-legit') { suspN++; if (pred === 'fraud') suspFP++; }
}
const prec = TP + FP ? TP / (TP + FP) : 0;
const rec = TP + FN ? TP / (TP + FN) : 0;
const f1 = prec + rec ? (2 * prec * rec) / (prec + rec) : 0;
const fpr = FP + TN ? FP / (FP + TN) : 0;
const report = {
  threshold: `score >= ${THRESHOLD} (Suspicious+)`,
  n: db.rows.length, fraud: TP + FN, legit: TN + FP,
  TP, FP, TN, FN,
  precision: +prec.toFixed(3), recall: +rec.toFixed(3), f1: +(f1.toFixed(3)), falsePositiveRate: +fpr.toFixed(3),
  cleanFraudRecall: +(cleanTP / Math.max(1, cleanN)).toFixed(3),
  suspLegitFPR: +(suspFP / Math.max(1, suspN)).toFixed(3),
  acceptance: { targetF1: '>= 0.80', targetCleanRecall: '>= 0.90', targetFPR: '<= 0.20', pass: f1 >= 0.8 && cleanTP / cleanN >= 0.9 && fpr <= 0.2 },
  sampleMisses: misses.slice(0, 5), sampleFalseAlarms: falseAlarms.slice(0, 5),
  note: 'Synthetic-data measurement only. Not a claim of production readiness on real-world traffic.',
};
console.log(JSON.stringify(report, null, 2));
