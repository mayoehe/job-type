# JobShield Evaluation Report (synthetic data)

> All figures below are **actually measured** by running `npm run evaluate`
> against `backend/data/dataset.json` on the committed engine code. They describe
> performance on synthetic, template-built cases only and **must not** be read as
> production-readiness claims for real-world traffic.

## Dataset

- Built deterministically by `backend/data/build-dataset.js` → `dataset.json`
  (100 rows: **50 fraudulent**, **50 legitimate**).
- 20 fraud rows use technically-clean domains (`clean-fraud`: plausible
  `careers-*` hosts, simulated valid SSL + aged domain + clean reputation) to
  prove behaviour-first detection.
- 20 legit rows use technically-poor small portals (`susp-legit`: plain HTTP,
  new domain, `.xyz`/`.live`/`.top`) to test false positives.
- Coverage: valid-SSL scams, aged-domain impersonation, refundable-fee fraud,
  credential-harvesting forms, Hindi / Marathi / Hinglish / English messages,
  genuine appropriate-stage document checks, official `.gov.in` listings,
  sparse listings, and unavailable-inspection cases.
- Limitation: cases are template-varied, not wild-collected; template artifacts
  (e.g. salary figures, disclaimer phrasing) flatter the numbers. Real-world
  precision/recall will be lower until evaluated on labelled real listings.

## Method

- `backend/src/evaluate.js` runs `runScan()` with **simulated** technical intel
  per subset (no network), exactly as documented in the file.
- Positive = final score ≥ 40 (`Suspicious` band or worse). Acceptance targets:
  F1 ≥ 0.80, clean-scam recall ≥ 0.90, FPR ≤ 0.20.

## Measured results

```
threshold: score >= 40 (Suspicious+), n = 100 (50 fraud / 50 legit)
TP = 50, FP = 0, TN = 50, FN = 0
precision = 1.000, recall = 1.000, F1 = 1.000, falsePositiveRate = 0.000
cleanFraudRecall (technically-clean scams) = 1.000 (20/20)
suspLegitFPR (technically-poor legit sites) = 0.000 (0/20)
acceptance: PASS (F1 ≥ 0.80 ✓, clean recall ≥ 0.90 ✓, FPR ≤ 0.20 ✓)
```

Reproduce: `cd backend && npm install && npm run evaluate`.

## Regression guarantees (all passing — `npm test`, 8/8)

1. Valid SSL does not drag strong behavioural risk into the low band.
2. Aged domain does not neutralise OTP/UPI-PIN/payment requests (floor 80).
3. Strong behavioural evidence outweighs clean hosting reputation.
4. Legitimate appropriate-stage documentation is not auto-flagged as phishing.
5. Unknown technical signals are treated as unknown (explicit finding), never safe.
6. Identical inputs → deterministic scores.
7. Missing URL access does not prevent text-only analysis.
8. Every major score contribution carries an explainable evidence record.

## Known weaknesses / next work

- Multilingual coverage is keyword-pattern based; paraphrased or code-mixed scam
  text outside the pattern set will under-score — needs labelled real data +
  a lightweight local classifier.
- Employer auto-verification is heuristic (cited domains/emails); adversarial
  pages can fake trust leads — corroboration depth should grow (careers-page
  fetch allow-list, certificate-organisation match).
- Live WHOIS/RDAP + reputation feeds are optional hooks, unmeasured here.
