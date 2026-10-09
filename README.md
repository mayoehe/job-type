# JobShield — Behaviour-First Job Phishing Detection Scanner

Browser-based app that detects fraudulent job listings, fake recruitment portals, and phishing
attempts targeting Aadhaar, PAN, bank details, OTPs and UPI PINs. **Behavioural and linguistic
evidence outweighs reassuring technical signals**: valid SSL, aged domains and clean hosting can
never cancel out fraudulent recruitment behaviour.

## Architecture

```
frontend/ (React + TS + Vite, offline-capable engine mirror)
   │  POST /api/scan { url, text }   (proxyless dev via vite /api → :8787)
   src/App.tsx             dashboard shell: sidebar + topbar + mobile nav
   src/views/              Dashboard, Scan, Results (+Safe Apply), Message,
                           History, Reports, Settings
   src/components/ui.tsx   cards, badges, score rings, checklist + verify chips,
                           empty states, skeletons, toasts (lucide-react icons)
   src/lib/history.ts      scan history in browser localStorage only
                           (full evidence for re-inspection; never uploaded)
backend/  (Node 20 + Express, no build step)
   src/scoring.js            weighted aggregation + overrides + risk floors
   src/detectors/{linguistic,behavioural,urlAnalysis,technical,employer}.js
   src/inspect.js            SSRF-guarded static-HTML fetch (no JS execution)
   src/utils/{psl,ssrf,redact}.js
   data/dataset.json         120-case synthetic labelled set (built by build-dataset.js)
   tests/regression.test.js  8 behaviour-first guarantees (node:test)
```

Detection logic is separate from UI and intel providers. External APIs are optional
(`backend/.env.example`); core scanning works fully offline.

## Scoring (documented in code + UI)

`total = linguistic(≤35) + behavioural(≤30) + domain(≤15) + technical(≤10) + employer(≤10)`;
`final = max(total, highest applicable floor)`.

| Override | Floor | Severity |
|---|---|---|
| OTP / UPI PIN / banking password requested | 80 (Critical) | critical warning |
| Payment demanded for job / offer release | 65 (High) | high warning |
| ≥2 independent credential-harvesting indicators | 60 (High) | elevated |

- Technical trust is one-directional: clean HTTPS / aged domain / clean reputation add
  **0 points** and never subtract. Unknown checks = unknown, not safe.
- Bands: 0–19 Low · 20–39 Caution · 40–59 Suspicious · 60–79 High · 80–100 Critical.
- The score is a **heuristic risk score**, not a calibrated probability.

## Setup & run

```powershell
# backend
cd backend
npm install
npm test            # regression guarantees
npm run evaluate    # synthetic metrics (see EVALUATION.md)
npm start           # http://localhost:8787 (GET /api/health)

# frontend (new terminal)
cd frontend
npm install
npm run dev         # http://localhost:5173 (proxies /api → backend)
# production: npm run build; npm run preview
```

## Interface (v1.2 redesign)

Dark analytics dashboard (`#060607` canvas, charcoal cards, lime/orange data
accents, slim icon rail; semantic lime→orange→red risk colours). Destinations: **Dashboard** (live
stats, risk distribution, 14-day activity, recent scans — all computed from
real local history, with empty states when none), **Scan Job** (listing +
message tabs), **Scan History** (search, risk filters, re-open past evidence,
delete; stale-data warning), **Safe Apply** (latest action plan), **Reports**
(aggregates, top recurring signals, JSON export), **Settings** (backend URL
override, clear local data, reduce-motion, connection status). Sidebar on
desktop, bottom nav on mobile; keyboard focus states and
`prefers-reduced-motion` respected throughout.

Without the backend, the frontend still scans via its built-in offline engine
(text + URL-structure analysis) and labels results `local offline engine`.

## Safe Apply Assistant (v1.1)

Every scan now returns a `safeApply` block (see `POST /api/scan`, `POST /api/message`):

- **Verdict**: Avoid This Listing / Verify Employer / Proceed Carefully — derived
  from score + confirmed findings. There is deliberately no “safe” verdict.
- **Why unsafe**: plain-language explanation assembled from the top confirmed findings.
- **Action plan**: contextual steps (don't pay, don't share OTPs/PINs, resolve
  domain mismatches, verify independently…), each citing the finding ids it came from.
- **Employer verification** (`backend/src/verify.js` + `src/data/employers.json`):
  claimed employer/position extraction, official domain resolved **only** from the
  curated offline directory, listing-domain comparison, recruiter-email
  classification, and best-effort vacancy corroboration against the official
  careers page via the SSRF-guarded fetcher. Every check reports
  `verified` / `mismatch` / `could-not-verify` with evidence + source.
  Missing evidence is never fabricated into verification.
- **Red-flag highlighter**: sentence-grounded spans in the original text with
  severity, why-it-matters, and what-to-do per finding.
- **Protection panel**: Aadhaar/PAN, bank/cards, OTP/PIN/passwords, documents,
  payments — each `requested` / `mentioned` / `not-detected` with contextual warnings.
- **Checklist** (`backend/src/checklist.js`): 8 dynamic items with
  passed/failed/unverified auto states + derivation refs; the UI lets users mark
  items “reviewed by you”, visually distinct from automatic evidence.
- **Recruiter message scanner** (`POST /api/message`, text-only, same engine):
  WhatsApp/email/offer/interview/payment channels, separate score, evidence,
  and a recommended reply. Nothing is sent to external AI services.
- **Already-shared guidance**: bank-freeze steps, Aadhaar lock, credit monitoring,
  and reporting via https://cybercrime.gov.in / helpline 1930.

Tests: `backend/tests/safeapply.test.js` (10 acceptance criteria) +
`regression.test.js` (8 behaviour-first guarantees) — run `npm test`.

## Privacy

- No personal-data persistence: only anonymised aggregate counts (`GET /api/stats`).
- Evidence redacted by default (Aadhaar/PAN/cards/phones/UPI masked).
- Pasted text is never sent to AI providers; only to your local backend for analysis.
- Report fraud: **https://cybercrime.gov.in** / helpline **1930** (guidance, not legal advice).

## Limitations

- Synthetic evaluation only — not production-ready claims for real traffic.
- Live WHOIS/RDAP, VirusTotal, SafeBrowsing are optional hooks, not bundled.
- Non-English coverage focuses on Hindi/Marathi/Hinglish job-scam phrasing.
- See `EVALUATION.md` for measured results and `backend/src/*` for rule documentation.

## Updating threat-intel sources

1. Append domains to `LOCAL_BLOCKLIST` in `backend/src/inspect.js`, or
2. Set `THREAT_FEED_URLS` (newline/CSV of hosts) and extend `inspectUrl()` to fetch at
   startup with a 10s timeout + SSRF policy from `src/utils/ssrf.js`, or
3. Wire `VT_API_KEY` / `GS_API_KEY` lookups in `analyseTechnical()` input mapping —
   keep them optional and timestamp + label the source in the URL-intelligence panel.
