# JobShield Java backend (drop-in replacement for `backend/`)

Pure **Java 17, zero dependencies** (JDK `HttpServer`, `HttpClient`, no Maven/Gradle needed).
Same port (`8787`), same routes, same JSON contract — the React UI in `frontend/` works unchanged
(dev proxy `vite /api → :8787`, or the built UI served from `frontend/dist` on the same port).

## Run

```powershell
cd backend-java
.\run.bat            # builds to out/ and serves http://localhost:8787
```

or manually:

```powershell
javac -encoding UTF-8 -d out (Get-ChildItem -Recurse src -Filter *.java | % FullName)
java -cp out com.jobshield.App
```

`PORT` env var overrides the port. Employer directory loads from
`backend-java/data/employers.json` (copy of `backend/src/data/employers.json`).

## Endpoints (identical to Node backend)

- `GET /api/health`, `GET /api/scoring-info`, `GET /api/stats`
- `POST /api/scan { url, text }`, `POST /api/message { text, channel }`
- `GET /*` → static `frontend/dist` + SPA fallback; unknown `/api/*` → JSON 404

## Layout

```
src/com/jobshield/
  App.java            HTTP server, pipelines (scanListing/scanMessage), stats, static UI
  Scoring.java        weighted aggregation + floors (port of scoring.js)
  Inspect.java        SSRF-guarded fetch (port of inspect.js)
  Verify.java         employer verification (port of verify.js)
  Checklist.java      8-item checklist (port of checklist.js)
  Plan.java           verdict/steps/protection/highlights (port of plan.js)
  Redact.java Psl.java Ssrf.java Json.java
  detect/             Linguistic, Behavioural, UrlAnalysis, Technical, EmployerCat
RegressionTest.java   mirrors backend/tests/regression.test.js (8 guarantees)
```

## Parity

- `java -cp out com.jobshield.RegressionTest` → 8/8 pass
- Same score/floor/findings/order verified against Node on text-only,
  URL (typosquat + brand-mismatch), message, legit, and error (`400`/`413`/`404`) cases.
- One intentional difference: `/api/health` reports `"version": "1.0.0-java"`.
