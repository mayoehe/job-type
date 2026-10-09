package com.jobshield;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;

/**
 * JobShield Java backend — drop-in replacement for the Node/Express backend.
 * Same port (8787), same routes, same JSON contract. UI unchanged.
 */
public final class App {
    private App() {}

    private static final Map<String, Object> STATS = new LinkedHashMap<>();
    private static final Map<String, Long> BY_LEVEL = new LinkedHashMap<>();

    static {
        STATS.put("scans", 0L);
        STATS.put("messages", 0L);
        BY_LEVEL.put("low", 0L); BY_LEVEL.put("caution", 0L); BY_LEVEL.put("suspicious", 0L);
        BY_LEVEL.put("high", 0L); BY_LEVEL.put("critical", 0L);
        STATS.put("lastAt", null);
    }

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8787"));
        Path here = Paths.get("").toAbsolutePath();
        Verify.loadDb(
            here.resolve("data/employers.json"),
            here.resolve("backend-java/data/employers.json"),
            here.resolve("backend/src/data/employers.json"),
            Paths.get("C:/Users/Mayo/Desktop/Personal/job type/job type/backend/src/data/employers.json"));
        Path dist = findDist(here);

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", ex -> {
            try { route(ex, dist); }
            catch (Exception e) {
                try { sendJson(ex, 500, Map.of("error", "Scan failed safely. Try text-only analysis.")); }
                catch (Exception ignored) {}
            }
        });
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("[jobshield-java] app running on http://localhost:" + port + " (API + UI on one port)");
        if (dist != null) System.out.println("[jobshield-java] serving UI from " + dist);
        else System.out.println("[jobshield-java] frontend/dist not found — API-only mode. Run `npm run build` in frontend/.");
    }

    private static Path findDist(Path here) {
        Path[] cands = {
            here.resolve("frontend/dist"),
            here.resolve("../frontend/dist"),
            Paths.get("C:/Users/Mayo/Desktop/Personal/job type/job type/frontend/dist"),
            here.resolve("backend-java/../frontend/dist").normalize(),
        };
        for (Path p : cands) {
            try { if (Files.exists(p.resolve("index.html"))) return p.toRealPath(); }
            catch (Exception ignored) {}
        }
        return null;
    }

    private static void route(HttpExchange ex, Path dist) throws IOException {
        String method = ex.getRequestMethod().toUpperCase();
        String path = ex.getRequestURI().getPath();
        // CORS (mirror Express cors({origin:'*'}))
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Content-Type");
        if ("OPTIONS".equals(method)) { ex.sendResponseHeaders(204, -1); ex.close(); return; }

        if ("GET".equals(method) && "/api/health".equals(path)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("ok", true); m.put("service", "jobshield-backend"); m.put("version", "1.0.0-java");
            m.put("time", Instant.now().toString());
            sendJson(ex, 200, m);
            return;
        }
        if ("GET".equals(method) && "/api/scoring-info".equals(path)) {
            sendJson(ex, 200, Scoring.scoringDoc());
            return;
        }
        if ("GET".equals(method) && "/api/stats".equals(path)) {
            Map<String, Object> m;
            synchronized (STATS) {
                m = new LinkedHashMap<>();
                m.put("scans", STATS.get("scans")); m.put("messages", STATS.get("messages"));
                m.put("byLevel", new LinkedHashMap<>(BY_LEVEL));
                m.put("lastAt", STATS.get("lastAt"));
            }
            m.put("note", "Anonymised aggregate counts only. No scanned content is retained.");
            sendJson(ex, 200, m);
            return;
        }
        if ("POST".equals(method) && "/api/scan".equals(path)) {
            Map<String, Object> body = readJsonBody(ex);
            if (body == null) { sendJson(ex, 400, Map.of("error", "Invalid JSON body.")); return; }
            String url = str(body.get("url"), ""), text = str(body.get("text"), "");
            if (url.trim().isEmpty() && text.trim().isEmpty()) { sendJson(ex, 400, Map.of("error", "Provide a URL, pasted job text, or both.")); return; }
            if (text.length() > 60_000) { sendJson(ex, 413, Map.of("error", "Text too long (max 60k chars).")); return; }
            try {
                Map<String, Object> result = scanListing(url, text);
                countScan(result, false);
                sendJson(ex, 200, result);
            } catch (Exception e) {
                System.err.println("[scan-error] " + e.getMessage());
                sendJson(ex, 500, Map.of("error", "Scan failed safely. Try text-only analysis."));
            }
            return;
        }
        if ("POST".equals(method) && "/api/message".equals(path)) {
            Map<String, Object> body = readJsonBody(ex);
            if (body == null) { sendJson(ex, 400, Map.of("error", "Invalid JSON body.")); return; }
            String text = str(body.get("text"), ""), channel = str(body.get("channel"), "whatsapp");
            if (text.trim().isEmpty()) { sendJson(ex, 400, Map.of("error", "Paste a recruiter message to scan it.")); return; }
            if (text.length() > 60_000) { sendJson(ex, 413, Map.of("error", "Text too long (max 60k chars).")); return; }
            try {
                Map<String, Object> result = scanMessage(text, channel);
                countScan(result, true);
                sendJson(ex, 200, result);
            } catch (Exception e) {
                System.err.println("[message-error] " + e.getMessage());
                sendJson(ex, 500, Map.of("error", "Message scan failed safely. Please retry."));
            }
            return;
        }
        if (path.startsWith("/api")) { sendJson(ex, 404, Map.of("error", "Not found")); return; }
        // static UI
        if (dist != null && ("GET".equals(method) || "HEAD".equals(method))) {
            serveStatic(ex, dist, path, method);
            return;
        }
        sendJson(ex, 404, Map.of("error", "Not found"));
    }

    // ---------- pipelines (ports of scanListing / scanMessage) ----------

    @SuppressWarnings("unchecked")
    static Map<String, Object> scanListing(String url, String text) {
        Map<String, Object> intel = new LinkedHashMap<>();
        intel.put("inspected", false);
        intel.put("inspectNote", "No URL provided; text-only analysis.");
        // NOTE: no "redirects" key here — mirrors Node (undefined -> null in JSON),
        // distinct from inspect.js which starts at 0 once a URL is inspected.
        String pageText = "";
        String finalUrl = "";
        boolean cross = false;
        String finalReg = null;
        Map<String, Object> timestamps = Map.of("at", Instant.now().toString(), "source", "none");
        if (url != null && !url.trim().isEmpty()) {
            Inspect.Inspection insp = Inspect.inspectUrl(url.trim());
            intel = insp.intel();
            pageText = insp.pageText();
            finalUrl = insp.finalUrl();
            cross = insp.redirectCrossDomain();
            finalReg = insp.finalRegistrable();
            timestamps = insp.timestamps();
        }
        Map<String, Object> intelForScore = new LinkedHashMap<>(intel);
        intelForScore.put("redirectCrossDomain", cross);
        intelForScore.put("finalRegistrable", finalReg);
        Map<String, Object> result = Scoring.runScan(text == null ? "" : text, url == null ? "" : url, intelForScore, Map.of(), pageText);
        Map<String, Object> verification = Verify.verifyEmployer((text == null ? "" : text) + "\n" + pageText, url == null ? "" : url, finalUrl, intel, true);
        Map<String, Object> checklist = Checklist.build(result, verification);
        Map<String, Object> safeApply = Plan.buildSafeApply(result, verification, checklist, text == null ? "" : text, "listing", null);
        safeApply.put("checklist", checklist);
        result.put("safeApply", safeApply);
        redactResult(result);
        Map<String, Object> meta = (Map<String, Object>) result.get("meta");
        Map<String, Object> intelligence = new LinkedHashMap<>();
        intelligence.put("domain", meta == null ? null : meta.get("registrableDomain"));
        intelligence.put("host", meta == null ? null : meta.get("urlHost"));
        intelligence.put("redirects", intel.get("redirects"));
        intelligence.put("https", intel.get("https"));
        intelligence.put("certValid", intel.get("certValid"));
        intelligence.put("reputationListed", intel.getOrDefault("reputationListed", false));
        intelligence.put("reputationSource", intel.get("reputationSource"));
        intelligence.put("domainAgeDays", intel.get("domainAgeDays"));
        intelligence.put("inspected", intel.getOrDefault("inspected", false));
        intelligence.put("inspectNote", intel.get("inspectNote"));
        intelligence.put("finalUrl", finalUrl.isEmpty() ? null : finalUrl);
        intelligence.put("source", timestamps.getOrDefault("source", "jobshield-backend"));
        intelligence.put("at", timestamps.get("at"));
        result.put("intelligence", intelligence);
        return result;
    }

    static Map<String, Object> scanMessage(String text, String channel) {
        Set<String> allowed = Set.of("whatsapp", "email", "offer", "interview", "payment");
        String ch = allowed.contains(channel) ? channel : "whatsapp";
        Map<String, Object> intel = new LinkedHashMap<>();
        intel.put("inspected", false);
        intel.put("inspectNote", "Message scan (" + ch + "): no URL inspection by design; analysis is local text + behaviour only.");
        Map<String, Object> result = Scoring.runScan(text, "", intel, Map.of(), "");
        Map<String, Object> verification = Verify.verifyEmployer(text, "", "", Map.of(), false);
        Map<String, Object> checklist = Checklist.build(result, verification);
        Map<String, Object> safeApply = Plan.buildSafeApply(result, verification, checklist, text, "message", ch);
        safeApply.put("checklist", checklist);
        safeApply.put("channel", ch);
        result.put("safeApply", safeApply);
        redactResult(result);
        return result;
    }

    @SuppressWarnings("unchecked")
    static void redactResult(Map<String, Object> result) {
        List<Object> findings = new ArrayList<>();
        for (Object o : (List<Object>) result.getOrDefault("allFindings", List.of())) {
            Map<String, Object> f = new LinkedHashMap<>((Map<String, Object>) o);
            f.put("evidence", Redact.redactText(String.valueOf(f.get("evidence"))));
            findings.add(f);
        }
        result.put("allFindings", findings);
        List<Object> ovs = new ArrayList<>();
        for (Object o : (List<Object>) result.getOrDefault("overrides", List.of())) {
            Map<String, Object> ov = new LinkedHashMap<>((Map<String, Object>) o);
            List<Object> evs = new ArrayList<>();
            for (Object e : (List<Object>) ov.getOrDefault("evidence", List.of())) evs.add(Redact.redactText(String.valueOf(e)));
            ov.put("evidence", evs);
            ovs.add(ov);
        }
        result.put("overrides", ovs);
        Object sa = result.get("safeApply");
        if (sa instanceof Map) {
            Map<String, Object> s = (Map<String, Object>) sa;
            List<Object> hs = new ArrayList<>();
            for (Object o : (List<Object>) s.getOrDefault("highlights", List.of())) {
                Map<String, Object> h = new LinkedHashMap<>((Map<String, Object>) o);
                h.put("quote", Redact.redactText(String.valueOf(h.get("quote"))));
                hs.add(h);
            }
            s.put("highlights", hs);
            List<Object> st = new ArrayList<>();
            for (Object o : (List<Object>) s.getOrDefault("steps", List.of())) {
                Map<String, Object> x = new LinkedHashMap<>((Map<String, Object>) o);
                x.put("detail", Redact.redactText(String.valueOf(x.get("detail"))));
                st.add(x);
            }
            s.put("steps", st);
            Object cl = s.get("checklist");
            if (cl instanceof Map) {
                Map<String, Object> c = (Map<String, Object>) cl;
                List<Object> items = new ArrayList<>();
                for (Object o : (List<Object>) c.getOrDefault("items", List.of())) {
                    Map<String, Object> it = new LinkedHashMap<>((Map<String, Object>) o);
                    it.put("detail", Redact.redactText(String.valueOf(it.get("detail"))));
                    items.add(it);
                }
                c.put("items", items);
            }
            Object ver = s.get("verification");
            if (ver instanceof Map) {
                Map<String, Object> v = (Map<String, Object>) ver;
                List<Object> checks = new ArrayList<>();
                for (Object o : (List<Object>) v.getOrDefault("checks", List.of())) {
                    Map<String, Object> c = new LinkedHashMap<>((Map<String, Object>) o);
                    c.put("evidence", Redact.redactText(String.valueOf(c.get("evidence"))));
                    checks.add(c);
                }
                v.put("checks", checks);
            }
            List<Object> prot = new ArrayList<>();
            for (Object o : (List<Object>) s.getOrDefault("protection", List.of())) {
                Map<String, Object> g = new LinkedHashMap<>((Map<String, Object>) o);
                List<Object> fl = new ArrayList<>();
                for (Object fo : (List<Object>) g.getOrDefault("findings", List.of())) {
                    Map<String, Object> f = new LinkedHashMap<>((Map<String, Object>) fo);
                    f.put("evidence", Redact.redactText(String.valueOf(f.get("evidence"))));
                    fl.add(f);
                }
                g.put("findings", fl);
                prot.add(g);
            }
            s.put("protection", prot);
        }
    }

    static void countScan(Map<String, Object> result, boolean isMessage) {
        synchronized (STATS) {
            STATS.put("scans", ((Number) STATS.get("scans")).longValue() + 1);
            if (isMessage) STATS.put("messages", ((Number) STATS.get("messages")).longValue() + 1);
            String level = String.valueOf(result.get("level"));
            BY_LEVEL.computeIfPresent(level, (k, v) -> v + 1);
            STATS.put("lastAt", Instant.now().toString());
        }
    }

    // ---------- http helpers ----------

    private static Map<String, Object> readJsonBody(HttpExchange ex) throws IOException {
        byte[] buf = ex.getRequestBody().readNBytes(300_000);
        if (buf.length == 0) return new LinkedHashMap<>();
        String s = new String(buf, StandardCharsets.UTF_8);
        try {
            Object v = Json.parse(s);
            if (v instanceof Map) { @SuppressWarnings("unchecked") Map<String, Object> m = (Map<String, Object>) v; return m; }
            return null;
        } catch (Exception e) { return null; }
    }

    private static void sendJson(HttpExchange ex, int status, Object body) throws IOException {
        byte[] b = Json.stringify(body).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    private static void serveStatic(HttpExchange ex, Path dist, String path, String method) throws IOException {
        String rel = path.equals("/") ? "index.html" : path.substring(1);
        Path file = dist.resolve(rel).normalize();
        if (!file.startsWith(dist) || !Files.isRegularFile(file)) {
            file = dist.resolve("index.html"); // SPA fallback
        }
        String ct = contentType(file.getFileName().toString());
        byte[] b = Files.readAllBytes(file);
        ex.getResponseHeaders().set("Content-Type", ct);
        ex.getResponseHeaders().set("Cache-Control", rel.equals("index.html") ? "no-cache" : "public, max-age=3600");
        if ("HEAD".equals(method)) { ex.sendResponseHeaders(200, -1); ex.close(); return; }
        ex.sendResponseHeaders(200, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    private static String contentType(String name) {
        if (name.endsWith(".html")) return "text/html; charset=utf-8";
        if (name.endsWith(".js")) return "text/javascript; charset=utf-8";
        if (name.endsWith(".css")) return "text/css; charset=utf-8";
        if (name.endsWith(".json")) return "application/json; charset=utf-8";
        if (name.endsWith(".svg")) return "image/svg+xml";
        if (name.endsWith(".png")) return "image/png";
        if (name.endsWith(".ico")) return "image/x-icon";
        if (name.endsWith(".woff2")) return "font/woff2";
        if (name.endsWith(".woff")) return "font/woff";
        return "application/octet-stream";
    }

    private static String str(Object v, String def) { return v instanceof String s ? s : (v == null ? def : String.valueOf(v)); }
}
