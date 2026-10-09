package com.jobshield;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Safe URL inspection — port of backend/src/inspect.js */
public final class Inspect {
    private Inspect() {}

    private static final int MAX_REDIRECTS = 5;
    private static final int MAX_BYTES = 750_000;
    private static final int TIMEOUT_MS = 10_000;
    private static final Pattern ALLOWED_MIME = Pattern.compile("text/html|application/xhtml|text/plain", Pattern.CASE_INSENSITIVE);
    private static final Set<String> LOCAL_BLOCKLIST = Set.of(
        "secure-naukri-verification.xyz", "infosys-careers-apply.top", "sarkari-job-apply.club");

    private static final HttpClient CLIENT = HttpClient.newBuilder()
        .connectTimeout(Duration.ofMillis(TIMEOUT_MS))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();

    public static String stripHtml(String html) {
        String s = String.valueOf(html == null ? "" : html);
        s = s.replaceAll("(?is)<script.*?</script>", " ");
        s = s.replaceAll("(?is)<style.*?</style>", " ");
        s = s.replaceAll("<[^>]+>", " ");
        s = s.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">");
        s = s.replaceAll("\\s+", " ").trim();
        return s.substring(0, Math.min(20000, s.length()));
    }

    public record Inspection(Map<String, Object> intel, String pageText, String finalUrl,
                             boolean redirectCrossDomain, String finalRegistrable, Map<String, Object> timestamps) {}

    public static Inspection inspectUrl(String rawUrl) {
        long started = System.currentTimeMillis();
        Map<String, Object> intel = new LinkedHashMap<>();
        intel.put("inspected", false);
        intel.put("inspectNote", "");
        intel.put("redirects", 0);
        String pageText = "";
        String finalUrl = "";
        boolean crossDomain = false;
        String finalReg = null;
        Map<String, Object> timestamps = new LinkedHashMap<>();
        timestamps.put("at", Instant.now().toString());

        Ssrf.UrlPolicy first = Ssrf.validateUrlAgainstPolicy(rawUrl);
        if (!first.ok()) {
            intel.put("inspectNote", first.reason() + " URL text analysis still proceeds.");
            timestamps.put("durationMs", System.currentTimeMillis() - started);
            timestamps.put("source", "jobshield-backend safe-inspect 1.0");
            return new Inspection(intel, pageText, finalUrl, crossDomain, finalReg, timestamps);
        }
        String current = first.url().toString();
        String startReg;
        try { startReg = Psl.registrableOf(first.url().getHost()); } catch (Exception e) { startReg = ""; }
        int hops = 0;

        while (hops <= MAX_REDIRECTS) {
            Ssrf.UrlPolicy v = Ssrf.validateUrlAgainstPolicy(current);
            if (!v.ok()) { intel.put("inspectNote", "Redirect hop blocked: " + v.reason()); break; }
            Map<String, Object> dns = Ssrf.checkDns(v.url().getHost());
            if (Boolean.FALSE.equals(dns.get("ok"))) { intel.put("inspectNote", "DNS blocked at hop " + (hops + 1) + ": " + dns.get("reason")); break; }
            HttpResponse<byte[]> res;
            try {
                HttpRequest req = HttpRequest.newBuilder(v.url())
                    .timeout(Duration.ofMillis(TIMEOUT_MS))
                    .header("User-Agent", "JobShield-Scanner/1.0 (+safety-check)")
                    .header("Accept", "text/html,text/plain")
                    .GET().build();
                res = CLIENT.send(req, HttpResponse.BodyHandlers.ofByteArray());
            } catch (Exception e) {
                String msg = e.getMessage() == null ? String.valueOf(e) : e.getMessage();
                intel.put("inspectNote", "Fetch failed (" + msg.substring(0, Math.min(120, msg.length())) + "). Text-only analysis still applies.");
                break;
            }
            int status = res.statusCode();
            if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
                String loc = res.headers().firstValue("location").orElse(null);
                if (loc == null) { intel.put("inspectNote", "Redirect without Location header."); break; }
                try { current = v.url().resolve(loc).toString(); } catch (Exception e) { intel.put("inspectNote", "Bad redirect target."); break; }
                hops++;
                continue;
            }
            intel.put("redirects", hops);
            finalUrl = current;
            URI finalU;
            try { finalU = new URI(current); } catch (Exception e) { break; }
            finalReg = Psl.registrableOf(finalU.getHost());
            crossDomain = !finalReg.equals(startReg);
            String ct = res.headers().firstValue("content-type").orElse("");
            byte[] body = res.body() == null ? new byte[0] : res.body();
            if (body.length > MAX_BYTES * 2) {
                intel.put("inspectNote", "Response too large; skipped body.");
            } else if (!ct.isEmpty() && !ALLOWED_MIME.matcher(ct).find()) {
                intel.put("inspectNote", "Non-HTML content (" + ct + "); skipped body.");
            } else {
                int len = Math.min(body.length, MAX_BYTES);
                String html = new String(body, 0, len, java.nio.charset.StandardCharsets.UTF_8);
                pageText = stripHtml(html);
                boolean https = "https".equalsIgnoreCase(finalU.getScheme());
                intel.put("https", https);
                intel.put("certValid", https ? null : false);
                if (!https) intel.put("https", false);
            }
            intel.put("inspected", true);
            intel.put("dnsOk", true);
            if (System.currentTimeMillis() - started > 25_000)
                intel.put("inspectNote", String.valueOf(intel.getOrDefault("inspectNote", "")) + " (inspection time-capped)");
            break;
        }
        if (hops > MAX_REDIRECTS) intel.put("inspectNote", "Too many redirects; stopped.");

        String host;
        try { host = new URI(finalUrl.isEmpty() ? rawUrl : finalUrl).getHost().toLowerCase(); }
        catch (Exception e) { host = ""; }
        String reg = (host == null || host.isEmpty()) ? null : Psl.registrableOf(host);
        boolean listed = reg != null && LOCAL_BLOCKLIST.contains(reg);
        intel.put("reputationListed", listed);
        if (listed) intel.put("reputationSource", "local blocklist (built-in demo feed)");
        if ("1".equals(System.getenv("WHOIS_ENABLED")))
            intel.put("inspectNote", String.valueOf(intel.getOrDefault("inspectNote", "")) + " WHOIS hook enabled but no provider configured.");
        timestamps.put("durationMs", System.currentTimeMillis() - started);
        timestamps.put("source", "jobshield-backend safe-inspect 1.0");
        return new Inspection(intel, pageText, finalUrl, crossDomain, finalReg, timestamps);
    }
}
