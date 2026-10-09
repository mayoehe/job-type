package com.jobshield.detect;

import com.jobshield.Psl;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** C. URL & domain analysis — max 15. Port of detectors/urlAnalysis.js */
public final class UrlAnalysis {
    private UrlAnalysis() {}
    public static final double MAX = 15;

    private static final Set<String> SHORTENERS = Set.of("bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy");
    private static final Set<String> SUSPICIOUS_TLDS = Set.of("xyz", "top", "club", "live", "click", "link", "world", "buzz", "rest", "quest");
    private static final String[] TRUSTED = {"infosys.com", "tcs.com", "wipro.com", "hcltech.com", "techmahindra.com", "reliance.com", "tata.com", "tatamotors.com", "flipkart.com", "amazon.in", "amazon.com", "google.com", "microsoft.com", "ibm.com", "accenture.com", "cognizant.com", "icici.com", "hdfcbank.com", "onlinesbi.com", "statebankofindia.com", "naukri.com", "linkedin.com", "indeed.com", "upsc.gov.in", "ssc.gov.in", "ibps.in", "employmentnews.gov.in"};

    private static int levenshtein(String a, String b) {
        int m = a.length(), n = b.length();
        if (m == 0) return n;
        if (n == 0) return m;
        int[][] dp = new int[m + 1][n + 1];
        for (int i = 0; i <= m; i++) dp[i][0] = i;
        for (int j = 0; j <= n; j++) dp[0][j] = j;
        for (int i = 1; i <= m; i++) for (int j = 1; j <= n; j++)
            dp[i][j] = Math.min(Math.min(dp[i-1][j] + 1, dp[i][j-1] + 1), dp[i-1][j-1] + (a.charAt(i-1) == b.charAt(j-1) ? 0 : 1));
        return dp[m][n];
    }

    private static String homoglyph(String host) {
        if (host.contains("xn--")) return "punycode-encoded label (possible homoglyph attack)";
        for (int i = 0; i < host.length(); i++) if (host.charAt(i) > 0x7F) return "non-ASCII characters in hostname (possible homoglyph)";
        return null;
    }

    public static Map<String, Object> analyse(String rawUrl) {
        List<Object> findings = new ArrayList<>();
        Map<String, Object> signals = new LinkedHashMap<>();
        double[] raw = {0};
        AddFn add = (id, severity, title, evidence, weight) -> {
            raw[0] += weight;
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("id", "url-" + id); f.put("category", "domain"); f.put("severity", severity);
            f.put("title", title); f.put("evidence", evidence); f.put("points", weight);
            findings.add(f);
            signals.put(id, true);
        };
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("score", 0.0); out.put("max", MAX); out.put("findings", findings);
            out.put("signals", signals); out.put("rawWeight", 0.0); out.put("parsed", null);
            out.put("note", "no-url");
            return out;
        }
        URI u;
        try { u = new URI(rawUrl.trim()); if (u.getHost() == null) throw new Exception("no host"); }
        catch (Exception e) {
            add.add("unparseable", "medium", "URL could not be parsed", rawUrl.substring(0, Math.min(120, rawUrl.length())), 4);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("score", Math.min(MAX, raw[0])); out.put("max", MAX); out.put("findings", findings);
            out.put("signals", signals); out.put("rawWeight", raw[0]); out.put("parsed", null);
            return out;
        }
        String host = u.getHost().toLowerCase(Locale.ROOT);
        Map<String, Object> parsed = Psl.parseDomain(host);
        String reg = String.valueOf(parsed.get("registrableDomain"));

        if (SHORTENERS.contains(reg) || SHORTENERS.contains(host))
            add.add("shortener", "medium", "URL shortener hides the real destination (" + host + ")", host, 4);
        else signals.put("shortener", false);

        String hg = homoglyph(host);
        if (hg != null) add.add("homoglyph", "high", "Suspicious hostname encoding: " + hg, host, 6);
        else signals.put("homoglyph", false);

        String sub = String.valueOf(parsed.getOrDefault("subdomain", ""));
        String brandInSub = null;
        for (String d : TRUSTED) {
            String b = d.split("\\.")[0];
            if (sub.contains(b)) { brandInSub = b; break; }
        }
        boolean trustedReg = Set.of(TRUSTED).contains(reg);
        if (brandInSub != null && !trustedReg)
            add.add("misleading-subdomain", "high", "Trusted brand \"" + brandInSub + "\" appears as a subdomain of unrelated domain " + reg, host, 6);
        else signals.put("misleading-subdomain", false);

        String pathQ = ((u.getPath() == null ? "" : u.getPath()) + " " + (u.getQuery() == null ? "" : u.getQuery())).toLowerCase(Locale.ROOT);
        String brandInPath = null;
        for (String d : TRUSTED) {
            String b = d.split("\\.")[0];
            if (pathQ.contains(b)) { brandInPath = b; break; }
        }
        if (brandInPath != null && !trustedReg && !reg.contains(brandInPath))
            add.add("brand-in-path", "medium", "Brand name \"" + brandInPath + "\" appears in URL path but domain is " + reg, u.getPath() == null ? "" : u.getPath().substring(0, Math.min(120, u.getPath().length())), 3);
        else signals.put("brand-in-path", false);

        String label = reg.split("\\.")[0];
        String closest = null; int best = Integer.MAX_VALUE;
        for (String td : TRUSTED) {
            String tl = td.split("\\.")[0];
            if (label.equals(tl)) { best = 0; closest = td; break; }
            int d = levenshtein(label, tl);
            if (d < best) { best = d; closest = td; }
        }
        if (best == 1 || (best == 2 && label.length() >= 6))
            add.add("typosquat", "high", "Domain \"" + reg + "\" is " + best + " edit(s) from trusted \"" + closest + "\" (possible typosquat)", reg + " ↔ " + closest, 6);
        else signals.put("typosquat", false);

        if (best > 2) {
            String contains = null;
            for (String d : TRUSTED) {
                String b = d.split("\\.")[0];
                if (b.length() >= 4 && label.contains(b)) {
                    boolean exactOfficial = false;
                    for (String t2 : TRUSTED) if (t2.split("\\.")[0].equals(b) && reg.equals(t2)) { exactOfficial = true; break; }
                    if (!exactOfficial) { contains = b; break; }
                }
            }
            if (contains != null) add.add("brand-contains-mismatch", "medium", "Domain contains brand \"" + contains + "\" but is not the official domain (" + reg + ")", reg, 4);
            else signals.put("brand-contains-mismatch", false);
        }

        String suffix = String.valueOf(parsed.getOrDefault("suffix", ""));
        String tld = suffix.contains(".") ? suffix.substring(suffix.lastIndexOf('.') + 1) : suffix;
        if (SUSPICIOUS_TLDS.contains(tld)) add.add("suspicious-tld", "low", "Uncommon/low-reputation TLD \"." + tld + "\" often abused in job scams", "." + tld, 2);
        else signals.put("suspicious-tld", false);

        if (Boolean.TRUE.equals(parsed.get("isIp"))) add.add("ip-host", "high", "URL uses a raw IP address instead of a domain name", host, 5);
        else signals.put("ip-host", false);

        if (host.split("\\.").length >= 5 || host.length() > 60)
            add.add("obfuscated-host", "low", "Unusually deep/long hostname (possible obfuscation)", host.substring(0, Math.min(120, host.length())), 2);
        else signals.put("obfuscated-host", false);

        String search = u.getQuery() == null ? "" : "?" + u.getQuery();
        if (Pattern.compile("token=|sessionid=|account=|verify=|login", Pattern.CASE_INSENSITIVE).matcher(search).find() && search.length() > 40)
            add.add("suspicious-query", "low", "Long tracking/verification query string typical of phishing kits", search.substring(0, Math.min(120, search.length())), 2);
        else signals.put("suspicious-query", false);

        double score = Math.round(Math.min(MAX, MAX * (1 - Math.exp(-raw[0] / 7))) * 10) / 10.0;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("score", score); out.put("max", MAX); out.put("findings", findings);
        out.put("signals", signals); out.put("rawWeight", raw[0]); out.put("parsed", parsed);
        return out;
    }

    private interface AddFn { void add(String id, String severity, String title, String evidence, double weight); }
}
