package com.jobshield;

import com.jobshield.detect.Behavioural;
import com.jobshield.detect.EmployerCat;
import com.jobshield.detect.Linguistic;
import com.jobshield.detect.Technical;
import com.jobshield.detect.UrlAnalysis;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Risk aggregation — port of backend/src/scoring.js */
public final class Scoring {
    private Scoring() {}

    public static Map<String, Object> bandFor(double score) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (score >= 80) { m.put("band", "Critical risk"); m.put("level", "critical"); m.put("color", "#dc2626"); }
        else if (score >= 60) { m.put("band", "High risk"); m.put("level", "high"); m.put("color", "#ea580c"); }
        else if (score >= 40) { m.put("band", "Suspicious"); m.put("level", "suspicious"); m.put("color", "#d97706"); }
        else if (score >= 20) { m.put("band", "Caution"); m.put("level", "caution"); m.put("color", "#ca8a04"); }
        else { m.put("band", "Low apparent risk"); m.put("level", "low"); m.put("color", "#16a34a"); }
        return m;
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> computeOverrides(Map<String, Object> linguistic, Map<String, Object> behavioural) {
        List<Map<String, Object>> overrides = new ArrayList<>();
        List<Map<String, Object>> all = new ArrayList<>();
        for (Object o : (List<Object>) linguistic.getOrDefault("findings", List.of())) {
            Map<String, Object> f = (Map<String, Object>) o;
            if (List.of("critical", "high").contains(f.get("severity"))) all.add(f);
        }
        for (Object o : (List<Object>) behavioural.getOrDefault("findings", List.of())) {
            Map<String, Object> f = (Map<String, Object>) o;
            if (List.of("critical", "high").contains(f.get("severity"))) all.add(f);
        }
        java.util.function.Predicate<String> has = frag -> all.stream().anyMatch(f -> String.valueOf(f.get("id")).contains(frag));

        if (has.test("otp-critical") || has.test("otp-pin-harvest")) {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("id", "override-otp"); o.put("severity", "critical");
            o.put("title", "Immediate warning: OTP / UPI PIN / banking password requested");
            o.put("detail", "Legitimate recruiters never ask for OTPs, UPI PINs or banking passwords. Stop and do not share these under any circumstance.");
            o.put("floor", 80);
            o.put("evidence", all.stream().filter(f -> String.valueOf(f.get("id")).contains("otp")).map(f -> f.get("evidence")).limit(2).toList());
            overrides.add(o);
        }
        if (has.test("payment-for-job") || has.test("fee-job")) {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("id", "override-payment"); o.put("severity", "high");
            o.put("title", "High-severity warning: payment demanded to secure employment");
            o.put("detail", "Demanding a registration / security / verification fee for a job or offer release is a hallmark of recruitment fraud in India.");
            o.put("floor", 65);
            o.put("evidence", all.stream().filter(f -> String.valueOf(f.get("id")).contains("payment") || String.valueOf(f.get("id")).contains("fee")).map(f -> f.get("evidence")).limit(2).toList());
            overrides.add(o);
        }
        String[] harvestIds = {"cred-aadhaar", "cred-pan", "cred-bank", "early-sensitive-harvest", "excessive-collection"};
        List<Map<String, Object>> harvest = all.stream().filter(f -> {
            for (String h : harvestIds) if (String.valueOf(f.get("id")).contains(h)) return true;
            return false;
        }).toList();
        boolean has80 = overrides.stream().anyMatch(o -> ((Number) o.get("floor")).intValue() >= 80);
        if (harvest.size() >= 2 && !has80) {
            Map<String, Object> o = new LinkedHashMap<>();
            o.put("id", "override-harvest-multi"); o.put("severity", "high");
            o.put("title", "Multiple credential-harvesting indicators (" + harvest.size() + ") elevate risk despite any clean technical signals");
            o.put("detail", "Independent requests for identity/financial data collectively indicate harvesting.");
            o.put("floor", 60);
            o.put("evidence", harvest.stream().map(f -> f.get("evidence")).limit(3).toList());
            overrides.add(o);
        }
        return overrides;
    }

    @SuppressWarnings("unchecked")
    public static List<String> buildRecommendations(Map<String, Object> result) {
        List<String> recs = new ArrayList<>();
        List<Map<String, Object>> overrides = (List<Map<String, Object>>) result.getOrDefault("overrides", List.of());
        boolean hasOtp = overrides.stream().anyMatch(o -> "override-otp".equals(o.get("id")));
        boolean hasPay = overrides.stream().anyMatch(o -> "override-payment".equals(o.get("id")));
        if (hasOtp) recs.add("Do NOT share OTPs, UPI PINs, passwords or banking credentials with anyone — no genuine hiring process needs them.");
        if (hasPay) recs.add("Do NOT pay any recruiter to secure a job, release an offer letter, or refund a \"verification fee\".");
        recs.add("Verify the vacancy through the employer's independently located official careers website (type the address yourself; do not click links in the message).");
        recs.add("Contact the employer through independently verified contact information, not the phone/email in the suspicious message.");
        Map<String, Object> cats = (Map<String, Object>) result.get("categories");
        if (cats != null) {
            Map<String, Object> domain = (Map<String, Object>) cats.get("domain");
            if (domain != null && ((Number) domain.get("score")).doubleValue() > 5)
                recs.add("Check the domain carefully: look for typosquatting, extra brand words, misleading subdomains, or URL shorteners.");
            Map<String, Object> emp = (Map<String, Object>) cats.get("employer");
            if (emp != null && ((Number) emp.get("score")).doubleValue() >= 5)
                recs.add("Ask the recruiter for verifiable company details (official email domain, CIN/registered office) and cross-check them.");
        }
        recs.add("Report suspected fraud to the National Cybercrime Reporting Portal (cybercrime.gov.in) or call helpline 1930. This is general guidance, not legal advice.");
        if (((Number) result.get("score")).doubleValue() < 20)
            recs.add("Low apparent risk does NOT guarantee safety — stay alert for any new requests for money or credentials as the process continues.");
        return recs;
    }

    private static final String[] KNOWN_OFFICIAL = {"infosys.com", "tcs.com", "wipro.com", "hcltech.com", "techmahindra.com", "reliance.com", "tata.com", "tatamotors.com", "flipkart.com", "amazon.in", "amazon.com", "google.com", "microsoft.com", "ibm.com", "accenture.com", "cognizant.com", "icici.com", "hdfcbank.com", "sbi.co.in", "statebankofindia.com", "naukri.com", "linkedin.com", "indeed.com", "upsc.gov.in", "ssc.gov.in", "ibps.in", "upsconline.nic.in", "employmentnews.gov.in", "iitb.ac.in", "iitd.ac.in"};

    public static Map<String, Object> deriveEmployerHints(String text, String url) {
        Map<String, Object> hints = new LinkedHashMap<>();
        String host = "";
        try { host = new URI(String.valueOf(url)).getHost().toLowerCase(Locale.ROOT); } catch (Exception e) { host = ""; }
        String t = String.valueOf(text == null ? "" : text);
        Matcher em = Pattern.compile("[\\w.+-]+@([\\w.-]+\\.[a-z]{2,})", Pattern.CASE_INSENSITIVE).matcher(t);
        List<String> emails = new ArrayList<>();
        while (em.find()) emails.add(em.group(1).toLowerCase(Locale.ROOT));
        String corpMail = null;
        for (String d : emails) {
            if (!Pattern.compile("gmail|yahoo|rediffmail|outlook|hotmail|protonmail", Pattern.CASE_INSENSITIVE).matcher(d).find()) { corpMail = d; break; }
        }
        String officialRef = null;
        for (String d : KNOWN_OFFICIAL) if (t.toLowerCase(Locale.ROOT).contains(d)) { officialRef = d; break; }
        if (officialRef != null && host != null && !host.isEmpty() && (host.equals(officialRef) || host.endsWith("." + officialRef))) {
            hints.put("officialDomain", officialRef);
            hints.put("vacancyOnOfficialSite", true);
            hints.put("vacancyUrl", url);
            hints.put("applicationDomainLinked", officialRef);
        } else if (officialRef != null) {
            hints.put("officialDomain", officialRef);
        }
        if (corpMail != null && host != null && !host.isEmpty() && (host.equals(corpMail) || host.endsWith("." + corpMail) || (officialRef != null && corpMail.equals(officialRef)))) {
            hints.put("contactMatches", corpMail);
        } else if (corpMail != null && Set.of(KNOWN_OFFICIAL).contains(corpMail)) {
            hints.put("contactMatches", corpMail + " (known official domain; confirm the sender address independently)");
        } else if (corpMail != null) {
            hints.put("contactPresent", corpMail);
        } else if (!emails.isEmpty()) {
            hints.put("contactPresent", emails.get(0));
        }
        if (Pattern.compile("(sarkari|सरकारी|शासकीय|govt|government job|upsc|ssc|ibps|railway recruitment)", Pattern.CASE_INSENSITIVE).matcher(t).find()) {
            hints.put("govtClaim", true);
            if (host != null && host.matches("(?i).*gov\\.in$|.*nic\\.in$")) hints.put("govtCorroborated", host);
        }
        return hints;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> runScan(String text, String url, Map<String, Object> intel, Map<String, Object> employer, String pageText) {
        if (text == null) text = "";
        if (url == null) url = "";
        if (intel == null) intel = Map.of();
        if (employer == null) employer = Map.of();
        if (pageText == null) pageText = "";
        String combined = (!text.isEmpty() && !pageText.isEmpty()) ? text + "\n\n" + pageText : text + pageText;
        Map<String, Object> linguistic = Linguistic.analyse(combined);
        Map<String, Object> urlRes = UrlAnalysis.analyse(url);
        Map<String, Object> parsed = urlRes.get("parsed") instanceof Map ? (Map<String, Object>) urlRes.get("parsed") : null;
        Map<String, Object> behInput = new LinkedHashMap<>();
        behInput.put("text", combined); behInput.put("url", url);
        behInput.put("urlHost", safeHost(url));
        behInput.put("registrableDomain", parsed == null ? null : parsed.get("registrableDomain"));
        behInput.put("pageText", pageText);
        behInput.put("redirectCrossDomain", Boolean.TRUE.equals(intel.get("redirectCrossDomain")));
        behInput.put("finalRegistrable", intel.get("finalRegistrable"));
        Map<String, Object> behavioural = Behavioural.analyse(behInput);
        Map<String, Object> technical = Technical.analyse(intel);
        Map<String, Object> autoHints = deriveEmployerHints(combined, url);
        Map<String, Object> empInput = new LinkedHashMap<>();
        empInput.put("hasUrl", !url.isEmpty());
        empInput.put("hasText", !combined.isEmpty());
        empInput.putAll(autoHints);
        empInput.putAll(employer);
        Map<String, Object> employerRes = EmployerCat.analyse(empInput);

        double rawTotal = Math.round((num(linguistic, "score") + num(behavioural, "score") + num(urlRes, "score") + num(technical, "score") + num(employerRes, "score")) * 10) / 10.0;
        List<Map<String, Object>> overrides = computeOverrides(linguistic, behavioural);
        int floor = overrides.stream().mapToInt(o -> ((Number) o.get("floor")).intValue()).max().orElse(0);
        double score = Math.min(100, Math.max(rawTotal, floor));
        Map<String, Object> band = bandFor(score);

        List<Map<String, Object>> allFindings = new ArrayList<>();
        for (Map<String, Object> cat : List.of(linguistic, behavioural, urlRes, technical, employerRes)) {
            for (Object o : (List<Object>) cat.getOrDefault("findings", List.of())) allFindings.add((Map<String, Object>) o);
        }
        allFindings.sort((a, b) -> {
            int r = Integer.compare(severityRank(String.valueOf(b.get("severity"))), severityRank(String.valueOf(a.get("severity"))));
            if (r != 0) return r;
            return Double.compare(num(b, "points"), num(a, "points"));
        });

        long confirmed = allFindings.stream().filter(f -> List.of("critical", "high").contains(f.get("severity"))).count();
        long susp = allFindings.stream().filter(f -> "medium".equals(f.get("severity"))).count();
        long info = allFindings.stream().filter(f -> List.of("low", "info").contains(f.get("severity"))).count();

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("score", score); result.put("band", band.get("band")); result.put("level", band.get("level"));
        result.put("color", band.get("color")); result.put("rawTotal", rawTotal); result.put("floor", floor);
        Map<String, Object> cats = new LinkedHashMap<>();
        cats.put("linguistic", Map.of("score", linguistic.get("score"), "max", 35));
        cats.put("behavioural", Map.of("score", behavioural.get("score"), "max", 30));
        cats.put("domain", Map.of("score", urlRes.get("score"), "max", 15));
        cats.put("technical", Map.of("score", technical.get("score"), "max", 10));
        cats.put("employer", Map.of("score", employerRes.get("score"), "max", 10));
        result.put("categories", cats);
        result.put("overrides", overrides);
        result.put("allFindings", allFindings);
        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("confirmed", confirmed); counts.put("suspicious", susp); counts.put("info", info);
        result.put("counts", counts);
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("urlHost", safeHost(url));
        meta.put("registrableDomain", parsed == null ? null : parsed.get("registrableDomain"));
        result.put("meta", meta);
        result.put("recommendations", buildRecommendations(result));
        return result;
    }

    public static Map<String, Object> scoringDoc() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("formula", "total = linguistic(≤35) + behavioural(≤30) + domain(≤15) + technical(≤10) + employer(≤10); final = max(total, maxFloor)");
        m.put("weights", Map.of("linguistic", 35, "behavioural", 30, "domain", 15, "technical", 10, "employer", 10));
        m.put("bands", List.of("0–19 Low apparent risk", "20–39 Caution", "40–59 Suspicious", "60–79 High risk", "80–100 Critical risk"));
        m.put("overrides", List.of(
            Map.of("when", "OTP / UPI PIN / banking password requested", "floor", 80, "severity", "critical"),
            Map.of("when", "Payment demanded to secure job / release offer", "floor", 65, "severity", "high"),
            Map.of("when", "≥2 independent credential-harvesting indicators", "floor", 60, "severity", "high")));
        m.put("behaviourFirst", "Technical trust (HTTPS, domain age, clean reputation) only adds risk for negative signals and can never subtract behavioural risk. Unknown checks count as unknown, not safe.");
        return m;
    }

    public static String safeHost(String url) {
        try { return new URI(String.valueOf(url)).getHost().toLowerCase(Locale.ROOT); }
        catch (Exception e) { return ""; }
    }

    private static double num(Map<String, Object> m, String k) {
        Object v = m.get(k);
        return v instanceof Number n ? n.doubleValue() : 0;
    }

    private static int severityRank(String s) {
        return switch (s) { case "critical" -> 5; case "high" -> 4; case "medium" -> 3; case "low" -> 2; case "info" -> 1; default -> 0; };
    }
}
