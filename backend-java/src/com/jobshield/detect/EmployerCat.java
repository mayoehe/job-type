package com.jobshield.detect;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** E. Employer & evidence verification — max 10. Port of detectors/employer.js */
public final class EmployerCat {
    private EmployerCat() {}
    public static final double MAX = 10;

    public static Map<String, Object> analyse(Map<String, Object> ev) {
        if (ev == null) ev = Map.of();
        List<Object> findings = new ArrayList<>();
        Map<String, Object> signals = new LinkedHashMap<>();
        double[] raw = {0};
        AddFn add = (id, severity, title, evidence, weight) -> {
            raw[0] += weight;
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("id", "emp-" + id); f.put("category", "employer"); f.put("severity", severity);
            f.put("title", title); f.put("evidence", evidence); f.put("points", weight);
            findings.add(f);
            signals.put(id, true);
        };
        InfoFn ok = (id, title, evidence) -> {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("id", "emp-" + id); f.put("category", "employer"); f.put("severity", "info");
            f.put("title", title); f.put("evidence", evidence); f.put("points", 0);
            findings.add(f);
            signals.put(id, false);
        };

        boolean hasUrl = isTrue(ev.get("hasUrl"));
        boolean hasText = isTrue(ev.get("hasText"));

        if (!hasUrl && !hasText) {
            add.add("no-input", "low", "Nothing verifiable provided", "empty scan", 2);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("score", 2.0); out.put("max", MAX); out.put("findings", findings);
            out.put("signals", signals); out.put("rawWeight", raw[0]);
            return out;
        }

        if (ev.get("officialDomain") != null)
            ok.ok("official-known", "Employer official domain noted: " + ev.get("officialDomain"), String.valueOf(ev.get("officialDomain")));
        else add.add("no-official-domain", "low", "No verifiable official employer website could be established from the listing", "no official domain reference found", 3);

        if (Boolean.TRUE.equals(ev.get("vacancyOnOfficialSite")))
            ok.ok("vacancy-verified", "Vacancy appears on the employer official careers page (as reported by verification check)", str(ev.get("vacancyUrl"), "careers page"));
        else if (hasUrl || hasText)
            add.add("vacancy-unverified", "low", "Vacancy could not be corroborated on an official careers page — uncertainty, not proof of fraud", "unverified", 3);

        if (ev.get("contactMatches") != null)
            ok.ok("contact-match", "Recruiter contact matches independently verifiable company information", String.valueOf(ev.get("contactMatches")));
        else if (ev.get("contactPresent") != null)
            add.add("contact-unverifiable", "medium", "Recruiter contact could not be matched to verifiable company information", String.valueOf(ev.get("contactPresent")).substring(0, Math.min(120, String.valueOf(ev.get("contactPresent")).length())), 3);
        else add.add("contact-missing", "low", "No verifiable recruiter contact information present", "missing contact", 2);

        if (Boolean.TRUE.equals(ev.get("govtClaim")) && !Boolean.TRUE.equals(ev.get("govtCorroborated")))
            add.add("govt-uncorroborated", "medium", "Government-recruitment claim could not be corroborated on an official .gov.in domain", "uncorroborated govt claim", 4);
        else if (Boolean.TRUE.equals(ev.get("govtClaim")))
            ok.ok("govt-verified", "Government vacancy corroborated on official domain", String.valueOf(ev.get("govtCorroborated")));
        else signals.put("govt-uncorroborated", false);

        if (ev.get("applicationDomainLinked") != null)
            ok.ok("domain-linked", "Application domain is linked from a trusted employer source", String.valueOf(ev.get("applicationDomainLinked")));
        else if (hasUrl) add.add("domain-unlinked", "low", "Application domain is not demonstrably linked from a trusted employer source", "unlinked", 2);

        double score = Math.round(Math.min(MAX, raw[0]) * 10) / 10.0;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("score", score); out.put("max", MAX); out.put("findings", findings);
        out.put("signals", signals); out.put("rawWeight", raw[0]);
        return out;
    }

    private interface AddFn { void add(String id, String severity, String title, String evidence, double weight); }
    private interface InfoFn { void ok(String id, String title, String evidence); }

    private static boolean isTrue(Object v) {
        if (v instanceof Boolean b) return b;
        if (v instanceof String s) return !s.isEmpty() && !s.equals("false");
        if (v instanceof Number n) return n.doubleValue() != 0;
        return v != null;
    }

    private static String str(Object v, String def) { return v == null ? def : String.valueOf(v); }
}
