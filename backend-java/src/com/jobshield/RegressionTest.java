package com.jobshield;

import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

/** Mirrors backend/tests/regression.test.js (8 behaviour-first guarantees) — run: java -cp out com.jobshield.RegressionTest */
public final class RegressionTest {
    public static void main(String[] args) {
        Verify.loadDb(Paths.get("data/employers.json"), Paths.get("backend-java/data/employers.json"),
            Paths.get("backend/src/data/employers.json"));
        Map<String, Object> clean = Map.of("inspected", true, "https", true, "certValid", true,
            "dnsOk", true, "redirects", 0, "reputationListed", false, "domainAgeDays", 1200, "inspectNote", "simulated clean");
        String scam = "Dear Candidate, selected for Infosys work from home, salary Rs 85000. Pay refundable registration fee Rs 2499 via UPI and share Aadhaar card, PAN, bank account plus OTP on WhatsApp within 2 hours.";
        int pass = 0, fail = 0;
        pass += check("1. SSL does not drag behavioural risk to low", run(scam, "https://careers-infosys-apply.com/apply", clean).score() >= 40);
        Map<String, Object> aged = new java.util.LinkedHashMap<>(clean); aged.put("domainAgeDays", 3000);
        var r2 = run("Share your OTP and UPI PIN to confirm the offer. Pay Rs 999 verification fee.", "https://example-jobs.com/apply", aged);
        pass += check("2. aged domain keeps OTP floor>=80 + override", r2.score() >= 80 && hasOverride(r2.result(), "override-otp"));
        var r3 = run(scam, "https://clean-host-example.com/jobs", clean);
        pass += check("3. clean hosting -> high/critical", r3.level().equals("high") || r3.level().equals("critical"));
        String legit = "Infosys hiring Senior Developer in Bengaluru. Process: assessment, two technical interviews, HR round. Apply via infosys.com/careers. Original documents verified in person after provisional selection. We never ask for fees or OTPs. Contact careers@infosys.com. About the company: founded in 1981, registered office Bengaluru, CIN L85110KA1981PLC013115.";
        var r4 = Scoring.runScan(legit, "https://www.infosys.com/careers/", clean,
            Map.of("officialDomain", "infosys.com", "contactMatches", "careers@infosys.com", "vacancyOnOfficialSite", true, "applicationDomainLinked", true), "");
        pass += check("4. legit listing <40 (got " + r4.get("score") + ")", ((Number) r4.get("score")).doubleValue() < 40);
        var r5 = run(scam, "https://some-new-portal.com/apply", Map.of("inspected", false, "inspectNote", "blocked"));
        pass += check("5. unknown intel -> >=60 + tech-not-inspected", r5.score() >= 60 && hasFinding(r5.result(), "tech-not-inspected"));
        var a = run(scam, "https://x.com/a", clean); var b = run(scam, "https://x.com/a", clean);
        pass += check("6. deterministic", a.score() == b.score() && Json.stringify(a.result().get("allFindings")).equals(Json.stringify(b.result().get("allFindings"))));
        var r7 = run(scam, "", Map.of("inspected", false, "inspectNote", "no URL"));
        pass += check("7. text-only -> >=60", r7.score() >= 60);
        var r8 = run(scam, "https://secure-naukri-verification.xyz/infosys-careers/apply", clean);
        pass += check("8. every scoring category has evidence", hasEvidence(r8.result()));
        System.out.println("PASS=" + pass + " FAIL=" + (8 - pass));
        if (pass != 8) System.exit(1);
    }

    record R(Map<String, Object> result) {
        double score() { return ((Number) result.get("score")).doubleValue(); }
        String level() { return String.valueOf(result.get("level")); }
    }

    static R run(String text, String url, Map<String, Object> intel) {
        return new R(Scoring.runScan(text, url, intel, Map.of(), ""));
    }

    static int check(String name, boolean ok) {
        System.out.println((ok ? "ok   " : "FAIL ") + name);
        return ok ? 1 : 0;
    }

    @SuppressWarnings("unchecked")
    static boolean hasOverride(Map<String, Object> r, String id) {
        for (Object o : (List<Object>) r.getOrDefault("overrides", List.of()))
            if (id.equals(((Map<String, Object>) o).get("id"))) return true;
        return false;
    }

    @SuppressWarnings("unchecked")
    static boolean hasFinding(Map<String, Object> r, String id) {
        for (Object o : (List<Object>) r.getOrDefault("allFindings", List.of()))
            if (String.valueOf(((Map<String, Object>) o).get("id")).contains(id)) return true;
        return false;
    }

    @SuppressWarnings("unchecked")
    static boolean hasEvidence(Map<String, Object> r) {
        Map<String, Object> cats = (Map<String, Object>) r.get("categories");
        List<Object> findings = (List<Object>) r.getOrDefault("allFindings", List.of());
        for (Map.Entry<String, Object> e : cats.entrySet()) {
            Map<String, Object> c = (Map<String, Object>) e.getValue();
            if (((Number) c.get("score")).doubleValue() >= 2) {
                String want = e.getKey().equals("domain") ? "domain" : e.getKey();
                boolean any = false;
                for (Object o : findings) {
                    Map<String, Object> f = (Map<String, Object>) o;
                    if (want.equals(f.get("category")) && f.get("evidence") != null && !String.valueOf(f.get("evidence")).isEmpty()) { any = true; break; }
                }
                // linguistic/behavioural categories map: linguistic->linguistic, behavioural->behavioural, employer->employer
                if (!any) {
                    // fallback: employer findings have category 'employer'
                    for (Object o : findings) {
                        Map<String, Object> f = (Map<String, Object>) o;
                        if (String.valueOf(f.get("category")).equals(e.getKey()) || (e.getKey().equals("domain") && "domain".equals(f.get("category")))) {
                            if (f.get("evidence") != null && !String.valueOf(f.get("evidence")).isEmpty()) { any = true; break; }
                        }
                    }
                }
                if (!any) { System.out.println("     category " + e.getKey() + " scored without evidence"); return false; }
            }
        }
        return true;
    }
}
