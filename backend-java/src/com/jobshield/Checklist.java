package com.jobshield;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Safe-application checklist — port of backend/src/checklist.js */
public final class Checklist {
    private Checklist() {}

    @SuppressWarnings("unchecked")
    public static Map<String, Object> build(Map<String, Object> scan, Map<String, Object> verification) {
        List<Map<String, Object>> findings = new ArrayList<>();
        if (scan != null) for (Object o : (List<Object>) scan.getOrDefault("allFindings", List.of()))
            findings.add((Map<String, Object>) o);
        List<Map<String, Object>> items = new ArrayList<>();
        AddItem item = (id, label, state, detail, derivedFrom) -> {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id); m.put("label", label); m.put("state", state);
            m.put("auto", true); m.put("detail", detail); m.put("derivedFrom", derivedFrom);
            items.add(m);
        };

        Object officialDomain = verification == null ? null : verification.get("officialDomain");
        if (officialDomain != null)
            item.add("official-site", "Independently locate the employer's official website", "passed",
                "Official domain established: " + officialDomain + ". Still type it yourself rather than clicking message links.", List.of("verify:official-website"));
        else item.add("official-site", "Independently locate the employer's official website", "unverified",
            "No official website could be established from the listing. Search the company name independently.", List.of("verify:official-website"));

        Map<String, Object> corr = findCheck(verification, "vacancy-corroboration");
        if (corr != null && "verified".equals(corr.get("status")))
            item.add("vacancy", "Confirm the vacancy through the official careers page or recruiter", "passed", String.valueOf(corr.get("evidence")), List.of("verify:vacancy-corroboration"));
        else item.add("vacancy", "Confirm the vacancy through the official careers page or recruiter", "unverified",
            corr != null ? String.valueOf(corr.get("evidence")) : "Vacancy could not be corroborated — check with the employer directly.", List.of("verify:vacancy-corroboration"));

        List<Map<String, Object>> domainBad = new ArrayList<>();
        domainBad.addAll(has(findings, "typosquat")); domainBad.addAll(has(findings, "misleading-subdomain"));
        domainBad.addAll(has(findings, "brand-identity-mismatch")); domainBad.addAll(has(findings, "homoglyph"));
        domainBad.addAll(has(findings, "brand-contains-mismatch")); domainBad.addAll(has(findings, "ip-host"));
        Map<String, Object> cmp = findCheck(verification, "domain-comparison");
        if (!domainBad.isEmpty())
            item.add("app-domain", "Verify the application domain is legitimately associated with the employer", "failed",
                titles(domainBad).substring(0, Math.min(240, titles(domainBad).length())), ids(domainBad));
        else if (cmp != null && "verified".equals(cmp.get("status")))
            item.add("app-domain", "Verify the application domain is legitimately associated with the employer", "passed", String.valueOf(cmp.get("evidence")), List.of("verify:domain-comparison"));
        else if (verification == null || verification.get("listingDomain") == null)
            item.add("app-domain", "Verify the application domain is legitimately associated with the employer", "unverified", "No application URL was provided.", List.of("verify:domain-comparison"));
        else item.add("app-domain", "Verify the application domain is legitimately associated with the employer", "unverified",
            cmp != null ? String.valueOf(cmp.get("evidence")) : "Domain association could not be confirmed — compare carefully with the official domain.", List.of("verify:domain-comparison"));

        List<Map<String, Object>> recBad = has(findings, "recruiter-domain-mismatch");
        Map<String, Object> recCheck = findCheck(verification, "recruiter-email");
        if (!recBad.isEmpty() || (recCheck != null && "mismatch".equals(recCheck.get("status")))) {
            List<String> parts = new ArrayList<>(titlesList(recBad));
            List<String> from = new ArrayList<>(ids(recBad));
            if (recCheck != null && "mismatch".equals(recCheck.get("status"))) { parts.add(String.valueOf(recCheck.get("evidence"))); from.add("verify:recruiter-email"); }
            String joined = String.join(" | ", parts);
            item.add("recruiter", "Confirm the recruiter’s identity using independently obtained contact info", "failed",
                joined.substring(0, Math.min(240, joined.length())), from);
        } else if (recCheck != null && "verified".equals(recCheck.get("status")))
            item.add("recruiter", "Confirm the recruiter’s identity using independently obtained contact info", "passed", String.valueOf(recCheck.get("evidence")), List.of("verify:recruiter-email"));
        else item.add("recruiter", "Confirm the recruiter’s identity using independently obtained contact info", "unverified",
            "No verifiable recruiter contact found — obtain one from the official website, not the message.", List.of("verify:recruiter-email"));

        List<Map<String, Object>> feeBad = new ArrayList<>();
        feeBad.addAll(has(findings, "payment-for-job")); feeBad.addAll(has(findings, "fee-job"));
        if (!feeBad.isEmpty())
            item.add("fees", "Check whether any recruitment or interview fees are requested", "failed",
                "A payment is demanded to secure the job or release the offer. Do not pay — genuine employers do not charge candidates.", ids(feeBad));
        else item.add("fees", "Check whether any recruitment or interview fees are requested", "passed",
            "No recruitment-fee demand was detected in this listing. Stay alert if one appears later.", ids(hasAny(findings, "fee-job")));

        List<Map<String, Object>> piiBad = new ArrayList<>();
        piiBad.addAll(has(findings, "early-sensitive-harvest")); piiBad.addAll(has(findings, "cred-aadhaar"));
        piiBad.addAll(has(findings, "cred-pan")); piiBad.addAll(has(findings, "cred-bank"));
        piiBad.addAll(has(findings, "excessive-collection"));
        if (!piiBad.isEmpty())
            item.add("pii-collection", "Review what personal information the application collects", "failed",
                titles(piiBad).substring(0, Math.min(240, titles(piiBad).length())), ids(piiBad));
        else item.add("pii-collection", "Review what personal information the application collects", "passed",
            "No premature harvesting of identity/financial documents was detected.", List.of());

        List<Map<String, Object>> otpBad = new ArrayList<>();
        otpBad.addAll(has(findings, "otp-critical")); otpBad.addAll(has(findings, "otp-pin-harvest"));
        if (!otpBad.isEmpty())
            item.add("otp", "Confirm that no OTP, UPI PIN, or banking password is requested", "failed",
                "This listing asks for OTPs, UPI PINs or banking credentials. Never share these — no genuine hiring process needs them.", ids(otpBad));
        else item.add("otp", "Confirm that no OTP, UPI PIN, or banking password is requested", "passed",
            "No OTP / UPI PIN / password request was detected.", List.of());

        List<Map<String, Object>> incBad = new ArrayList<>();
        incBad.addAll(has(findings, "implausible-salary")); incBad.addAll(has(findings, "fake-govt-portal"));
        for (Map<String, Object> f : hasAny(findings, "contradiction"))
            if (!"info".equals(f.get("severity"))) incBad.add(f);
        double score = scan == null ? 0 : ((Number) scan.getOrDefault("score", 0)).doubleValue();
        if (!incBad.isEmpty())
            item.add("offer-consistency", "Review the offer letter and instructions for inconsistencies", "failed",
                titles(incBad).substring(0, Math.min(240, titles(incBad).length())), ids(incBad));
        else if (score >= 40)
            item.add("offer-consistency", "Review the offer letter and instructions for inconsistencies", "unverified",
                "Other risk signals are present — re-read the offer critically before proceeding.", List.of());
        else item.add("offer-consistency", "Review the offer letter and instructions for inconsistencies", "passed",
            "No salary/requirement contradictions or impersonation markers were detected.", List.of());

        Map<String, Object> counts = new LinkedHashMap<>();
        counts.put("passed", items.stream().filter(i -> "passed".equals(i.get("state"))).count());
        counts.put("failed", items.stream().filter(i -> "failed".equals(i.get("state"))).count());
        counts.put("unverified", items.stream().filter(i -> "unverified".equals(i.get("state"))).count());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("items", new ArrayList<>(items)); out.put("counts", counts); out.put("total", items.size());
        return out;
    }

    private interface AddItem { void add(String id, String label, String state, String detail, List<String> derivedFrom); }

    private static List<Map<String, Object>> has(List<Map<String, Object>> findings, String frag) {
        return findings.stream().filter(f -> String.valueOf(f.get("id")).contains(frag) && List.of("critical", "high").contains(f.get("severity"))).toList();
    }

    private static List<Map<String, Object>> hasAny(List<Map<String, Object>> findings, String frag) {
        return findings.stream().filter(f -> String.valueOf(f.get("id")).contains(frag)).toList();
    }

    private static String titles(List<Map<String, Object>> fs) { return String.join(" | ", titlesList(fs)); }
    private static List<String> titlesList(List<Map<String, Object>> fs) { return fs.stream().map(f -> String.valueOf(f.get("title"))).toList(); }
    private static List<String> ids(List<Map<String, Object>> fs) { return fs.stream().map(f -> String.valueOf(f.get("id"))).toList(); }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> findCheck(Map<String, Object> verification, String id) {
        if (verification == null) return null;
        for (Object o : (List<Object>) verification.getOrDefault("checks", List.of())) {
            Map<String, Object> c = (Map<String, Object>) o;
            if (id.equals(c.get("id"))) return c;
        }
        return null;
    }
}
