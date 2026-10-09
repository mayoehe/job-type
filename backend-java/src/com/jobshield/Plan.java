package com.jobshield;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/** Safe Apply action planner — port of backend/src/plan.js */
public final class Plan {
    private Plan() {}

    private static final Map<String, String> WHY_TEMPLATES = Map.of(
        "override-otp", "it asks for OTPs, UPI PINs or banking passwords, which legitimate recruiters never request",
        "override-payment", "it demands payment (registration/security/verification fee) to secure the job or release the offer",
        "override-harvest-multi", "it independently requests multiple types of sensitive identity/financial data, indicating credential harvesting");

    @SuppressWarnings("unchecked")
    public static Map<String, Object> buildVerdict(Map<String, Object> scan) {
        List<Map<String, Object>> findings = (List<Map<String, Object>>) (List<?>) scan.getOrDefault("allFindings", List.of());
        List<Map<String, Object>> confirmed = findings.stream().filter(f -> List.of("critical", "high").contains(f.get("severity"))).toList();
        double score = ((Number) scan.getOrDefault("score", 0)).doubleValue();
        Map<String, Object> m = new LinkedHashMap<>();
        if (score >= 60 || confirmed.stream().anyMatch(f -> "critical".equals(f.get("severity")))) {
            m.put("verdict", "avoid"); m.put("label", "Avoid This Listing"); m.put("reason", "critical/high-severity evidence or high risk score");
        } else if (score >= 40 || !confirmed.isEmpty()) {
            m.put("verdict", "verify"); m.put("label", "Verify Employer"); m.put("reason", "suspicious signals require independent verification before any further step");
        } else {
            long unverified = findings.stream().filter(f -> "info".equals(f.get("severity")) && String.valueOf(f.get("title")).matches("(?i).*unknown.*|.*unverif.*|.*could not be.*")).count();
            if (unverified >= 2) { m.put("verdict", "verify"); m.put("label", "Verify Employer"); m.put("reason", "key facts could not be independently confirmed"); }
            else { m.put("verdict", "proceed"); m.put("label", "Proceed Carefully"); m.put("reason", "no strong fraud evidence, but low risk does not guarantee safety"); }
        }
        return m;
    }

    @SuppressWarnings("unchecked")
    public static String explainWhy(Map<String, Object> scan) {
        List<Map<String, Object>> findings = (List<Map<String, Object>>) (List<?>) scan.getOrDefault("allFindings", List.of());
        List<Map<String, Object>> confirmed = findings.stream().filter(f -> List.of("critical", "high").contains(f.get("severity"))).limit(3).toList();
        double score = ((Number) scan.getOrDefault("score", 0)).doubleValue();
        if (confirmed.isEmpty()) {
            if (score >= 20) return "Several weaker signals were found, but nothing conclusive. Treat the listing as unproven and verify the employer independently.";
            return "No strong fraud evidence was detected in this listing. That is reassuring but not a guarantee — verify the employer and stay alert for later money or credential requests.";
        }
        List<Map<String, Object>> overrides = (List<Map<String, Object>>) (List<?>) scan.getOrDefault("overrides", List.of());
        List<String> bits = new ArrayList<>();
        for (Map<String, Object> f : confirmed) {
            String ev = String.valueOf(f.get("evidence"));
            String prefix = ev.length() >= 30 ? ev.substring(0, 30) : ev;
            Map<String, Object> o = overrides.stream().filter(x -> {
                List<Object> evs = (List<Object>) (List<?>) x.getOrDefault("evidence", List.of());
                return evs.stream().anyMatch(e -> String.valueOf(e).length() >= 30 ? String.valueOf(e).substring(0, 30).equals(prefix) : String.valueOf(e).equals(ev));
            }).findFirst().orElse(null);
            if (o != null && WHY_TEMPLATES.containsKey(String.valueOf(o.get("id")))) bits.add(WHY_TEMPLATES.get(String.valueOf(o.get("id"))));
            else {
                String t = String.valueOf(f.get("title"));
                bits.add("it shows \u201c" + (t.isEmpty() ? t : Character.toLowerCase(t.charAt(0)) + t.substring(1)) + "\u201d");
            }
        }
        return "This listing may be unsafe because " + String.join("; and ", bits) + ".";
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> has(Map<String, Object> scan, String frag, List<String> sevs) {
        List<Map<String, Object>> findings = (List<Map<String, Object>>) (List<?>) scan.getOrDefault("allFindings", List.of());
        return findings.stream().filter(f -> String.valueOf(f.get("id")).contains(frag) && sevs.contains(f.get("severity"))).toList();
    }

    private static List<String> ids(List<Map<String, Object>> fs) { return fs.stream().map(f -> String.valueOf(f.get("id"))).toList(); }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> buildSteps(Map<String, Object> scan, Map<String, Object> verification, Map<String, Object> checklist, String mode) {
        List<Map<String, Object>> steps = new ArrayList<>();
        AddStep add = (title, detail, derivedFrom, priority) -> {
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("title", title); s.put("detail", detail); s.put("derivedFrom", derivedFrom); s.put("priority", priority);
            steps.add(s);
        };
        List<String> critHigh = List.of("critical", "high");
        List<Map<String, Object>> otp = new ArrayList<>(); otp.addAll(has(scan, "otp-critical", critHigh)); otp.addAll(has(scan, "otp-pin-harvest", critHigh));
        List<Map<String, Object>> pay = new ArrayList<>(); pay.addAll(has(scan, "payment-for-job", critHigh)); pay.addAll(has(scan, "fee-job", critHigh));
        List<Map<String, Object>> harvest = new ArrayList<>();
        harvest.addAll(has(scan, "early-sensitive-harvest", critHigh)); harvest.addAll(has(scan, "cred-aadhaar", critHigh));
        harvest.addAll(has(scan, "cred-pan", critHigh)); harvest.addAll(has(scan, "cred-bank", critHigh)); harvest.addAll(has(scan, "excessive-collection", critHigh));
        List<Map<String, Object>> domain = new ArrayList<>();
        for (String g : List.of("typosquat", "misleading-subdomain", "brand-identity-mismatch", "brand-contains-mismatch", "homoglyph", "shortener", "ip-host"))
            domain.addAll(has(scan, g, critHigh));

        if (!pay.isEmpty()) add.add("Do not pay any money", "Do not pay registration, security, verification or training fees by UPI, QR or transfer — genuine employers in India do not charge candidates to hire them. Break contact if payment is insisted upon.", ids(pay), "urgent");
        if (!otp.isEmpty()) add.add("Do not share OTPs, PINs or passwords", "Never share OTPs, UPI PINs, CVV, netbanking or card passwords. No genuine hiring step needs them — not even for \u201cverification\u201d or \u201csalary activation\u201d.", ids(otp), "urgent");
        if (!harvest.isEmpty()) add.add("Do not send identity/financial documents yet", "Do not share Aadhaar, PAN, bank details, passbook or card copies at this application stage. Such documents, if ever needed, are verified in person after a provisional offer — never over WhatsApp/Telegram forms.", ids(harvest), "urgent");
        if (!domain.isEmpty()) {
            Map<String, Object> ev = domain.get(0);
            add.add("Check the web address character by character", "\u201c" + ev.get("title") + ".\u201d Open the employer's real site by typing its address yourself; do not click links in the message. A familiar brand name in a link does not make it official.", ids(domain), "normal");
        }
        String overall = verification == null ? null : String.valueOf(verification.get("overall"));
        if ("mismatch".equals(overall)) {
            List<Object> chks = (List<Object>) (List<?>) verification.getOrDefault("checks", List.of());
            List<String> parts = new ArrayList<>();
            for (Object o : chks) {
                Map<String, Object> c = (Map<String, Object>) o;
                if ("mismatch".equals(c.get("status"))) parts.add("Mismatch: " + c.get("label") + " — " + c.get("evidence"));
            }
            String joined = String.join(" ", parts);
            add.add("Resolve the identity mismatch", joined.substring(0, Math.min(280, joined.length())) + " Contact the company through independently found details before continuing.", List.of("verify:domain-comparison", "verify:recruiter-email"), "normal");
        }
        if ("could-not-verify".equals(overall)) {
            Object od = verification.get("officialDomain");
            add.add("Verify the employer independently", "Independently locate the official website" + (od != null ? " (directory lead: " + od + ")" : "") + " and confirm this vacancy there or with HR reached via official contact details — not the phone/email in this message.", List.of("verify:official-website", "verify:vacancy-corroboration"), "normal");
        }
        if ("verified".equals(overall))
            add.add("Keep the verified trail", "You have partial independent corroboration — still apply only through the official channel and re-check if anyone later asks for money or credentials.", List.of("verify:domain-comparison", "verify:vacancy-corroboration"), "normal");
        List<String> medPlus = List.of("medium", "high", "critical");
        List<Map<String, Object>> off = has(scan, "offchannel", medPlus);
        if (!off.isEmpty()) add.add("Stay on official channels", "Do not move the conversation to personal WhatsApp/Telegram accounts or install apps/APKs the recruiter sends. Keep communication on the official portal or corporate email.", ids(off), "normal");
        List<Map<String, Object>> urg = has(scan, "urgency", medPlus);
        List<Map<String, Object>> guar = has(scan, "guarantee-salary", List.of("medium", "high"));
        List<Map<String, Object>> press = new ArrayList<>(urg); press.addAll(guar);
        if (!press.isEmpty()) add.add("Slow down — pressure is a tactic", "Countdowns, \u201clast chance\u201d offers and guaranteed high salaries without interviews are pressure tactics. A real offer will survive you taking a day to verify it.", ids(press), "normal");
        List<Map<String, Object>> failedChecks = new ArrayList<>();
        if (checklist != null) for (Object o : (List<Object>) (List<?>) ((Map<String, Object>) checklist).getOrDefault("items", List.of())) {
            Map<String, Object> c = (Map<String, Object>) o;
            if ("failed".equals(c.get("state"))) failedChecks.add(c);
        }
        if (steps.isEmpty() && !failedChecks.isEmpty()) {
            List<String> labels = failedChecks.stream().map(c -> String.valueOf(c.get("label"))).toList();
            String joined = String.join("; ", labels);
            add.add("Work through the failed safety checks", joined.substring(0, Math.min(260, joined.length())), failedChecks.stream().map(c -> String.valueOf(c.get("id"))).toList(), "normal");
        }
        if (steps.isEmpty()) add.add("Apply standard caution", "message".equals(mode)
            ? "Even without red flags: verify the sender independently, keep communication on official channels, and never share money or credentials."
            : "Even without red flags: verify the vacancy on the official careers site, use official contact details, and never share money or credentials during application.", List.of(), "normal");
        return steps;
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> buildProtection(Map<String, Object> scan) {
        List<Map<String, Object>> F = (List<Map<String, Object>>) (List<?>) scan.getOrDefault("allFindings", List.of());
        List<List<String>> defs = List.of(
            List.of("aadhaar-pan"), List.of("bank-cards"), List.of("otp-pin"), List.of("documents"), List.of("payments"));
        String[] ids = {"aadhaar-pan", "bank-cards", "otp-pin", "documents", "payments"};
        String[] labels = {"Aadhaar & PAN", "Bank accounts & cards", "OTPs, UPI PINs & passwords", "Identity documents & uploads", "Fees & deposits"};
        String[] risks = {
            "Sharing enables identity theft and SIM/bank fraud in your name.",
            "Account numbers, IFSC, passbook/cheque copies and card details enable unauthorised withdrawals.",
            "Never share — these authorise transactions instantly and cannot be undone. No hiring step needs them.",
            "Photos, signatures, passports and salary slips fuel impersonation. Share only in person, after a provisional offer, through official channels.",
            "Registration, security, training or \u201crefundable\u201d fees for a job are a hallmark of recruitment fraud. Do not pay."};
        String[][] frags = {
            {"cred-aadhaar", "cred-pan", "early-sensitive-harvest"},
            {"cred-bank", "early-sensitive-harvest"},
            {"otp-critical", "otp-pin-harvest"},
            {"excessive-collection", "early-sensitive-harvest"},
            {"payment-for-job", "fee-job"}};
        List<Map<String, Object>> groups = new ArrayList<>();
        for (int i = 0; i < ids.length; i++) {
            final int idx = i;
            List<Map<String, Object>> found = F.stream().filter(f -> {
                for (String g : frags[idx]) if (String.valueOf(f.get("id")).contains(g)) return true;
                return false;
            }).toList();
            Map<String, Object> g = new LinkedHashMap<>();
            g.put("id", ids[idx]); g.put("label", labels[idx]); g.put("risk", risks[idx]);
            boolean requested = found.stream().anyMatch(f -> List.of("critical", "high").contains(f.get("severity")));
            g.put("status", requested ? "requested" : (!found.isEmpty() ? "mentioned" : "not-detected"));
            List<Map<String, Object>> slim = new ArrayList<>();
            for (Map<String, Object> f : found) {
                Map<String, Object> s = new LinkedHashMap<>();
                s.put("id", f.get("id")); s.put("severity", f.get("severity")); s.put("title", f.get("title")); s.put("evidence", f.get("evidence"));
                slim.add(s);
            }
            g.put("findings", slim);
            groups.add(g);
        }
        return groups;
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> buildHighlights(String text, List<Map<String, Object>> findings) {
        String src = text == null ? "" : text;
        String slow = src.toLowerCase();
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> f : findings) {
            if (!List.of("critical", "high", "medium").contains(f.get("severity"))) continue;
            String clean = String.valueOf(f.get("evidence"))
                .replaceAll("X{3,}(?:[-\\s]*X{3,})*", " ")
                .replaceAll("\\[REDACTED-[A-Z-]+\\]", " ")
                .replaceAll("•+", " ")
                .replaceAll("\\s+", " ").trim();
            int[] hit = null;
            for (int len = Math.min(70, clean.length()); len >= 25 && hit == null; len -= 5) {
                for (int i = 0; i + len <= clean.length() && hit == null; i += 10) {
                    String probe = clean.substring(i, i + len).toLowerCase();
                    if (probe.matches("(?s).*[a-z\\u0900-\\u097f]{4}.*")) {
                        int idx = slow.indexOf(probe);
                        if (idx >= 0) hit = new int[]{idx, len};
                    }
                }
            }
            if (hit == null) continue;
            int idx = hit[0];
            String before = src.substring(0, idx);
            int bs = Math.max(Math.max(Math.max(before.lastIndexOf(". "), before.lastIndexOf("।")), before.lastIndexOf("\n")), Math.max(before.lastIndexOf("! "), before.lastIndexOf("? ")));
            int start = bs < 0 ? Math.max(0, idx - 40) : bs + 1;
            String after = src.substring(idx);
            java.util.regex.Matcher m = Pattern.compile("[.!?।\n]").matcher(after);
            int end = (m.find()) ? idx + Math.min(m.start() + 1, 280) : Math.min(src.length(), idx + 160);
            Map<String, Object> h = new LinkedHashMap<>();
            h.put("findingId", f.get("id")); h.put("category", f.get("category")); h.put("severity", f.get("severity"));
            h.put("title", f.get("title")); h.put("why", whyFor(f)); h.put("recommendation", recFor(f));
            h.put("quote", Redact.excerpt(src.substring(start, Math.max(start, Math.min(end, src.length()))).trim(), 280));
            h.put("start", start); h.put("end", end);
            out.add(h);
        }
        Map<String, Integer> rank = Map.of("critical", 3, "high", 2, "medium", 1);
        out.sort((a, b) -> {
            int c = Integer.compare(((Number) a.get("start")).intValue(), ((Number) b.get("start")).intValue());
            if (c != 0) return c;
            return Integer.compare(rank.getOrDefault(String.valueOf(b.get("severity")), 0), rank.getOrDefault(String.valueOf(a.get("severity")), 0));
        });
        List<Map<String, Object>> dedup = new ArrayList<>();
        for (Map<String, Object> h : out) {
            int s = ((Number) h.get("start")).intValue(), e = ((Number) h.get("end")).intValue();
            boolean overlap = false;
            for (Map<String, Object> p : dedup) {
                int ps = ((Number) p.get("start")).intValue(), pe = ((Number) p.get("end")).intValue();
                if (s < pe - 10 && e > ps + 10) { overlap = true; break; }
            }
            if (!overlap) dedup.add(h);
        }
        return dedup;
    }

    private static final Map<String, String> WHY_MAP = Map.of(
        "ling-fee-job", "Genuine employers do not charge candidates to hire them. Upfront or \u201crefundable\u201d fees are the classic advance-fee job scam.",
        "beh-payment-for-job", "Payment demanded to release a job or offer letter is a hallmark of recruitment fraud.",
        "ling-cred-otp-critical", "OTPs, UPI PINs and banking passwords authorise money movement. No hiring step ever needs them.",
        "beh-otp-pin-harvest", "Requests for OTPs/PINs/passwords during hiring are credential harvesting, not verification.",
        "ling-cred-aadhaar", "Aadhaar enables identity theft. Early collection before the employer is verified indicates harvesting.",
        "ling-cred-pan", "PAN misuse enables financial fraud. It is never needed at the application stage.",
        "ling-cred-bank", "Bank/card details at application stage enable unauthorised withdrawals.",
        "beh-early-sensitive-harvest", "Sensitive documents requested before employer identity is established indicate harvesting.");

    private static String whyFor(Map<String, Object> f) {
        String id = String.valueOf(f.get("id"));
        if (WHY_MAP.containsKey(id)) return WHY_MAP.get(id);
        String cat = String.valueOf(f.get("category"));
        if ("domain".equals(cat)) return "The web address itself shows deception markers (lookalike spelling, misleading subdomain, shortener), independent of page content.";
        if ("technical".equals(cat)) return "Infrastructure signals (missing HTTPS, long redirects, threat-listing) raise caution but never decide alone.";
        if ("employer".equals(cat)) return "The employer connection could not be independently corroborated — uncertainty to resolve, not proof of fraud.";
        if (id.contains("urgency")) return "Countdowns and threats of losing the offer are pressure tactics to stop you verifying.";
        if (id.contains("offchannel")) return "Moving you to personal chat apps evades official records and verification.";
        if (id.contains("guarantee")) return "Guaranteed jobs and disproportionate salaries without a selection process are bait.";
        return "This behaviour deviates from standard, verifiable hiring practice.";
    }

    private static final Map<String, String> REC_MAP = Map.of(
        "ling-fee-job", "Do not pay. Independently verify the recruiter and report fee demands.",
        "beh-payment-for-job", "Do not pay. Break contact if payment is insisted upon.",
        "ling-cred-otp-critical", "Do not share. End the conversation if pressed.",
        "beh-otp-pin-harvest", "Do not share any OTP, PIN or password.",
        "ling-cred-aadhaar", "Do not share Aadhaar now; in-person verification only after a provisional offer.",
        "ling-cred-pan", "Do not share PAN at this stage.",
        "ling-cred-bank", "Do not share bank/card details during application.");

    private static String recFor(Map<String, Object> f) {
        String id = String.valueOf(f.get("id"));
        if (REC_MAP.containsKey(id)) return REC_MAP.get(id);
        String cat = String.valueOf(f.get("category"));
        if ("domain".equals(cat)) return "Type the official address yourself; do not click message links.";
        if ("employer".equals(cat)) return "Corroborate through the official careers page or HR.";
        return "Pause, verify independently, and do not share money or credentials.";
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> alreadySharedGuidance(Map<String, Object> scan) {
        List<Map<String, Object>> findings = (List<Map<String, Object>>) (List<?>) scan.getOrDefault("allFindings", List.of());
        boolean money = findings.stream().anyMatch(f -> String.valueOf(f.get("id")).matches("(?i).*otp.*|.*upi.*|.*bank.*|.*card.*|.*cvv.*|.*password.*|.*payment.*|.*fee.*") && !"info".equals(f.get("severity")));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("money", money
            ? "You may have exposed financial credentials. Immediately: (1) call your bank\u2019s official customer-care number (from the bank website or card, not the recruiter) to block/freeze affected accounts and cards; (2) change UPI PIN and netbanking passwords from the official app; (3) review recent transactions and dispute unknown ones in writing."
            : "If you shared any financial details (OTP, PIN, card, bank login) or paid money: call your bank immediately via its official helpline to freeze/block, reset credentials from the official app, and dispute unknown transactions.");
        m.put("identity", "If you shared Aadhaar, PAN or document copies: (1) lock your Aadhaar biometrics via myaadhaar.uidai.gov.in; (2) monitor for misuse — check your CIBIL/credit report and watch for unknown SIMs or accounts; (3) keep copies of everything the recruiter sent.");
        m.put("report", "Report the fraud at the National Cybercrime Reporting Portal — https://cybercrime.gov.in — or call the national cybercrime helpline 1930. Preserve message screenshots, UPI transaction IDs, phone numbers and URLs. General guidance, not legal advice.");
        return m;
    }

    @SuppressWarnings("unchecked")
    public static String recommendedResponse(Map<String, Object> scan, String channel) {
        List<Map<String, Object>> findings = (List<Map<String, Object>>) (List<?>) scan.getOrDefault("allFindings", List.of());
        double score = ((Number) scan.getOrDefault("score", 0)).doubleValue();
        boolean danger = score >= 40 || findings.stream().anyMatch(f -> List.of("critical", "high").contains(f.get("severity")));
        Map<String, String> where = Map.of("whatsapp", "WhatsApp", "email", "email", "offer", "offer letter", "interview", "interview invitation", "payment", "payment request");
        String w = where.getOrDefault(channel, "message");
        if (danger) return "Do not reply with any money, documents, OTPs or credentials. Safe response: \u201cI apply only through official company channels. Please share your corporate email ID and the vacancy link on the company\u2019s official careers page so I can verify and proceed there.\u201d Then verify independently — and report at cybercrime.gov.in / 1930 if fraud is confirmed. This " + w + " shows strong fraud signals (score " + score + "/100).";
        return "No strong fraud signals (score " + score + "/100), but stay cautious. Safe response: \u201cThanks — I\u2019ll verify this vacancy on the company\u2019s official careers page and continue there. Please share your official contact details.\u201d Never share OTPs, PINs or fees at any stage.";
    }

    private interface AddStep { void add(String title, String detail, List<String> derivedFrom, String priority); }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> buildSafeApply(Map<String, Object> scan, Map<String, Object> verification, Map<String, Object> checklist, String text, String mode, String channel) {
        Map<String, Object> verdict = buildVerdict(scan);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("mode", mode);
        m.put("verdict", verdict.get("verdict")); m.put("verdictLabel", verdict.get("label")); m.put("verdictReason", verdict.get("reason"));
        m.put("score", scan.get("score")); m.put("band", scan.get("band")); m.put("level", scan.get("level")); m.put("color", scan.get("color"));
        m.put("whyUnsafe", explainWhy(scan));
        m.put("steps", buildSteps(scan, verification, checklist, mode));
        m.put("checklist", checklist);
        m.put("verification", verification);
        m.put("protection", buildProtection(scan));
        m.put("highlights", buildHighlights(text, (List<Map<String, Object>>) (List<?>) scan.getOrDefault("allFindings", List.of())));
        m.put("alreadyShared", alreadySharedGuidance(scan));
        m.put("recommendedResponse", "message".equals(mode) ? recommendedResponse(scan, channel) : null);
        return m;
    }
}
