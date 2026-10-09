package com.jobshield.detect;

import com.jobshield.Redact;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** B. Recruitment behaviour & structural analysis — max 30. Port of detectors/behavioural.js */
public final class Behavioural {
    private Behavioural() {}
    public static final double MAX = 30;

    private static final String[] KNOWN_BRANDS = {
        "infosys", "tcs", "wipro", "hcl", "techmahindra", "reliance", "tata", "tata motors",
        "flipkart", "amazon", "google", "microsoft", "ibm", "accenture", "cognizant",
        "icici", "hdfc", "sbi", "axis", "maruti", "hindustan unilever", "isro", "railway",
        "ssc", "upsc", "ibps", "naukri", "linkedin", "indeed"};

    public static List<String> detectBrandMentions(String text) {
        String t = String.valueOf(text == null ? "" : text).toLowerCase(Locale.ROOT);
        List<String> out = new ArrayList<>();
        for (String b : KNOWN_BRANDS) if (t.contains(b)) out.add(b);
        return out;
    }

    private static boolean hasEmployerIdentityEstablished(String text, String urlHost, Map<String, Object> hints) {
        String t = String.valueOf(text == null ? "" : text).toLowerCase(Locale.ROOT);
        Pattern[] signals = {
            Pattern.compile("about (us|the company)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("founded in \\d{4}", Pattern.CASE_INSENSITIVE),
            Pattern.compile("cin\\s*[:-]?\\s*[lu]\\d{5}", Pattern.CASE_INSENSITIVE),
            Pattern.compile("registered office", Pattern.CASE_INSENSITIVE),
            Pattern.compile("careers@|hr@|jobs@", Pattern.CASE_INSENSITIVE),
            Pattern.compile("www\\.[a-z0-9\\-]+\\.(com|in|org)", Pattern.CASE_INSENSITIVE),
            Pattern.compile("interview\\s+(venue|address|schedule)", Pattern.CASE_INSENSITIVE),
        };
        int score = 0;
        for (Pattern s : signals) if (s.matcher(t).find()) score++;
        if (hints != null && hints.get("officialDomain") != null) score += 2;
        if (urlHost != null && urlHost.matches("(?i).*gov\\.in$|.*nic\\.in$|.*\\.ac\\.in$")) score += 1;
        return score >= 2;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> analyse(Map<String, Object> input) {
        if (input == null) input = Map.of();
        String text = str(input.get("text"), str(input.get("pageText"), ""));
        String t = text.toLowerCase(Locale.ROOT);
        List<Object> findings = new ArrayList<>();
        Map<String, Object> signals = new LinkedHashMap<>();
        double[] raw = {0};
        java.util.function.BiConsumer<String, Object> markFalse = (k, v) -> signals.put(k, false);

        java.util.function.Consumer<Map<String, Object>> push = findings::add;
        AddFn add = (id, severity, title, evidence, weight) -> {
            raw[0] += weight;
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("id", "beh-" + id); f.put("category", "behavioural"); f.put("severity", severity);
            f.put("title", title); f.put("evidence", Redact.excerpt(evidence)); f.put("points", weight);
            push.accept(f);
            signals.put(id, true);
        };

        String urlHost = str(input.get("urlHost"), "");
        Map<String, Object> hints = input.get("employerHints") instanceof Map ? (Map<String, Object>) input.get("employerHints") : null;
        boolean identityEstablished = hasEmployerIdentityEstablished(text, urlHost, hints);

        Pattern DEMAND_CUE = Pattern.compile("\\b(pay|paid|payable|deposit|upi|qr|phonepe|gpay|paytm|refundable|₹|\\brs\\.?\\b|\\binr\\b|भरो|भरा|bhejo|bhej|pay karo)\\b", Pattern.CASE_INSENSITIVE);
        Pattern NO_FEE_DISCLAIMER = Pattern.compile("\\bno\\s+(fees?|charges?|advance|payment|money)\\b|without\\s+(any\\s+)?(fees?|charge|payment|advance)", Pattern.CASE_INSENSITIVE);
        Pattern STRONG_CUE = Pattern.compile("\\bpay\\b|upi|qr|₹|\\brs\\.?\\b|\\binr\\b|refundable|bhejo|bhej|भरो|भरा", Pattern.CASE_INSENSITIVE);

        Matcher payMatch = Pattern.compile("(refundable|registration|security|processing|verification|training|placement|interview|offer|appointment|joining).{0,30}(fee|deposit|charge|amount|payment)|\\bpay\\b.{0,30}(fee|deposit|₹|\\brs\\.?\\b|\\binr\\b|upi|qr)", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(text);
        if (payMatch.find()) {
            int idx = payMatch.start();
            String window = text.substring(Math.max(0, idx - 100), Math.min(text.length(), idx + payMatch.group().length() + 100));
            if (Linguistic.hasNegationAround(text, idx, payMatch.group().length())
                || (NO_FEE_DISCLAIMER.matcher(window).find() && !STRONG_CUE.matcher(window).find())
                || !DEMAND_CUE.matcher(window).find()) {
                findings.add(info("beh-payment-disclaimer", "Fee mentioned without a payment demand (e.g. \"no fees\" / official-gateway note / payroll mention) — not a demand", payMatch.group()));
                signals.put("payment-for-job", false);
            } else {
                Matcher m = Pattern.compile(".{0,60}(refundable|registration|security|processing|verification|training|placement|interview|offer|appointment|joining).{0,60}", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(text);
                add.add("payment-for-job", "critical", "Payment demanded to secure the job / release the offer", m.find() ? m.group() : "fee/payment keywords present", 10);
            }
        } else signals.put("payment-for-job", false);

        Matcher otpMatch = Pattern.compile("\\botp\\b|upi\\s*pin|\\bmpin\\b|banking password|netbanking password|card pin|cvv", Pattern.CASE_INSENSITIVE).matcher(text);
        if (otpMatch.find()) {
            if (Linguistic.hasNegationAround(text, otpMatch.start(), otpMatch.group().length())) {
                findings.add(info("beh-otp-pin-harvest", "OTP/PIN language appears in a safety warning — not a request", otpMatch.group()));
                signals.put("otp-pin-harvest", false);
            } else {
                Matcher m = Pattern.compile(".{0,60}(\\botp\\b|upi\\s*pin|banking password|netbanking password|cvv).{0,60}", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(text);
                add.add("otp-pin-harvest", "critical", "OTP / UPI PIN / banking password requested — credential harvesting", m.find() ? m.group() : "otp/pin keywords", 10);
            }
        } else signals.put("otp-pin-harvest", false);

        boolean asksAadhaar = Pattern.compile("aadhaar|aadhar|आधार", Pattern.CASE_INSENSITIVE).matcher(t).find();
        boolean asksPan = Pattern.compile("pan\\s*(card|number|details)|पैन|पॅन", Pattern.CASE_INSENSITIVE).matcher(t).find();
        boolean asksBank = Pattern.compile("bank account|account number|ifsc|passbook|cancelled cheque|debit card|credit card", Pattern.CASE_INSENSITIVE).matcher(t).find();
        int sensitiveCount = (asksAadhaar ? 1 : 0) + (asksPan ? 1 : 0) + (asksBank ? 1 : 0);
        signals.put("early-sensitive-harvest", false);
        if (sensitiveCount > 0) {
            Matcher sm = Pattern.compile(".{0,80}(aadhaar|pan\\s*(card|number)|bank account|ifsc).{0,80}", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(text);
            String span = sm.find() ? sm.group() : "";
            boolean inperson = Pattern.compile("\\bin[- ]person\\b|walk[- ]?in|originals?\\b|verification (at|in) .{0,20}(office|hub|centre|center|venue|branch)|nothing collected online", Pattern.CASE_INSENSITIVE).matcher(span + " " + text.substring(0, Math.min(400, text.length()))).find();
            if (!identityEstablished && !inperson) {
                Matcher m = Pattern.compile(".{0,60}(aadhaar|pan\\s*(card|number)|bank account|ifsc).{0,60}", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(text);
                add.add("early-sensitive-harvest", sensitiveCount >= 2 ? "critical" : "high",
                    "Sensitive identity/financial data requested before employer identity is established (" + sensitiveCount + " type" + (sensitiveCount > 1 ? "s" : "") + ")",
                    m.find() ? m.group() : "sensitive data keywords", sensitiveCount >= 2 ? 8 : 5);
            } else if (inperson && !identityEstablished) {
                Matcher m2 = Pattern.compile(".{0,60}(aadhaar|pan\\s*(card|number)|bank account|ifsc).{0,60}", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(text);
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("id", "beh-inperson-doc"); f.put("category", "behavioural"); f.put("severity", "medium");
                f.put("title", "Identity document mentioned with an in-person verification channel — lower risk than remote harvesting; verify employer first");
                f.put("evidence", Redact.excerpt(m2.find() ? m2.group() : "document keyword")); f.put("points", 2);
                findings.add(f);
                raw[0] += 2;
            } else {
                Map<String, Object> f = new LinkedHashMap<>();
                f.put("id", "beh-doc-late-stage"); f.put("category", "behavioural"); f.put("severity", "info");
                f.put("title", "Document request at a stage where employer identity appears established — verify channel before sharing");
                f.put("evidence", Redact.excerpt(text.substring(0, Math.min(140, text.length())))); f.put("points", 1);
                findings.add(f);
                raw[0] += 1; signals.put("late-stage-doc", true);
            }
        }

        String[] JOB_PLATFORMS = {"linkedin.com", "naukri.com", "indeed.com", "foundit.in", "shine.com", "timesjobs.com", "apna.co", "freshersworld.com", "cutshort.io", "wellfound.com"};
        List<String> brands = detectBrandMentions(text);
        String regDom = str(input.get("registrableDomain"), null);
        if (!brands.isEmpty() && regDom != null && !regDom.isEmpty()) {
            String reg = regDom.toLowerCase(Locale.ROOT);
            boolean mismatch = true;
            for (String b : brands) if (reg.contains(b.replaceAll("\\s+", ""))) { mismatch = false; break; }
            if (mismatch) {
                boolean isPlatform = false;
                for (String p : JOB_PLATFORMS) if (reg.equals(p) || reg.endsWith("." + p)) { isPlatform = true; break; }
                if (isPlatform) {
                    findings.add(info("beh-platform-posting", "Job posted via third-party platform (" + regDom + ") — brand difference is expected; verify the recruiter profile and vacancy on the employer's official site", "brands: " + String.join(", ", brands.subList(0, Math.min(3, brands.size()))) + " via " + regDom));
                    signals.put("brand-identity-mismatch", false);
                } else {
                    add.add("brand-identity-mismatch", "high", "Advertised brand (" + String.join(", ", brands.subList(0, Math.min(3, brands.size()))) + ") does not match application domain " + regDom, "brands: " + String.join(", ", brands.subList(0, Math.min(3, brands.size()))) + " vs domain: " + regDom, 6);
                }
            } else signals.put("brand-identity-mismatch", false);
        }

        String[] items = {"photo", "signature", "aadhaar", "pan", "passport", "voter", "ration card", "bank", "salary slip", "mother", "father", "spouse", "nominee"};
        List<String> dataItems = new ArrayList<>();
        for (String w : items) if (t.contains(w)) dataItems.add(w);
        if (dataItems.size() >= 4) {
            add.add("excessive-collection", "medium", "Application collects excessive personal data (" + dataItems.size() + " sensitive item types: " + String.join(", ", dataItems.subList(0, Math.min(5, dataItems.size()))) + ")", String.join(", ", dataItems), 4);
        } else signals.put("excessive-collection", false);

        Matcher salaryMatch = Pattern.compile("₹\\s?([\\d,]+)").matcher(text);
        boolean lowReq = Pattern.compile("(8th|10th|12th)\\s*pass|no experience|fresher", Pattern.CASE_INSENSITIVE).matcher(t).find();
        if (salaryMatch.find()) {
            long amount;
            try { amount = Long.parseLong(salaryMatch.group(1).replace(",", "")); } catch (Exception e) { amount = 0; }
            if (lowReq && amount >= 50000) {
                Matcher rm = Pattern.compile("(8th|10th|12th)\\s*pass|no experience|fresher", Pattern.CASE_INSENSITIVE).matcher(text);
                String req = rm.find() ? rm.group() : "";
                add.add("implausible-salary", "medium", "Implausible salary (₹" + String.format("%,d", amount) + ") for stated low requirements", salaryMatch.group() + " + " + req, 4);
            } else signals.put("implausible-salary", false);
        }

        Object rcd = input.get("redirectCrossDomain");
        boolean cross = rcd instanceof Boolean && (Boolean) rcd;
        if (cross) {
            add.add("redirect-to-unrelated-portal", "high", "Legitimate-looking job page redirects to unrelated data-collection domain (" + str(input.get("finalRegistrable"), "unknown") + ")", "redirect chain crosses registrable domains", 6);
        } else signals.put("redirect-to-unrelated-portal", false);

        if (Pattern.compile("(sarkari|सरकारी|शासकीय).{0,20}(naukri|job|bharti|vacancy)|govt.{0,20}job|government job", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(t).find()
            && urlHost != null && !urlHost.isEmpty() && !Pattern.compile("gov\\.in$|nic\\.in$").matcher(urlHost).find()) {
            Matcher gm = Pattern.compile(".{0,50}(sarkari|सरकारी|शासकीय|govt|government).{0,50}", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(text);
            add.add("fake-govt-portal", "high", "Government-job claim made from a non-government domain — verify on official .gov.in portal", gm.find() ? gm.group() : "govt job claim", 5);
        } else signals.put("fake-govt-portal", false);

        Matcher freeMail = Pattern.compile("[\\w.]+@(gmail|yahoo|rediffmail|outlook|hotmail|protonmail)\\.com", Pattern.CASE_INSENSITIVE).matcher(text);
        if (freeMail.find() && !brands.isEmpty()) {
            add.add("recruiter-domain-mismatch", "medium", "Recruiter uses free-mail address (" + freeMail.group() + ") while advertising brand (" + brands.get(0) + ")", freeMail.group(), 3);
        } else signals.put("recruiter-domain-mismatch", false);

        double score = text.isEmpty() ? 0 : Math.round(MAX * (1 - Math.exp(-raw[0] / 14)) * 10) / 10.0;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("score", score); out.put("max", MAX); out.put("findings", findings);
        out.put("signals", signals); out.put("rawWeight", raw[0]); out.put("identityEstablished", identityEstablished);
        return out;
    }

    private interface AddFn { void add(String id, String severity, String title, String evidence, double weight); }

    private static Map<String, Object> info(String id, String title, String evidence) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("id", id); f.put("category", "behavioural"); f.put("severity", "info");
        f.put("title", title); f.put("evidence", Redact.excerpt(evidence)); f.put("points", 0);
        return f;
    }

    private static String str(Object v, String def) {
        return v instanceof String s ? s : def;
    }
}
