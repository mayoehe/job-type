package com.jobshield.detect;

import com.jobshield.Redact;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** A. Linguistic & semantic analysis — max 35 points. Port of detectors/linguistic.js */
public final class Linguistic {
    private Linguistic() {}
    public static final double MAX = 35;

    private record Rule(String id, String severity, double weight, String title, String[] patterns) {}

    private static final Rule[] RULES = {
        new Rule("cred-aadhaar", "high", 7, "Requests Aadhaar number / copy before hiring need is established",
            new String[]{"aadhaar", "aadhar", "adhaar", "आधार", "आधार कार्ड", "aadhaar card", "aadhar number", "share your aadhaar", "aadhaar details", "आधार नंबर"}),
        new Rule("cred-pan", "high", 6, "Requests PAN details upfront",
            new String[]{"\\bpan\\b.{0,20}(card|number|details|copy)", "pan card", "पॅन कार्ड", "पैन कार्ड", "pan number", "share your pan"}),
        new Rule("cred-bank", "high", 7, "Requests bank account / card / IFSC details during application",
            new String[]{"bank account", "account number", "खाते नंबर", "ifsc", "bank details", "passbook", "cancelled cheque", "cancelled check", "debit card", "credit card", "cvv", "card number", "बँक तपशील", "बैंक विवरण"}),
        new Rule("cred-otp-critical", "critical", 12, "Requests OTP / UPI PIN / banking password — never legitimate in hiring",
            new String[]{"\\botp\\b", "one[- ]time password", "upi pin", "upi\\.pin", "mpin", "m-pin", "netbanki?ng passwords?", "banking passwords?", "(share|send|forward|tell|provide|disclose|submit|demand|bata|bhejo)[^.!?।\n]{0,40}passwords?", "passwords?[^.!?।\n]{0,40}(share|send|forward|tell|bata|bhejo|disclose|demand)", "पिन", "ओटीपी", "otp share", "otp bhejo", "otp bhej", "otp batayen", "otp sanga", "share[^.!?।\n]{0,40}otp", "forward[^.!?।\n]{0,40}otp", "upi[^.!?।\n]{0,20}pin[^.!?।\n]{0,30}(share|enter|bata)", "card[^.!?।\n]{0,30}(pin|cvv)"}),
        new Rule("fee-job", "high", 9, "Demands registration / security / training / verification fee for the job",
            new String[]{"registration fee", "registration charge", "security deposit", "refundable[^.!?।\n]{0,60}(fee|deposit|amount)", "processing fee", "verification fee", "training fee", "interview fee", "placement fee", "joining.{0,10}(fee|charge)", "application.{0,10}(fee|charge)", "jobs?[^.!?।\n]{0,40}fees?", "pay[^.!?।\n]{0,40}(to|for)[^.!?।\n]{0,40}(job|offer|appointment|selection)", "रजिस्ट्रेशन फीस", "सिक्युरिटी डिपॉजिट", "नोंदणी शुल्क", "सुरक्षा ठेव", "refundable", "(registration|verification|processing|training|placement|security|refundable|joining|interview|application)\\s+(fee|fees|charge|deposit)\\s+(rs\\.?|inr|₹)\\s?\\d", "(fee|charge|deposit|advance|शुल्क|फीस).{0,15}(₹|\\bupi\\b|\\bqr\\b)", "(₹|\\bupi\\b).{0,25}(fee|charge|deposit|भरो|bhejo|karo)", "\\bpay\\b.{0,20}(fee|charge|deposit|₹|\\brs\\b)", "फीस भरो", "पैसे भरो", "पैसे भरा"}),
        new Rule("guarantee-salary", "medium", 4, "Guaranteed job / unrealistic salary / instant selection without process",
            new String[]{"guaranteed job", "100%[^.!?।\n]{0,40}(job|placement|selection)", "no interview", "without interview", "instant selection", "spot offer", "earn[^.!?।\n]{0,40}₹[^.!?।\n]{0,40}(per day|daily|weekly)", "salary[^.!?।\n]{0,30}₹\\s?\\d", "₹\\s?\\d{5,}", "work from home[^.!?।\n]{0,40}earn", "घर बैठे कमाएं", "घरी बसून कमवा", "paisa kamao", "bina interview"}),
        new Rule("urgency", "medium", 4, "Excessive urgency / countdown / threat of losing offer",
            new String[]{"act (now|immediately|fast)", "urgent[^.!?।\n]{0,20}(join|apply|respond|reply)", "last chance", "offer expires", "limited slots", "only[^.!?।\n]{0,40}(slot|vacanc|seat)[^.!?।\n]{0,40}left", "immediately", "तुरंत", "तातडीने", "ताबडतोब", "last date[^.!?।\n]{0,40}today", "join[^.!?।\n]{0,40}today", "within[^.!?।\n]{0,20}(1|2|24)\\s?(hour|hr)"}),
        new Rule("offchannel", "medium", 5, "Pushes conversation to unofficial WhatsApp / Telegram without verifiable identity",
            new String[]{"whatsapp", "telegram", "व्हॉट्सअ‍ॅप", "व्हाट्सएप", "वॉट्सअ‍ॅप", "टेलिग्राम", "contact[^.!?।\n]{0,40}(whatsapp|telegram)", "message[^.!?।\n]{0,40}(whatsapp|telegram)", "chat[^.!?।\n]{0,40}(whatsapp|telegram)", "\\bwa\\.me\\b", "t\\.me/"}),
        new Rule("generic-copy", "low", 2, "Suspiciously generic / copied recruiter message",
            new String[]{"dear candidate", "dear applicant", "greetings from", "we are hiring[^.!?।\n]{0,40}(male|female|boys|girls)", "both fresher[^.!?।\n]{0,40}experienced[^.!?।\n]{0,20}can apply", "no experience needed[^.!?।\n]{0,30}high salary", "priya mam", "dear[^.!?।\n]{0,60}resume[^.!?।\n]{0,40}selected", "congratulations[^.!?।\n]{0,40}selected"}),
        new Rule("malware-install", "high", 8, "Asks to install unknown app / APK / open attachment",
            new String[]{"download[^.!?।\n]{0,40}(apk|app|application|software)", "install[^.!?।\n]{0,40}(app|application|apk|software)", "open[^.!?।\n]{0,30}attachment", "enable[^.!?।\n]{0,40}(screen share|anydesk|teamviewer)", "anydesk", "teamviewer", "remote access", "एपीके", "ॲप डाउनलोड"}),
        new Rule("bypass-channel", "medium", 4, "Instructs to bypass official recruitment channels",
            new String[]{"bypass", "do not apply[^.!?।\n]{0,40}(portal|website|official)", "don't apply[^.!?।\n]{0,40}official", "skip[^.!?।\n]{0,30}(hr|portal|official)", "direct joining", "direct bharti", "direct placement", "without[^.!?।\n]{0,40}(registration|application)[^.!?।\n]{0,20}portal"}),
        new Rule("contradiction", "low", 2, "Contradictory requirements / vague role with high pay",
            new String[]{"no qualification[^.!?।\n]{0,40}₹", "8th pass[^.!?।\n]{0,40}₹\\s?\\d{5}", "10th pass[^.!?।\n]{0,40}manager", "fresher[^.!?।\n]{0,40}₹\\s?[5-9]\\d{4}", "age[^.!?।\n]{0,30}18[^.!?।\n]{0,20}60[^.!?।\n]{0,20}salary"}),
    };

    private static final Pattern INPERSON_CUE = Pattern.compile("\\bin[- ]person\\b|walk[- ]?in|originals?\\b|bring .* (document|certificate)|verification (at|in) .{0,20}(office|hub|centre|center|venue|branch)", Pattern.CASE_INSENSITIVE);
    private static final Pattern OFFCHANNEL_DISCLAIMER = Pattern.compile("\\bno\\b.{0,25}(documents?|details?|data|money|payment|fees?|charges?|application).{0,30}\\b(whatsapp|telegram|online)\\b|nothing collected online|\\bnever\\b.{0,25}\\b(whatsapp|telegram)\\b|\\bdon't\\b.{0,25}\\b(whatsapp|telegram)\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern NEG_WORD = Pattern.compile("\\b(never|not|n't|without|beware|caution|alert|free|nil)\\b|कभी नहीं|नहीं|नही|नका\\b|नाही|बिना|मुफ्त|निःशुल्क|निशुल्क|मोफत");
    private static final Pattern ASK_WORD = Pattern.compile("\\b(ask|asks|asked|request|demand|charge|collect|share|need|take|pay)\\b|मांगा|मांगते|मागितले|विचारले|घेतले|घेत नाही|शुल्क");

    private record Hit(String snippet, String context, boolean negated) {}

    private static Hit findFirst(String text, String[] patterns) {
        for (String p : patterns) {
            Pattern re;
            try { re = Pattern.compile(p, Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE); }
            catch (Exception e) { continue; }
            Matcher m = re.matcher(text);
            if (m.find()) {
                int idx = m.start();
                int start = Math.max(0, idx - 60);
                String context = text.substring(Math.max(0, idx - 90), Math.min(text.length(), idx + m.group().length() + 70));
                String snippet = text.substring(start, Math.min(text.length(), idx + Math.min(m.group().length() + 60, 220)));
                boolean negated = hasNegationAround(text, idx, m.group().length()) || isNegatedDisclaimer(context);
                return new Hit(snippet, context, negated);
            }
        }
        return null;
    }

    public static boolean hasNegationAround(String text, int idx, int len) {
        String t = text == null ? "" : text;
        String before = t.substring(Math.max(0, idx - 90), Math.min(idx, t.length()));
        String after = t.substring(Math.min(t.length(), idx + len), Math.min(t.length(), idx + len + 70));
        String ctx = before + " " + after;
        return NEG_WORD.matcher(ctx).find() && ASK_WORD.matcher(ctx).find();
    }

    public static boolean isNegatedDisclaimer(String before) {
        String ctx = String.valueOf(before);
        return NEG_WORD.matcher(ctx).find() && ASK_WORD.matcher(ctx).find();
    }

    public static Map<String, Object> analyse(String text) {
        String t = text == null ? "" : text;
        List<Object> findings = new ArrayList<>();
        Map<String, Object> signals = new LinkedHashMap<>();
        double raw = 0;
        for (Rule rule : RULES) {
            Hit hit = t.isEmpty() ? null : findFirst(t, rule.patterns());
            signals.put(rule.id(), hit != null && !hit.negated());
            if (hit != null && hit.negated()) {
                findings.add(finding("ling-" + rule.id(), "linguistic", "info",
                    rule.title() + " — mentioned in a safety disclaimer, not requested", hit.snippet(), 0));
            } else if (hit != null) {
                boolean inperson = (rule.id().equals("cred-aadhaar") || rule.id().equals("cred-pan") || rule.id().equals("cred-bank"))
                    && INPERSON_CUE.matcher(hit.snippet() + " " + hit.context()).find();
                boolean offDisclaimer = rule.id().equals("offchannel") && OFFCHANNEL_DISCLAIMER.matcher(hit.context()).find();
                int winStart = 0;
                try {
                    String key = hit.snippet().length() >= 24 ? hit.snippet().substring(0, 24) : hit.snippet();
                    int at = t.indexOf(key);
                    winStart = Math.max(0, at - 100);
                } catch (Exception e) { winStart = 0; }
                String feeWindow = rule.id().equals("fee-job") ? t.substring(winStart, Math.min(t.length(), winStart + 320)) : "";
                boolean feeDisclaimer = false;
                if (rule.id().equals("fee-job")) {
                    boolean noFee = Pattern.compile("\\bno\\s+(\\w{1,12}\\s)?(fees?|charges?|advance|payment|money)\\b|without\\s+(any\\s+)?(fees?|charge|payment|advance)", Pattern.CASE_INSENSITIVE).matcher(feeWindow).find();
                    boolean rails = Pattern.compile("\\bpay\\b|upi|qr|₹|\\brs\\.?\\b|\\binr\\b|refundable|bhejo|bhej|भरो|भरा", Pattern.CASE_INSENSITIVE).matcher(feeWindow).find();
                    feeDisclaimer = noFee && !rails;
                }
                if (offDisclaimer || feeDisclaimer) {
                    findings.add(finding("ling-" + rule.id(), "linguistic", "info",
                        rule.id().equals("fee-job") ? "Fee language appears in a no-fee / no-charge statement — not a demand"
                            : "WhatsApp/Telegram mentioned in a cautionary context — not a push off-channel",
                        hit.snippet(), 0));
                } else if (inperson) {
                    raw += 3;
                    findings.add(finding("ling-" + rule.id(), "linguistic", "medium",
                        rule.title() + " — but an in-person verification channel is mentioned (lower risk; still verify identity first)",
                        hit.snippet(), 3));
                } else {
                    raw += rule.weight();
                    findings.add(finding("ling-" + rule.id(), "linguistic", rule.severity(), rule.title(), hit.snippet(), rule.weight()));
                }
            }
        }
        double score = t.isEmpty() ? 0 : Math.round(MAX * (1 - Math.exp(-raw / 18)) * 10) / 10.0;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("score", score); out.put("max", MAX); out.put("findings", findings);
        out.put("signals", signals); out.put("rawWeight", raw);
        return out;
    }

    public static Map<String, Object> finding(String id, String category, String severity, String title, String evidence, double points) {
        Map<String, Object> f = new LinkedHashMap<>();
        f.put("id", id); f.put("category", category); f.put("severity", severity);
        f.put("title", title); f.put("evidence", Redact.excerpt(evidence)); f.put("points", points);
        return f;
    }
}
