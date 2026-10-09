package com.jobshield;

import java.util.regex.Pattern;

/** Privacy helpers — port of backend/src/utils/redact.js */
public final class Redact {
    private Redact() {}

    private static final Pattern AADHAAR = Pattern.compile("\\b[2-9]\\d{3}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b");
    private static final Pattern PAN = Pattern.compile("\\b[A-Z]{5}\\d{4}[A-Z]\\b", Pattern.CASE_INSENSITIVE);
    private static final Pattern ACCT = Pattern.compile("\\b\\d{9,18}\\b");
    private static final Pattern CARD = Pattern.compile("\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b");
    private static final Pattern OTP = Pattern.compile("(\\botp\\b[\\s:.-]*)\\d{4,8}", Pattern.CASE_INSENSITIVE);
    private static final Pattern UPI = Pattern.compile("[\\w.\\-]{2,}@[a-zA-Z]{2,}");
    private static final Pattern PHONE = Pattern.compile("(\\+?91[\\s-]?)?[6-9]\\d{9}\\b");

    public static String redactText(String text) {
        if (text == null || text.isEmpty()) return "";
        String out = text;
        out = AADHAAR.matcher(out).replaceAll("XXXX-XXXX-XXXX");
        out = PAN.matcher(out).replaceAll("XXXXX0000X");
        out = ACCT.matcher(out).replaceAll("[REDACTED-ACCT]");
        out = CARD.matcher(out).replaceAll("XXXX-XXXX-XXXX-XXXX");
        out = OTP.matcher(out).replaceAll("$1••••••");
        out = UPI.matcher(out).replaceAll("[REDACTED-UPI]");
        out = PHONE.matcher(out).replaceAll("[REDACTED-PHONE]");
        return out;
    }

    public static String excerpt(String text, int maxLen) {
        String r = redactText(text);
        if (r.length() <= maxLen) return r;
        return r.substring(0, maxLen).stripTrailing() + "…";
    }

    public static String excerpt(String text) { return excerpt(text, 160); }
}
