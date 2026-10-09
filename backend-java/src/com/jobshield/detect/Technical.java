package com.jobshield.detect;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** D. Technical security signals — max 10. Port of detectors/technical.js */
public final class Technical {
    private Technical() {}
    public static final double MAX = 10;

    public static Map<String, Object> analyse(Map<String, Object> intel) {
        if (intel == null) intel = Map.of();
        List<Object> findings = new ArrayList<>();
        Map<String, Object> signals = new LinkedHashMap<>();
        double[] raw = {0};
        AddFn add = (id, severity, title, evidence, weight) -> {
            raw[0] += weight;
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("id", "tech-" + id); f.put("category", "technical"); f.put("severity", severity);
            f.put("title", title); f.put("evidence", evidence); f.put("points", weight);
            findings.add(f);
            signals.put(id, true);
        };
        InfoFn info = (id, title, evidence) -> {
            Map<String, Object> f = new LinkedHashMap<>();
            f.put("id", "tech-" + id); f.put("category", "technical"); f.put("severity", "info");
            f.put("title", title); f.put("evidence", evidence); f.put("points", 0);
            findings.add(f);
            signals.put(id, false);
        };

        if (Boolean.FALSE.equals(intel.get("inspected"))) {
            info.info("not-inspected", "Page could not be inspected — treated as UNKNOWN, not safe",
                str(intel.get("inspectNote"), "inspection unavailable"));
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("score", 0.0); out.put("max", MAX); out.put("findings", findings);
            out.put("signals", signals); out.put("rawWeight", 0.0);
            return out;
        }

        boolean tlsError = intel.get("tlsError") != null && !String.valueOf(intel.get("tlsError")).isEmpty();
        boolean certExpired = Boolean.TRUE.equals(intel.get("certExpired"));
        boolean hostMismatch = Boolean.TRUE.equals(intel.get("hostnameMismatch"));
        if (tlsError || certExpired || hostMismatch) {
            add.add("tls-problem", "medium", "TLS/certificate problem" + (certExpired ? " (expired)" : "") + (hostMismatch ? " (hostname mismatch)" : ""),
                str(intel.get("tlsError"), "certificate invalid"), 4);
        } else if (Boolean.TRUE.equals(intel.get("https")) && Boolean.TRUE.equals(intel.get("certValid"))) {
            info.info("https-valid", "Valid HTTPS observed — encrypts the connection but does NOT prove the recruiter is legitimate", "https + valid cert");
        } else if (Boolean.FALSE.equals(intel.get("https"))) {
            add.add("no-https", "medium", "Site does not use HTTPS for its application page", "http only", 4);
        } else signals.put("tls-problem", false);

        if (Boolean.FALSE.equals(intel.get("dnsOk")))
            add.add("dns-anomaly", "low", "DNS resolution anomaly during inspection", str(intel.get("inspectNote"), "dns failed"), 2);
        else signals.put("dns-anomaly", false);

        Object red = intel.get("redirects");
        if (red instanceof Number n && n.intValue() >= 3)
            add.add("redirect-chain", "medium", "Long redirect chain (" + n.intValue() + " hops)", n.intValue() + " redirects", 3);
        else if (red instanceof Number n)
            info.info("redirects-ok", "Redirect chain length: " + n.intValue(), n.intValue() + " hop(s)");

        if (Boolean.TRUE.equals(intel.get("reputationListed")))
            add.add("reputation-listed", "high", "Domain/IP appears in threat-intel feed (" + str(intel.get("reputationSource"), "local feed") + ")", String.valueOf(intel.getOrDefault("reputationListed", "")), 6);
        else info.info("reputation-clean", "No threat-intel listing in checked local feeds — absence of listing is not proof of safety", "checked: local blocklist");

        if (intel.get("hostingSuspicious") != null && !String.valueOf(intel.get("hostingSuspicious")).isEmpty())
            add.add("hosting-suspicious", "low", "Hosting/IP anomaly noted (e.g. freshly seen host, parking ASN)", String.valueOf(intel.get("hostingSuspicious")), 2);

        Object age = intel.get("domainAgeDays");
        if (age instanceof Number n) {
            if (n.intValue() <= 90) add.add("new-domain", "low", "Recently created domain (~" + n.intValue() + " days old) — weak supporting signal", n.intValue() + " days", 2);
            else info.info("domain-aged", "Domain age ~" + n.intValue() + " days — age alone does not establish legitimacy", n.intValue() + " days");
        }

        double score = Math.round(Math.min(MAX, MAX * (1 - Math.exp(-raw[0] / 5))) * 10) / 10.0;
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("score", score); out.put("max", MAX); out.put("findings", findings);
        out.put("signals", signals); out.put("rawWeight", raw[0]);
        return out;
    }

    private interface AddFn { void add(String id, String severity, String title, String evidence, double weight); }
    private interface InfoFn { void info(String id, String title, String evidence); }

    private static String str(Object v, String def) { return v == null ? def : String.valueOf(v); }
}
