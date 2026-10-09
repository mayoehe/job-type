package com.jobshield;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** Minimal PSL-aware domain parsing — port of backend/src/utils/psl.js */
public final class Psl {
    private Psl() {}

    private static final Set<String> SUFFIXES = Set.of(
        "co.in", "org.in", "net.in", "gen.in", "firm.in", "ind.in", "ac.in", "edu.in",
        "res.in", "gov.in", "nic.in", "mil.in",
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "co.kr", "com.au", "net.au",
        "org.au", "co.nz", "com.br", "com.mx", "co.za",
        "com", "org", "net", "io", "ai", "dev", "app", "in", "uk", "us", "info",
        "biz", "co", "me", "tech", "jobs", "work", "site", "online", "store",
        "top", "xyz", "club", "live", "world", "link", "click", "gov", "edu");

    public static String normaliseHost(String host) {
        if (host == null) return "";
        String h = host.trim().toLowerCase();
        if (h.endsWith(".")) h = h.substring(0, h.length() - 1);
        return h;
    }

    public static boolean isIpHost(String host) {
        String h = normaliseHost(host).replaceAll("^\\[|\\]$", "");
        if (h.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return true;
        return h.contains(":");
    }

    public static Map<String, Object> parseDomain(String host) {
        String h = normaliseHost(host);
        Map<String, Object> m = new LinkedHashMap<>();
        if (h.isEmpty() || isIpHost(h)) {
            m.put("host", h); m.put("subdomain", ""); m.put("registrableDomain", h);
            m.put("suffix", ""); m.put("isIp", true);
            return m;
        }
        String[] parts = h.split("\\.");
        java.util.List<String> list = new java.util.ArrayList<>();
        for (String p : parts) if (!p.isEmpty()) list.add(p);
        parts = list.toArray(new String[0]);
        if (parts.length < 2) {
            m.put("host", h); m.put("subdomain", ""); m.put("registrableDomain", h);
            m.put("suffix", ""); m.put("isIp", false);
            return m;
        }
        for (int len = 3; len >= 1; len--) {
            if (parts.length < len) continue;
            StringBuilder cand = new StringBuilder();
            for (int i = parts.length - len; i < parts.length; i++) {
                if (cand.length() > 0) cand.append('.');
                cand.append(parts[i]);
            }
            if (SUFFIXES.contains(cand.toString())) {
                String suffix = cand.toString();
                int restLen = parts.length - len;
                String registrable = restLen > 0 ? parts[restLen - 1] + "." + suffix : suffix;
                StringBuilder sub = new StringBuilder();
                for (int i = 0; i < restLen - 1; i++) {
                    if (sub.length() > 0) sub.append('.');
                    sub.append(parts[i]);
                }
                m.put("host", h); m.put("subdomain", sub.toString());
                m.put("registrableDomain", registrable); m.put("suffix", suffix);
                m.put("isIp", false);
                return m;
            }
        }
        String suffix = parts[parts.length - 1];
        String registrable = parts[parts.length - 2] + "." + parts[parts.length - 1];
        StringBuilder sub = new StringBuilder();
        for (int i = 0; i < parts.length - 2; i++) {
            if (sub.length() > 0) sub.append('.');
            sub.append(parts[i]);
        }
        m.put("host", h); m.put("subdomain", sub.toString());
        m.put("registrableDomain", registrable); m.put("suffix", suffix);
        m.put("isIp", false);
        return m;
    }

    public static String registrableOf(String host) {
        Object r = parseDomain(host).get("registrableDomain");
        return r == null ? normaliseHost(host) : String.valueOf(r);
    }
}
