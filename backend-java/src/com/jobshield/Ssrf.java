package com.jobshield;

import java.net.InetAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** SSRF + DNS-rebinding protections — port of backend/src/utils/ssrf.js */
public final class Ssrf {
    private Ssrf() {}

    private static final Set<String> METADATA_IPS = Set.of("169.254.169.254", "fd00:ec2::254");

    public static boolean isBlockedIp(String ip) {
        if (ip == null || ip.isEmpty()) return true;
        String v = ip.replaceAll("^\\[|\\]$", "");
        boolean v6 = v.contains(":");
        if (!v6) {
            String[] o = v.split("\\.", -1);
            if (o.length != 4) return true;
            int[] n = new int[4];
            try { for (int i = 0; i < 4; i++) { n[i] = Integer.parseInt(o[i]); if (n[i] < 0 || n[i] > 255) return true; } }
            catch (NumberFormatException e) { return true; }
            if (METADATA_IPS.contains(v)) return true;
            int a = n[0], b = n[1];
            if (a == 10) return true;
            if (a == 172 && b >= 16 && b <= 31) return true;
            if (a == 192 && b == 168) return true;
            if (a == 127) return true;
            if (a == 169 && b == 254) return true;
            if (a == 0) return true;
            if (a >= 224) return true;
            if (a == 100 && b >= 64 && b <= 127) return true;
            if (a == 192 && (b == 0 || b == 2)) return true;
            if (a == 198 && (b == 18 || b == 19)) return true;
            if (a == 203 && b == 0 && n[2] == 113) return true;
            return false;
        }
        String low = v.toLowerCase();
        if (low.equals("::1") || low.equals("::")) return true;
        if (low.startsWith("fc") || low.startsWith("fd")) return true;
        if (low.startsWith("fe80")) return true;
        if (low.startsWith("ff")) return true;
        return false;
    }

    public record UrlPolicy(boolean ok, String reason, URI url) {}

    public static UrlPolicy validateUrlAgainstPolicy(String raw) {
        URI u;
        try { u = new URI(String.valueOf(raw).trim()); }
        catch (Exception e) { return new UrlPolicy(false, "URL is not parseable.", null); }
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase();
        if (!scheme.equals("http") && !scheme.equals("https"))
            return new UrlPolicy(false, "Blocked protocol \"" + scheme + ":\". Only http/https are inspected.", null);
        String host = u.getHost();
        if (host == null || host.isEmpty()) return new UrlPolicy(false, "URL has no hostname.", null);
        host = host.toLowerCase();
        if (host.equals("localhost") || host.endsWith(".localhost"))
            return new UrlPolicy(false, "Localhost targets are blocked.", null);
        if (host.endsWith(".internal") || host.endsWith(".local") || host.endsWith(".invalid"))
            return new UrlPolicy(false, "Internal hostnames are blocked.", null);
        if (u.getUserInfo() != null)
            return new UrlPolicy(false, "URLs with embedded credentials are blocked.", null);
        if (isIpLiteral(host) && isBlockedIp(host))
            return new UrlPolicy(false, "IP literal " + host + " is in a blocked range.", null);
        if (host.equals("169.254.169.254") || host.equals("metadata.google.internal"))
            return new UrlPolicy(false, "Cloud metadata endpoints are blocked.", null);
        return new UrlPolicy(true, "", u);
    }

    private static boolean isIpLiteral(String host) {
        String h = host.replaceAll("^\\[|\\]$", "");
        if (h.matches("\\d{1,3}(\\.\\d{1,3}){3}")) return true;
        return h.contains(":");
    }

    public static Map<String, Object> checkDns(String host) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (isIpLiteral(host)) {
            if (isBlockedIp(host)) {
                m.put("ok", false); m.put("ips", List.of(host));
                m.put("reason", "IP " + host + " is blocked.");
            } else {
                m.put("ok", true); m.put("ips", List.of(host));
            }
            return m;
        }
        try {
            InetAddress[] addrs = InetAddress.getAllByName(host);
            List<Object> ips = new ArrayList<>();
            List<String> blocked = new ArrayList<>();
            for (InetAddress a : addrs) {
                String ip = a.getHostAddress();
                ips.add(ip);
                if (isBlockedIp(ip)) blocked.add(ip);
            }
            if (!blocked.isEmpty()) {
                m.put("ok", false); m.put("ips", ips);
                m.put("reason", "Hostname resolves to blocked IP(s): " + String.join(", ", blocked) + ".");
            } else {
                m.put("ok", true); m.put("ips", ips);
            }
        } catch (Exception e) {
            m.put("ok", false); m.put("ips", List.of());
            m.put("reason", "DNS resolution failed for " + host + ".");
        }
        return m;
    }
}
