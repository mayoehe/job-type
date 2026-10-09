package com.jobshield;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Employer verification — port of backend/src/verify.js */
public final class Verify {
    private Verify() {}

    private static Map<String, Object> DB;
    private static String SOURCE = "JobShield curated employer directory v1.0.0 (offline heuristic — absence means unknown, not illegitimate)";
    private static final Pattern FREE_MAIL = Pattern.compile("gmail|yahoo|rediffmail|outlook|hotmail|protonmail|zoho|gmx", Pattern.CASE_INSENSITIVE);

    public static void loadDb(Path... candidates) {
        for (Path p : candidates) {
            try {
                if (p != null && Files.exists(p)) {
                    Object v = Json.parse(Files.readString(p));
                    if (v instanceof Map) {
                        @SuppressWarnings("unchecked") Map<String, Object> db = (Map<String, Object>) v;
                        DB = db;
                        Object ver = db.get("version");
                        SOURCE = "JobShield curated employer directory v" + (ver == null ? "1.0.0" : ver) + " (offline heuristic — absence means unknown, not illegitimate)";
                        return;
                    }
                }
            } catch (Exception ignored) {}
        }
        // fallback: minimal built-in directory
        try {
            Object v = Json.parse("{\"version\":\"1.0.0\",\"employers\":[{\"names\":[\"infosys\"],\"officialDomain\":\"infosys.com\",\"careersUrl\":\"https://www.infosys.com/careers/\",\"type\":\"company\"}],\"platforms\":[\"linkedin.com\",\"naukri.com\",\"indeed.com\"]}");
            @SuppressWarnings("unchecked") Map<String, Object> db = (Map<String, Object>) v;
            DB = db;
        } catch (Exception e) { DB = Map.of("version", "1.0.0", "employers", List.of(), "platforms", List.of()); }
    }

    private record NameEntry(String name, Map<String, Object> entry) {}

    @SuppressWarnings("unchecked")
    private static List<NameEntry> sortedNames() {
        List<NameEntry> out = new ArrayList<>();
        if (DB == null) return out;
        for (Object o : (List<Object>) DB.getOrDefault("employers", List.of())) {
            Map<String, Object> e = (Map<String, Object>) o;
            for (Object n : (List<Object>) e.getOrDefault("names", List.of()))
                out.add(new NameEntry(String.valueOf(n).toLowerCase(Locale.ROOT), e));
        }
        out.sort((a, b) -> Integer.compare(b.name().length(), a.name().length()));
        return out;
    }

    public static NameEntry findEmployerEntry(String text) {
        String t = String.valueOf(text == null ? "" : text).toLowerCase(Locale.ROOT);
        for (NameEntry ne : sortedNames()) {
            if (ne.name().length() >= 3 && t.contains(ne.name())) return ne;
        }
        return null;
    }

    public record Claim(String employer, String position, String ref, List<Map<String, String>> emails) {}

    public static Claim extractClaim(String text) {
        String t = String.valueOf(text == null ? "" : text);
        NameEntry dirHit = findEmployerEntry(t);
        String employer = dirHit != null ? dirHit.name() : null;
        if (employer == null) {
            // find first matching pattern
            String found = null;
            Matcher m1 = Pattern.compile("([A-Z][A-Za-z&., ]{2,50}?)\\s+(is hiring|hiring for|is looking for|invites applications)").matcher(t);
            Matcher m2 = Pattern.compile("(?:greetings|hello|hi)\\s+from\\s+([A-Z][A-Za-z&., ]{2,50})", Pattern.CASE_INSENSITIVE).matcher(t);
            Matcher m3 = Pattern.compile("careers?\\s+(?:at|with)\\s+([A-Z][A-Za-z&., ]{2,50})", Pattern.CASE_INSENSITIVE).matcher(t);
            if (m1.find()) found = m1.group(1).trim();
            else if (m2.find()) found = m2.group(1).trim();
            else if (m3.find()) found = m3.group(1).trim();
            if (found != null) employer = found;
        }
        String position = null;
        Matcher p1 = Pattern.compile("hiring\\s+(?:a|an)\\s+([A-Z][\\w /&.,\\-]{2,60})").matcher(t);
        Matcher p2 = Pattern.compile("(?:role|position|opening(?:s)?\\s+for)\\s*[:\\-]\\s*([^\\n.]{3,80})", Pattern.CASE_INSENSITIVE).matcher(t);
        Matcher p3 = Pattern.compile("opening[s]?\\s+for\\s+([^\\n.]{3,80})", Pattern.CASE_INSENSITIVE).matcher(t);
        if (p1.find()) position = cleanPos(p1.group(1));
        else if (p2.find()) position = cleanPos(p2.group(1));
        else if (p3.find()) position = cleanPos(p3.group(1));
        Matcher rm = Pattern.compile("(?:advt|advertisement|notification|circular|ref(?:erence)?)\\s*(?:no|number|#)?\\s*[:\\-]?\\s*([A-Z0-9/\\-]{3,30})", Pattern.CASE_INSENSITIVE).matcher(t);
        String ref = rm.find() ? rm.group(1) : null;
        Matcher em = Pattern.compile("[\\w.+-]+@([\\w.-]+\\.[a-z]{2,})", Pattern.CASE_INSENSITIVE).matcher(t);
        List<Map<String, String>> emails = new ArrayList<>();
        while (em.find()) {
            Map<String, String> e = new LinkedHashMap<>();
            e.put("address", em.group(0).toLowerCase(Locale.ROOT));
            e.put("domain", em.group(1).toLowerCase(Locale.ROOT));
            emails.add(e);
        }
        return new Claim(employer, position, ref, emails);
    }

    private static String cleanPos(String s) {
        return s.trim().replaceAll("\\s+", " ").substring(0, Math.min(80, s.trim().length()));
    }

    private static String registrableOfUrl(String url) {
        try { return Psl.registrableOf(new java.net.URI(String.valueOf(url)).getHost()); }
        catch (Exception e) { return null; }
    }

    public static List<String> vacancyKeywords(Claim claim) {
        Set<String> stop = Set.of("with", "from", "role", "post", "hiring", "senior", "junior");
        List<String> words = new ArrayList<>();
        if (claim.ref() != null) words.add(claim.ref().toLowerCase(Locale.ROOT));
        if (claim.position() != null) {
            for (String w : claim.position().toLowerCase(Locale.ROOT).split("[^a-z0-9+]+")) {
                if (w.length() >= 4 && !stop.contains(w) && !words.contains(w)) words.add(w);
                if (words.size() >= 6) break;
            }
        }
        return words.subList(0, Math.min(6, words.size()));
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyEmployer(String text, String url, String finalUrl, Map<String, Object> inspection, boolean fetchCareers) {
        if (text == null) text = "";
        if (url == null) url = "";
        if (finalUrl == null) finalUrl = "";
        List<Map<String, Object>> checks = new ArrayList<>();
        AddCheck push = (id, label, status, evidence, source) -> {
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("id", id); c.put("label", label); c.put("status", status);
            c.put("evidence", Redact.excerpt(String.valueOf(evidence == null ? "" : evidence).substring(0, Math.min(220, String.valueOf(evidence == null ? "" : evidence).length()))));
            c.put("source", source);
            checks.add(c);
        };

        Claim claim = extractClaim(text);
        push.add("claimed-employer", "Claimed employer identified",
            claim.employer() != null ? "verified" : "could-not-verify",
            claim.employer() != null
                ? "Claimed employer mention: \"" + claim.employer() + "\"" + (claim.position() != null ? "; advertised position: \"" + claim.position() + "\"" : "; no clear position title found")
                : "No identifiable employer name in the listing text.",
            "Listing text (heuristic extraction)");
        if (claim.position() != null)
            push.add("claimed-position", "Advertised position identified", "verified",
                "Position: \"" + claim.position() + "\"" + (claim.ref() != null ? " (ref " + claim.ref() + ")" : ""), "Listing text (heuristic extraction)");
        else push.add("claimed-position", "Advertised position identified", "could-not-verify",
            "No clear position title or reference number found in the listing.", "Listing text (heuristic extraction)");

        NameEntry dirHit = claim.employer() != null ? findEmployerEntry(claim.employer() + " " + text) : null;
        String officialDomain = dirHit != null && dirHit.entry().get("officialDomain") != null ? String.valueOf(dirHit.entry().get("officialDomain")) : null;
        if (officialDomain != null)
            push.add("official-website", "Employer's official website", "verified", "Official domain " + officialDomain + " (" + dirHit.entry().get("type") + ")", SOURCE);
        else push.add("official-website", "Employer's official website", "could-not-verify",
            claim.employer() != null ? "\"" + claim.employer() + "\" is not in the curated directory, so no independent official domain can be stated. Locate it yourself (search the company name; do not trust links in the message)."
                : "No employer identified, so no official website can be resolved.", SOURCE);

        String listingReg = registrableOfUrl(finalUrl.isEmpty() ? url : finalUrl);
        // strip null
        if (listingReg != null && listingReg.equals("null")) listingReg = null;
        boolean isPlatform = false;
        if (listingReg != null && DB != null) {
            for (Object p : (List<Object>) DB.getOrDefault("platforms", List.of())) {
                String ps = String.valueOf(p);
                if (listingReg.equals(ps) || listingReg.endsWith("." + ps)) { isPlatform = true; break; }
            }
        }
        if (listingReg == null) push.add("domain-comparison", "Portal domain vs official domain", "could-not-verify", "No application URL was provided, so no domain comparison is possible.", "Scan input");
        else if (officialDomain == null) push.add("domain-comparison", "Portal domain vs official domain", "could-not-verify", "Listing domain is " + listingReg + ", but no independent official domain is established for comparison.", "Scan input + " + SOURCE);
        else if (listingReg.equals(officialDomain) || listingReg.endsWith("." + officialDomain)) push.add("domain-comparison", "Portal domain vs official domain", "verified", "Listing domain " + listingReg + " matches the official domain " + officialDomain + ".", "Scan input + " + SOURCE);
        else if (isPlatform) push.add("domain-comparison", "Portal domain vs official domain", "could-not-verify", "Listing is on third-party platform " + listingReg + " while the employer domain is " + officialDomain + " — expected for platform postings; verify the recruiter profile and the vacancy on the official site.", "Scan input + " + SOURCE);
        else push.add("domain-comparison", "Portal domain vs official domain", "mismatch", "Listing domain " + listingReg + " does NOT match the official domain " + officialDomain + ". Type the official address yourself to compare.", "Scan input + " + SOURCE);

        if (claim.emails().isEmpty()) push.add("recruiter-email", "Recruiter email vs official domain", "could-not-verify", "No recruiter email address found in the listing.", "Listing text");
        else {
            List<String> lines = new ArrayList<>();
            String verdict = "could-not-verify";
            for (Map<String, String> e : claim.emails().subList(0, Math.min(4, claim.emails().size()))) {
                String addr = e.get("address"), dom = e.get("domain");
                if (officialDomain != null && (dom.equals(officialDomain) || dom.endsWith("." + officialDomain))) { lines.add(addr + " — matches official domain"); verdict = "verified"; }
                else if (FREE_MAIL.matcher(dom).find()) { lines.add(addr + " — free-mail provider" + (officialDomain != null ? ", not " + officialDomain : "")); if (!verdict.equals("verified")) verdict = officialDomain != null ? "mismatch" : "could-not-verify"; }
                else if (officialDomain != null) { lines.add(dom + " — does not match " + officialDomain); if (!verdict.equals("verified")) verdict = "mismatch"; }
                else lines.add(addr + " — no official domain to compare against");
            }
            push.add("recruiter-email", "Recruiter email vs official domain", verdict, String.join("; ", lines), "Listing text" + (officialDomain != null ? " + " + SOURCE : ""));
        }

        List<String> keywords = vacancyKeywords(claim);
        String careersUrl = null;
        boolean candidatePath = false;
        if (dirHit != null && dirHit.entry().get("careersUrl") != null) careersUrl = String.valueOf(dirHit.entry().get("careersUrl"));
        else if (officialDomain != null) { careersUrl = "https://www." + officialDomain + "/careers"; candidatePath = true; }
        if (officialDomain == null) push.add("vacancy-corroboration", "Vacancy on official careers page", "could-not-verify", "No official website established, so corroboration is not possible. This is uncertainty, not proof of fraud.", SOURCE);
        else if (keywords.isEmpty()) push.add("vacancy-corroboration", "Vacancy on official careers page", "could-not-verify", "Official site: " + officialDomain + (careersUrl != null ? " (careers: " + careersUrl + (candidatePath ? " — candidate path, unverified" : "") + ")" : "") + ". No position title/reference found to search for — check manually.", SOURCE);
        else if (!fetchCareers) push.add("vacancy-corroboration", "Vacancy on official careers page", "could-not-verify", "Official careers page: " + careersUrl + (candidatePath ? " (candidate path, unverified)" : "") + ". Automatic check skipped — open it yourself (type the address) and search for \"" + String.join(" / ", keywords.subList(0, Math.min(3, keywords.size()))) + "\".", SOURCE);
        else {
            try {
                Inspect.Inspection res = Inspect.inspectUrl(careersUrl);
                String hay = res.pageText().toLowerCase(Locale.ROOT);
                List<String> hits = keywords.stream().filter(k -> !hay.isEmpty() && hay.contains(k.toLowerCase(Locale.ROOT))).toList();
                String at = String.valueOf(res.timestamps().getOrDefault("at", "check time"));
                if (hits.size() >= Math.min(2, keywords.size()) && !hits.isEmpty())
                    push.add("vacancy-corroboration", "Vacancy on official careers page", "verified", "Found " + hits.size() + "/" + keywords.size() + " vacancy keyword(s) (" + String.join(", ", hits.subList(0, Math.min(3, hits.size()))) + ") on " + careersUrl + ".", "Live fetch of official careers page at " + at + " (SSRF-guarded static fetch)");
                else if (keywords.size() == 1 && hits.size() == 1)
                    push.add("vacancy-corroboration", "Vacancy on official careers page", "verified", "Found vacancy reference \"" + hits.get(0) + "\" on " + careersUrl + ".", "Live fetch of official careers page at " + at + " (SSRF-guarded static fetch)");
                else push.add("vacancy-corroboration", "Vacancy on official careers page", "could-not-verify", "Checked " + careersUrl + " but vacancy keywords (" + String.join(", ", keywords.subList(0, Math.min(3, keywords.size()))) + ") were not found there (" + (((Map<String, Object>) res.intel()).get("inspectNote") == null ? "page fetched, no match" : ((Map<String, Object>) res.intel()).get("inspectNote")) + "). Listings are often absent from public pages — check with the employer directly.", "Live fetch of official careers page at " + at + " (SSRF-guarded static fetch)");
            } catch (Exception e) {
                String msg = e.getMessage() == null ? String.valueOf(e) : e.getMessage();
                push.add("vacancy-corroboration", "Vacancy on official careers page", "could-not-verify", "Could not fetch " + careersUrl + " (" + msg.substring(0, Math.min(100, msg.length())) + "). Check manually — do not treat this as safe or fraudulent.", SOURCE);
            }
        }

        String overall;
        boolean mismatch = checks.stream().anyMatch(c -> "mismatch".equals(c.get("status")) && ("domain-comparison".equals(c.get("id")) || "recruiter-email".equals(c.get("id"))));
        boolean verified = checks.stream().anyMatch(c -> "verified".equals(c.get("status")) && ("domain-comparison".equals(c.get("id")) || "vacancy-corroboration".equals(c.get("id")) || "recruiter-email".equals(c.get("id"))));
        overall = mismatch ? "mismatch" : (verified ? "verified" : "could-not-verify");

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("claimedEmployer", claim.employer()); out.put("claimedPosition", claim.position());
        out.put("reference", claim.ref()); out.put("officialDomain", officialDomain);
        out.put("careersUrl", careersUrl); out.put("isPlatform", isPlatform);
        out.put("listingDomain", listingReg); out.put("overall", overall);
        out.put("checks", new ArrayList<>(checks)); out.put("source", SOURCE);
        return out;
    }

    private interface AddCheck { void add(String id, String label, String status, String evidence, String source); }
}
