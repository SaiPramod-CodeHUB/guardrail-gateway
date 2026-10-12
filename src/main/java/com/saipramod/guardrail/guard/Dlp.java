package com.saipramod.guardrail.guard;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Data-loss prevention on everything leaving the system: the final answer and the body of
 * any outbound email. Detects SSNs, card numbers (Luhn-checked), API keys and passwords,
 * the system-prompt canary, and markdown images/links to non-allowlisted hosts (a classic
 * zero-click exfiltration channel, since rendering the image sends the data in the URL).
 */
public class Dlp {

    public record Hit(String type, String value) { }

    public record Result(String redacted, List<Hit> hits) {
        public boolean clean() {
            return hits.isEmpty();
        }
    }

    private static final Pattern SSN = Pattern.compile("\\b(?!000|666|9\\d\\d)\\d{3}-\\d{2}-\\d{4}\\b");
    private static final Pattern CARD = Pattern.compile("\\b(?:\\d[ -]?){13,19}\\b");
    private static final Pattern SECRET = Pattern.compile(
            "\\b(sk_(live|test)_[A-Za-z0-9]{10,}|sk-[A-Za-z0-9-]{20,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|xox[bp]-[A-Za-z0-9-]{10,})\\b");
    private static final Pattern PASSWORD = Pattern.compile("(?i)(password|passwd|pwd)\\s*(is|:|=)\\s*(\\S+)");
    private static final Pattern MD_LINK = Pattern.compile("!?\\[[^]]*]\\((https?://([^/)\\s]+)[^)]*)\\)");
    private static final Pattern BARE_URL_WITH_QUERY = Pattern.compile("https?://([^/\\s)]+)/\\S*[?&]\\S+");

    private final String canary;
    private final Set<String> allowedHosts;

    public Dlp(String canary, Set<String> allowedHosts) {
        this.canary = canary;
        this.allowedHosts = allowedHosts;
    }

    public Result scan(String text) {
        if (text == null) {
            return new Result(null, List.of());
        }
        List<Hit> hits = new ArrayList<>();
        String out = text;
        if (canary != null && out.contains(canary)) {
            hits.add(new Hit("system_prompt_leak", canary));
            out = "[Response withheld: it contained confidential system instructions.]";
            return new Result(out, hits);
        }
        out = replace(out, SECRET, "secret", hits, m -> "[REDACTED:secret]");
        out = replace(out, PASSWORD, "password", hits, m -> m.group(1) + " " + m.group(2) + " [REDACTED:password]");
        out = replace(out, SSN, "ssn", hits, m -> "[REDACTED:ssn]");
        Matcher c = CARD.matcher(out);
        StringBuilder sb = new StringBuilder();
        while (c.find()) {
            String digits = c.group().replaceAll("[ -]", "");
            if (digits.length() >= 13 && digits.length() <= 19 && luhn(digits)) {
                hits.add(new Hit("card", "****" + digits.substring(digits.length() - 4)));
                c.appendReplacement(sb, "[REDACTED:card]");
            } else {
                c.appendReplacement(sb, Matcher.quoteReplacement(c.group()));
            }
        }
        c.appendTail(sb);
        out = sb.toString();
        out = replace(out, MD_LINK, "untrusted_link", hits,
                m -> isAllowed(m.group(2)) ? m.group() : "[link removed: untrusted host]");
        hits.removeIf(h -> h.type().equals("untrusted_link") && isAllowedLink(h.value()));
        out = replace(out, BARE_URL_WITH_QUERY, "untrusted_url", hits,
                m -> isAllowed(m.group(1)) ? m.group() : "[url removed: untrusted host]");
        hits.removeIf(h -> h.type().equals("untrusted_url") && isAllowedLink(h.value()));
        return new Result(out, hits);
    }

    private boolean isAllowedLink(String link) {
        Matcher m = Pattern.compile("https?://([^/)\\s]+)").matcher(link);
        return m.find() && isAllowed(m.group(1));
    }

    public boolean isAllowed(String host) {
        String h = host.toLowerCase();
        return allowedHosts.stream().anyMatch(a -> h.equals(a) || h.endsWith("." + a));
    }

    private interface Replacer {
        String apply(Matcher m);
    }

    private static String replace(String text, Pattern p, String type, List<Hit> hits, Replacer r) {
        Matcher m = p.matcher(text);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            hits.add(new Hit(type, m.group()));
            m.appendReplacement(sb, Matcher.quoteReplacement(r.apply(m)));
        }
        m.appendTail(sb);
        return sb.toString();
    }

    static boolean luhn(String digits) {
        int sum = 0;
        boolean dbl = false;
        for (int i = digits.length() - 1; i >= 0; i--) {
            int d = digits.charAt(i) - '0';
            if (dbl) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }
}
