package com.saipramod.guardrail.guard;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Heuristic prompt-injection detector. Each rule targets one known technique and has a
 * weight; matches combine as 1 - prod(1 - w), so one strong signal or several weak ones
 * cross the threshold. Base64 blobs are decoded and re-scanned. It is fast (sub-ms) and
 * explainable, and it WILL miss novel phrasings: that is why the gateway does not rely on
 * it alone (see ToolPolicy).
 */
public class InjectionDetector {

    public static final double THRESHOLD = 0.6;

    /**
     * Where the text came from. A user asking to email someone is normal; a retrieved web
     * page asking the assistant to email someone is an attack, so exfiltration rules only
     * apply to untrusted CONTENT.
     */
    public enum Source { USER, CONTENT }

    private static final java.util.Set<String> CONTENT_ONLY = java.util.Set.of("exfil_instruction", "exfil_url");

    public record Rule(String id, double weight, Pattern pattern) { }

    public record Finding(String rule, double weight, String match) { }

    public record Result(double score, List<Finding> findings) {
        public boolean flagged() {
            return score >= THRESHOLD;
        }
    }

    private static final List<Rule> RULES = List.of(
            rule("override_instructions", 0.9,
                    "(ignore|disregard|forget|override|skip)\\s+(all\\s+|any\\s+|the\\s+|your\\s+)*(previous|prior|above|earlier|preceding|original|system)?\\s*(instructions|rules|guidelines|directions|context|prompts?)"),
            rule("reveal_system_prompt", 0.9,
                    "(reveal|print|show|repeat|output|display|leak|tell me)\\b.{0,40}\\b(system prompt|initial prompt|hidden (rules|instructions)|your instructions|developer message)"),
            rule("role_hijack", 0.7,
                    "(you are now|from now on you are|act as|pretend (to be|you are)|\\bDAN\\b|developer mode|jailbreak|unrestricted mode|no longer bound)"),
            rule("fake_authority", 0.7,
                    "(new|updated|important|urgent|priority)\\s+(system|admin|administrator|security|it)\\s+(instruction|message|update|notice|directive|override)"),
            rule("delimiter_spoof", 0.8,
                    "(</?\\s*(system|assistant|instructions?|im_start|im_end)\\s*>|\\bBEGIN (SYSTEM|INSTRUCTIONS)\\b|^\\s*#{2,}\\s*system\\b|\\[/?INST\\])"),
            rule("addresses_the_ai", 0.6,
                    "((dear|attention|note to|hey|hello)\\s+(ai|assistant|bot|llm|language model|copilot)|if you are an? (ai|assistant|language model)|to the (ai|assistant))"),
            rule("exfil_instruction", 0.6,
                    "(send|forward|email|e-mail|mail|post|upload|transmit|exfiltrate|bcc)\\b.{0,80}\\b[\\w.+-]+@[\\w-]+\\.[\\w.]+"),
            rule("exfil_url", 0.6,
                    "(fetch|visit|open|load|call|ping|request|go to)\\s+https?://\\S+[?&]\\w+=|https?://\\S+\\{?(data|secret|key|ssn|token|payload)\\}?"),
            rule("markdown_image_exfil", 0.7, "!\\[[^]]*]\\(https?://[^)]+[?&][^)]*\\)"),
            rule("secrecy", 0.7,
                    "(do not|don't|never)\\s+(tell|inform|mention|show|alert|notify)\\s+(the\\s+)?(user|customer|human|anyone)|without (telling|informing) (the )?(user|anyone)"),
            rule("credential_request", 0.5,
                    "(include|print|show|reveal|list|output|send)\\b.{0,40}\\b(api key|secret key|password|credentials|ssn|social security|card number)"),
            rule("invisible_chars", 0.5, "[\\u200B-\\u200F\\u2060-\\u2064\\uFEFF]|[\\uDB40][\\uDC00-\\uDC7F]"));

    private static final Pattern BASE64 = Pattern.compile("[A-Za-z0-9+/]{24,}={0,2}");

    public Result scan(String text) {
        return scan(text, Source.CONTENT);
    }

    public Result scan(String text, Source source) {
        if (text == null || text.isBlank()) {
            return new Result(0, List.of());
        }
        List<Finding> findings = new ArrayList<>();
        scanInto(text, findings, "", source);
        Matcher b = BASE64.matcher(text);
        while (b.find()) {
            String decoded = tryDecode(b.group());
            if (decoded != null) {
                findings.add(new Finding("base64_payload", 0.4, b.group().substring(0, 16) + "..."));
                scanInto(decoded, findings, "decoded:", source);
            }
        }
        double keep = 1;
        for (Finding f : findings) {
            keep *= 1 - f.weight();
        }
        return new Result(Math.round((1 - keep) * 1000) / 1000.0, findings);
    }

    private void scanInto(String text, List<Finding> out, String prefix, Source source) {
        for (Rule r : RULES) {
            if (source == Source.USER && CONTENT_ONLY.contains(r.id())) {
                continue;
            }
            Matcher m = r.pattern().matcher(text);
            if (m.find()) {
                String hit = m.group();
                out.add(new Finding(prefix + r.id(), r.weight(), hit.length() > 80 ? hit.substring(0, 80) : hit));
            }
        }
    }

    static String tryDecode(String s) {
        try {
            String d = new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8);
            long printable = d.chars().filter(c -> c >= 32 && c < 127).count();
            return d.length() >= 12 && printable >= d.length() * 0.9 ? d : null;
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private static Rule rule(String id, double w, String regex) {
        return new Rule(id, w, Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.MULTILINE));
    }
}
