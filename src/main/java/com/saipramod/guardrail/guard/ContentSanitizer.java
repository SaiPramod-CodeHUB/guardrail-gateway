package com.saipramod.guardrail.guard;

import java.util.ArrayList;
import java.util.List;

/**
 * Treats retrieved content as data: sentences that look like instructions to the model are
 * quarantined (removed and reported), invisible characters are stripped, and what remains
 * is wrapped in explicit "untrusted data" delimiters ("spotlighting"), which real models use
 * as a cue not to follow embedded instructions.
 */
public class ContentSanitizer {

    public record Sanitized(String text, List<String> quarantined, double docScore) { }

    private final InjectionDetector detector;

    public ContentSanitizer(InjectionDetector detector) {
        this.detector = detector;
    }

    public Sanitized sanitize(String sourceId, String raw) {
        String noInvisible = raw.replaceAll("[\\u200B-\\u200F\\u2060-\\u2064\\uFEFF]", "")
                .replaceAll("[\\uDB40][\\uDC00-\\uDC7F]", "");
        List<String> kept = new ArrayList<>();
        List<String> quarantined = new ArrayList<>();
        for (String sentence : noInvisible.split("(?<=[.!?])\\s+|\\n+")) {
            if (sentence.isBlank()) {
                continue;
            }
            if (detector.scan(sentence).flagged()) {
                quarantined.add(sentence.strip());
            } else {
                kept.add(sentence.strip());
            }
        }
        double docScore = detector.scan(noInvisible).score();
        String body = String.join(" ", kept);
        String wrapped = "<untrusted_data source=\"" + sourceId + "\">\n" + body + "\n</untrusted_data>";
        return new Sanitized(wrapped, quarantined, docScore);
    }
}
