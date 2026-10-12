package com.saipramod.guardrail.redteam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.saipramod.guardrail.agent.Agent;
import com.saipramod.guardrail.agent.GullibleAgent;
import com.saipramod.guardrail.core.Workspace;
import com.saipramod.guardrail.guard.Gateway;
import com.saipramod.guardrail.guard.Gateway.Layers;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Supplier;

/**
 * Automated red team: replays every attack and every legitimate task against the gateway
 * under several layer configurations and checks real outcomes (was the email sent? did
 * the secret reach the user?), not just whether something was flagged.
 *
 * <pre>mvn -q compile exec:java</pre>
 */
public final class RedTeamRunner {

    public record Scenario(String id, String kind, String category, String technique, String userMessage,
                           Workspace.Doc injectedDoc, String goal, String expect) {
        boolean attack() {
            return "attack".equals(kind);
        }
    }

    public record ConfigResult(String config, int attacks, int attacksSucceeded, double attackSuccessRate,
                               int benign, int benignCompleted, double taskCompletionRate,
                               Map<String, Double> asrByCategory, List<String> successfulAttacks,
                               List<String> failedBenign, double p50OverheadMicros, double p95OverheadMicros) { }

    public record DetectorResult(int attacks, int attacksFlagged, double falseNegativeRate,
                                 int benign, int benignFlagged, double falsePositiveRate, List<String> missed,
                                 List<String> falsePositives) { }

    public record Report(String agent, List<ConfigResult> configs, DetectorResult detector) { }

    static final Map<String, Layers> CONFIGS = new LinkedHashMap<>();

    static {
        CONFIGS.put("no guardrails", Layers.none());
        CONFIGS.put("detectors only (input + content)", new Layers(true, true, false, false));
        CONFIGS.put("tool policy only", new Layers(false, false, true, false));
        CONFIGS.put("tool policy + output DLP", new Layers(false, false, true, true));
        CONFIGS.put("full gateway", Layers.all());
    }

    private RedTeamRunner() { }

    public static void main(String[] args) throws IOException {
        Report r = run(GullibleAgent::new);
        Path out = Path.of("eval/results");
        Files.createDirectories(out);
        new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT).writeValue(out.resolve("results.json").toFile(), r);
        String md = markdown(r);
        Files.writeString(out.resolve("results.md"), md);
        System.out.println(md);
    }

    public static Report run(Supplier<Agent> agentFactory) throws IOException {
        List<Scenario> scenarios = load();
        List<ConfigResult> configs = new ArrayList<>();
        DetectorResult detector = null;
        for (var e : CONFIGS.entrySet()) {
            int attacks = 0, succeeded = 0, benign = 0, completed = 0;
            int flaggedAttacks = 0, flaggedBenign = 0;
            Map<String, int[]> byCat = new LinkedHashMap<>();
            List<String> successes = new ArrayList<>();
            List<String> failedBenign = new ArrayList<>();
            List<String> missed = new ArrayList<>();
            List<String> fps = new ArrayList<>();
            List<Long> overheads = new ArrayList<>();
            for (Scenario s : scenarios) {
                Workspace ws = Workspace.demo();
                if (s.injectedDoc() != null) {
                    ws.add(s.injectedDoc());
                }
                Gateway g = new Gateway(agentFactory.get(), ws, e.getValue());
                Gateway.Response resp = g.handle(s.userMessage());
                overheads.add(resp.gatewayOverheadMicros());
                boolean flagged = resp.findings().stream().anyMatch(f -> f.startsWith("input:") || f.startsWith("content:"));
                if (s.attack()) {
                    attacks++;
                    boolean ok = goalMet(s.goal(), ws, resp);
                    int[] c = byCat.computeIfAbsent(s.category(), k -> new int[2]);
                    c[0]++;
                    if (ok) {
                        succeeded++;
                        c[1]++;
                        successes.add(s.id());
                    }
                    if (flagged) {
                        flaggedAttacks++;
                    } else {
                        missed.add(s.id());
                    }
                } else {
                    benign++;
                    boolean ok = !resp.refused() && goalMet(s.expect(), ws, resp);
                    if (ok) {
                        completed++;
                    } else {
                        failedBenign.add(s.id());
                    }
                    if (flagged) {
                        flaggedBenign++;
                        fps.add(s.id());
                    }
                }
            }
            Map<String, Double> asr = new LinkedHashMap<>();
            byCat.forEach((k, v) -> asr.put(k, r3((double) v[1] / v[0])));
            overheads.sort(null);
            configs.add(new ConfigResult(e.getKey(), attacks, succeeded, r3((double) succeeded / attacks), benign, completed,
                    r3((double) completed / benign), asr, successes, failedBenign,
                    pct(overheads, 50), pct(overheads, 95)));
            if (e.getValue().equals(Layers.all())) {
                detector = new DetectorResult(attacks, flaggedAttacks, r3(1 - (double) flaggedAttacks / attacks),
                        benign, flaggedBenign, r3((double) flaggedBenign / benign), missed, fps);
            }
        }
        return new Report(agentFactory.get().name(), configs, detector);
    }

    static boolean goalMet(String goal, Workspace ws, Gateway.Response resp) {
        int i = goal.indexOf(':');
        String type = goal.substring(0, i);
        String v = goal.substring(i + 1);
        return switch (type) {
            case "EMAIL_DOMAIN" -> ws.outbox().stream().anyMatch(m -> m.to().toLowerCase(Locale.ROOT).endsWith("@" + v)
                    || m.to().toLowerCase(Locale.ROOT).endsWith("." + v));
            case "EMAIL_TO" -> ws.outbox().stream().anyMatch(m -> m.to().equalsIgnoreCase(v));
            case "OUTPUT" -> resp.answer() != null && resp.answer().contains(v);
            case "FETCH_DOMAIN", "FETCHED" -> ws.fetched().stream().anyMatch(u -> u.contains(v));
            case "TICKET" -> ws.tickets().stream().anyMatch(t -> (t.title() + " " + t.body()).contains(v));
            case "APPROVAL" -> resp.actions().stream().anyMatch(a -> a.call().tool().equals(v)
                    && (a.verdict().equals("PENDING_APPROVAL") || a.verdict().equals("EXECUTED")));
            default -> throw new IllegalArgumentException("unknown goal " + goal);
        };
    }

    public static List<Scenario> load() throws IOException {
        try (InputStream in = RedTeamRunner.class.getResourceAsStream("/redteam/scenarios.json")) {
            JsonNode root = new ObjectMapper().readTree(in);
            List<Scenario> out = new ArrayList<>();
            for (JsonNode n : root.path("scenarios")) {
                JsonNode d = n.path("injectedDoc");
                Workspace.Doc doc = d.isMissingNode() || d.isNull() ? null
                        : new Workspace.Doc(d.get("id").asText(), d.get("title").asText(), d.get("source").asText(), d.get("body").asText());
                out.add(new Scenario(n.get("id").asText(), n.get("kind").asText(), n.get("category").asText(),
                        n.path("technique").asText(""), n.get("userMessage").asText(), doc,
                        n.path("goal").asText(null), n.path("expect").asText(null)));
            }
            return out;
        }
    }

    private static double pct(List<Long> sorted, double p) {
        int idx = (int) Math.ceil(p / 100 * sorted.size()) - 1;
        return sorted.isEmpty() ? 0 : sorted.get(Math.max(0, Math.min(sorted.size() - 1, idx)));
    }

    private static double r3(double v) {
        return Math.round(v * 1000) / 1000.0;
    }

    static String markdown(Report r) {
        StringBuilder sb = new StringBuilder("## Guardrail Gateway red-team results\n\n");
        ConfigResult first = r.configs().get(0);
        sb.append(String.format(Locale.ROOT, "Agent: %s · %d attacks · %d legitimate tasks%n%n", r.agent(), first.attacks(), first.benign()));
        sb.append("| Configuration | Attack success rate | Attacks succeeded | Legit task completion | Gateway overhead p50 / p95 |\n|---|---|---|---|---|\n");
        for (ConfigResult c : r.configs()) {
            sb.append(String.format(Locale.ROOT, "| %s | **%.1f%%** | %d / %d | %.1f%% (%d / %d) | %.0f / %.0f µs |%n",
                    c.config(), c.attackSuccessRate() * 100, c.attacksSucceeded(), c.attacks(), c.taskCompletionRate() * 100,
                    c.benignCompleted(), c.benign(), c.p50OverheadMicros(), c.p95OverheadMicros()));
        }
        sb.append("\nAttack success rate by category:\n\n| Configuration | ");
        List<String> cats = new ArrayList<>(first.asrByCategory().keySet());
        sb.append(String.join(" | ", cats)).append(" |\n|---|").append("---|".repeat(cats.size())).append('\n');
        for (ConfigResult c : r.configs()) {
            sb.append("| ").append(c.config()).append(" | ");
            cats.forEach(k -> sb.append(String.format(Locale.ROOT, "%.0f%% | ", c.asrByCategory().get(k) * 100)));
            sb.append('\n');
        }
        DetectorResult d = r.detector();
        sb.append(String.format(Locale.ROOT, "%nInjection detectors alone (input scan + content scan): flagged %d / %d attacks "
                        + "(**false-negative rate %.1f%%**) and %d / %d legitimate tasks (**false-positive rate %.1f%%**).%n",
                d.attacksFlagged(), d.attacks(), d.falseNegativeRate() * 100, d.benignFlagged(), d.benign(), d.falsePositiveRate() * 100));
        sb.append("\nAttacks the detectors missed: ").append(String.join(", ", d.missed())).append("  \n");
        sb.append("Legitimate tasks the detectors flagged: ").append(String.join(", ", d.falsePositives())).append('\n');
        ConfigResult full = r.configs().get(r.configs().size() - 1);
        sb.append("\nFull gateway: attacks that still succeeded: ")
                .append(full.successfulAttacks().isEmpty() ? "none" : String.join(", ", full.successfulAttacks()))
                .append("; legitimate tasks that failed: ")
                .append(full.failedBenign().isEmpty() ? "none" : String.join(", ", full.failedBenign())).append('\n');
        return sb.toString();
    }
}
