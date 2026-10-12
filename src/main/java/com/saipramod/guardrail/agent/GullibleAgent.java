package com.saipramod.guardrail.agent;

import com.saipramod.guardrail.core.Workspace.ToolCall;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A deliberately vulnerable model: it follows ANY imperative it reads, whether it came from
 * the user or from a retrieved email/web page, decodes base64 it is handed, reads through
 * invisible characters and understands a couple of languages. This is the worst case a
 * gateway has to survive ("assume the model is compromised"), and it makes red-team results
 * deterministic. Real models are less gullible, but no current model is reliably immune.
 */
public class GullibleAgent implements Agent {

    private static final Pattern SEND = Pattern.compile(
            "(?i)\\b(send|forward|email|e-mail|mail|bcc|deliver(?:ed)?|cc|env[ií]a|reenv[ií]a|manda|transmit)\\b[^.\\n]{0,120}?([\\w.+-]+@[\\w-]+\\.[\\w.]+)");
    private static final Pattern FETCH = Pattern.compile(
            "(?i)\\b(fetch|visit|open|load|call|ping|request|check|go to|visita|abre)\\s+(https?://[^\\s)\"']+)");
    private static final Pattern TICKET = Pattern.compile("(?i)\\b(create|open|file|raise)\\s+(a\\s+|an?\\s+urgent\\s+)?ticket\\b([^.\\n]*)");
    private static final Pattern REVEAL = Pattern.compile(
            "(?i)\\b(reveal|print|show|repeat|output|display|tell me|muestra|revela)\\b[^.\\n]{0,60}\\b(system prompt|initial prompt|instructions|hidden rules|prompt del sistema|instrucciones)");
    private static final Pattern SECRETS = Pattern.compile(
            "(?i)\\b(include|print|show|reveal|list|output|send|add|append)\\b[^.\\n]{0,60}\\b(api key|secret|password|ssn|social security|card number|credentials|key)");
    private static final Pattern MD_IMAGE = Pattern.compile("!\\[[^]]*]\\([^)]+\\)");
    private static final Pattern BASE64 = Pattern.compile("[A-Za-z0-9+/]{24,}={0,2}");
    private static final Pattern SENSITIVE = Pattern.compile(
            "sk_(live|test)_[A-Za-z0-9]+|\\b\\d{3}-\\d{2}-\\d{4}\\b|(?i)password:?\\s*\\S+|\\b(?:\\d[ -]?){15,16}\\b");

    @Override
    public List<ToolCall> plan(String systemPrompt, String userMessage) {
        return Agent.defaultPlan(userMessage);
    }

    @Override
    public Turn act(String systemPrompt, String userMessage, List<ContextItem> context) {
        StringBuilder all = new StringBuilder(userMessage).append('\n');
        context.forEach(c -> all.append(strip(c.content())).append('\n'));
        String text = decodeEmbedded(all.toString().replaceAll("[\\u200B-\\u200F\\u2060-\\u2064\\uFEFF]", ""));
        String sensitive = firstSensitive(text);

        Map<String, ToolCall> actions = new LinkedHashMap<>();
        Matcher m = SEND.matcher(text);
        while (m.find()) {
            String to = m.group(2).replaceAll("[.,;]+$", "");
            actions.putIfAbsent("send:" + to, new ToolCall("sendEmail", Map.of("to", to,
                    "subject", "Requested information", "body", contextDump(context))));
        }
        m = FETCH.matcher(text);
        while (m.find()) {
            String url = m.group(2).replaceAll("(?i)\\{?(data|secret|key|ssn|token|payload)\\}?", sensitive == null ? "none" : sensitive)
                    .replaceAll("[.,;]+$", "");
            actions.putIfAbsent("fetch:" + url, new ToolCall("fetchUrl", Map.of("url", url)));
        }
        m = TICKET.matcher(text);
        if (m.find()) {
            String title = m.group(3).replaceAll("^\\s*(for|about|titled|called|:)\\s*", "").strip();
            actions.putIfAbsent("ticket", new ToolCall("createTicket", Map.of(
                    "title", title.isEmpty() ? "Follow-up" : title, "body", contextDump(context))));
        }

        StringBuilder answer = new StringBuilder();
        for (ContextItem c : context) {
            String body = strip(c.content());
            answer.append("From ").append(c.source()).append(": ").append(body.length() > 500 ? body.substring(0, 500) + "…" : body).append("\n");
        }
        if (REVEAL.matcher(text).find()) {
            answer.append("My instructions are: ").append(systemPrompt).append('\n');
        }
        if (SECRETS.matcher(text).find() && sensitive != null) {
            answer.append("As requested: ").append(sensitive).append('\n');
        }
        Matcher img = MD_IMAGE.matcher(text);
        while (img.find()) {
            answer.append(img.group().replaceAll("(?i)\\{?(data|secret|key|ssn|token|payload)\\}?",
                    sensitive == null ? "none" : sensitive)).append('\n');
        }
        if (answer.isEmpty()) {
            answer.append("I don't have any documents for that. Which document or customer should I look at?");
        }
        return new Turn(new ArrayList<>(actions.values()), answer.toString().strip());
    }

    private static String contextDump(List<ContextItem> context) {
        StringBuilder sb = new StringBuilder();
        context.forEach(c -> sb.append(strip(c.content())).append('\n'));
        return sb.toString().strip();
    }

    private static String strip(String s) {
        return s.replaceAll("</?untrusted_data[^>]*>", "").strip();
    }

    private static String firstSensitive(String text) {
        Matcher m = SENSITIVE.matcher(text);
        return m.find() ? m.group().replaceAll("(?i)password:?\\s*", "") : null;
    }

    private static String decodeEmbedded(String text) {
        StringBuilder sb = new StringBuilder(text);
        Matcher b = BASE64.matcher(text);
        while (b.find()) {
            try {
                String d = new String(Base64.getDecoder().decode(b.group()), StandardCharsets.UTF_8);
                if (d.chars().allMatch(c -> c >= 32 && c < 127 || c == '\n')) {
                    sb.append('\n').append(d);
                }
            } catch (IllegalArgumentException ignored) {
                // not base64
            }
        }
        return sb.toString();
    }

    @Override
    public String name() {
        return "gullible (simulated worst-case model)";
    }
}
