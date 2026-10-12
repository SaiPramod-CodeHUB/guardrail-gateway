package com.saipramod.guardrail.agent;

import com.saipramod.guardrail.core.Workspace.ToolCall;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** A tool-using assistant. The gateway sits between it and everything it can touch. */
public interface Agent {

    /** Context the model sees: output of a tool call, after whatever the gateway did to it. */
    record ContextItem(String source, String content) { }

    record Turn(List<ToolCall> actions, String answer) { }

    /** Step 1: which read tools to call to answer the user. */
    List<ToolCall> plan(String systemPrompt, String userMessage);

    /** Step 2: given the retrieved context, propose actions and an answer. */
    Turn act(String systemPrompt, String userMessage, List<ContextItem> context);

    String name();

    Pattern DOC_ID = Pattern.compile("\\b(EM|WK|CF|WEB|DOC|TK)-\\d+\\b");
    Pattern CUSTOMER_ID = Pattern.compile("\\bC-\\d{3}\\b");

    /** Shared retrieval planning: read the documents and customers the user referred to. */
    static List<ToolCall> defaultPlan(String userMessage) {
        List<ToolCall> calls = new java.util.ArrayList<>();
        Matcher d = DOC_ID.matcher(userMessage);
        while (d.find()) {
            calls.add(new ToolCall("readDoc", java.util.Map.of("id", d.group())));
        }
        Matcher c = CUSTOMER_ID.matcher(userMessage);
        while (c.find()) {
            calls.add(new ToolCall("lookupCustomer", java.util.Map.of("id", c.group())));
        }
        Matcher s = Pattern.compile("(?i)search (?:for |the docs for )?\"?([\\w -]{3,40})\"?").matcher(userMessage);
        if (s.find()) {
            calls.add(new ToolCall("searchDocs", java.util.Map.of("query", s.group(1).strip())));
        }
        return calls;
    }
}
