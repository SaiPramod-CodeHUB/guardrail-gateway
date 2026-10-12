package com.saipramod.guardrail.guard;

import com.saipramod.guardrail.core.Workspace;
import com.saipramod.guardrail.core.Workspace.Privilege;
import com.saipramod.guardrail.core.Workspace.ToolCall;

import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The structural defence: it does not try to recognise attacks, it limits what any model
 * output can do.
 * <ul>
 *   <li><b>Intent binding</b>: side-effecting tools are only available if the USER asked for
 *       that kind of action in this request. Retrieved text cannot grant capabilities.</li>
 *   <li><b>Provenance / taint</b>: destinations (email recipient, URL, customer id) must
 *       appear in the user's own message. A value that only exists in a retrieved document is
 *       attacker-controlled.</li>
 *   <li><b>Privilege levels</b>: READ &lt; READ_SENSITIVE &lt; WRITE_INTERNAL &lt; EXTERNAL / NETWORK.</li>
 *   <li><b>Human approval</b> for high-risk but legitimate actions: external recipients,
 *       actions the user did not explicitly request, sensitive data leaving to internal staff.</li>
 *   <li><b>Egress DLP</b>: sensitive data never goes to an external address.</li>
 * </ul>
 */
public class ToolPolicy {

    public enum Intent { SUMMARIZE, LOOKUP_CUSTOMER, CREATE_TICKET, SEND_EMAIL, FETCH, SEARCH }

    public enum Verdict { ALLOW, BLOCK, NEEDS_APPROVAL }

    public record Decision(Verdict verdict, String reason) { }

    private static final Pattern EMAIL = Pattern.compile("[\\w.+-]+@([\\w-]+\\.[\\w.]+)");
    private static final Pattern URL_HOST = Pattern.compile("https?://([^/\\s?#]+)");

    private final Dlp dlp;
    private final Set<String> fetchAllowlist;

    public ToolPolicy(Dlp dlp, Set<String> fetchAllowlist) {
        this.dlp = dlp;
        this.fetchAllowlist = fetchAllowlist;
    }

    /** Intents come ONLY from the authenticated user's message, never from retrieved content. */
    public static Set<Intent> intents(String userMessage) {
        String m = userMessage.toLowerCase(Locale.ROOT);
        Set<Intent> out = EnumSet.noneOf(Intent.class);
        if (m.matches("(?s).*\\b(summari[sz]e|summary|what does|tl;?dr|read|explain|find|what is|how much|when is)\\b.*")) {
            out.add(Intent.SUMMARIZE);
        }
        if (m.matches("(?s).*\\bc-\\d{3}\\b.*") || m.contains("customer")) {
            out.add(Intent.LOOKUP_CUSTOMER);
        }
        if (m.matches("(?s).*\\b(create|open|file|raise)\\b.{0,20}\\bticket\\b.*")) {
            out.add(Intent.CREATE_TICKET);
        }
        if (m.matches("(?s).*\\b(send|email|e-mail|forward|mail)\\b.*") && EMAIL.matcher(userMessage).find()) {
            out.add(Intent.SEND_EMAIL);
        }
        if (m.matches("(?s).*\\b(fetch|check|open|load)\\b.*https?://.*")) {
            out.add(Intent.FETCH);
        }
        if (m.contains("search")) {
            out.add(Intent.SEARCH);
        }
        return out;
    }

    public Decision decide(ToolCall call, String userMessage, Set<Intent> intents) {
        Privilege p = Workspace.TOOLS.get(call.tool());
        if (p == null) {
            return block("unknown tool " + call.tool());
        }
        String user = userMessage.toLowerCase(Locale.ROOT);
        return switch (call.tool()) {
            case "readDoc", "searchDocs" -> allow("read-only");
            case "lookupCustomer" -> user.contains(call.args().getOrDefault("id", "~").toLowerCase(Locale.ROOT))
                    ? allow("customer id provided by the user")
                    : block("customer id did not come from the user (tainted)");
            case "createTicket" -> intents.contains(Intent.CREATE_TICKET)
                    ? allow("user asked to create a ticket")
                    : new Decision(Verdict.NEEDS_APPROVAL, "ticket creation was not requested by the user");
            case "sendEmail" -> sendEmail(call, userMessage, intents);
            case "fetchUrl" -> fetch(call, user, intents);
            default -> block("no policy for " + call.tool());
        };
    }

    private Decision sendEmail(ToolCall call, String userMessage, Set<Intent> intents) {
        String to = call.args().getOrDefault("to", "");
        if (!intents.contains(Intent.SEND_EMAIL)) {
            return block("user did not ask to send email; instruction came from content");
        }
        if (!userMessage.toLowerCase(Locale.ROOT).contains(to.toLowerCase(Locale.ROOT))) {
            return block("recipient " + to + " does not appear in the user's request (tainted)");
        }
        Matcher m = EMAIL.matcher(to);
        boolean internal = m.find() && m.group(1).equalsIgnoreCase(Workspace.COMPANY_DOMAIN);
        boolean sensitive = !dlp.scan(call.args().getOrDefault("body", "")).clean();
        if (sensitive && !internal) {
            return block("sensitive data in an email to an external address");
        }
        if (sensitive) {
            return new Decision(Verdict.NEEDS_APPROVAL, "email contains sensitive data");
        }
        if (!internal) {
            return new Decision(Verdict.NEEDS_APPROVAL, "external recipient " + to);
        }
        return allow("internal recipient requested by the user");
    }

    private Decision fetch(ToolCall call, String user, Set<Intent> intents) {
        String url = call.args().getOrDefault("url", "");
        Matcher m = URL_HOST.matcher(url);
        String host = m.find() ? m.group(1).toLowerCase(Locale.ROOT) : "";
        if (fetchAllowlist.stream().noneMatch(a -> host.equals(a) || host.endsWith("." + a))) {
            return block("host " + host + " is not on the egress allowlist");
        }
        if (!intents.contains(Intent.FETCH) || !user.contains(url.toLowerCase(Locale.ROOT))) {
            return block("URL did not come from the user (tainted)");
        }
        return allow("allowlisted URL requested by the user");
    }

    private static Decision allow(String why) {
        return new Decision(Verdict.ALLOW, why);
    }

    private static Decision block(String why) {
        return new Decision(Verdict.BLOCK, why);
    }
}
