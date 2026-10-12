package com.saipramod.guardrail.api;

import com.saipramod.guardrail.agent.Agent;
import com.saipramod.guardrail.guard.Gateway;
import com.saipramod.guardrail.redteam.RedTeamRunner;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

@RestController
@RequestMapping("/api")
public class GatewayController {

    public record ChatRequest(@NotBlank @Size(max = 8000) String message, Gateway.Layers layers) { }

    public record Review(@NotBlank String reviewer) { }

    private final Gateway gateway;
    private final Agent agent;

    public GatewayController(Gateway gateway, Agent agent) {
        this.gateway = gateway;
        this.agent = agent;
    }

    @PostMapping("/chat")
    public Gateway.Response chat(@Valid @RequestBody ChatRequest req) {
        return gateway.handle(req.message(), req.layers() == null ? Gateway.Layers.all() : req.layers());
    }

    @GetMapping("/audit")
    public List<Gateway.AuditEvent> audit() {
        List<Gateway.AuditEvent> all = gateway.audit();
        return all.subList(Math.max(0, all.size() - 200), all.size());
    }

    @GetMapping("/approvals")
    public List<Gateway.PendingApproval> approvals() {
        return gateway.pending();
    }

    @PostMapping("/approvals/{id}/approve")
    public Map<String, String> approve(@PathVariable String id, @Valid @RequestBody Review r) {
        return Map.of("result", gateway.approve(id, r.reviewer()));
    }

    @PostMapping("/approvals/{id}/reject")
    public Map<String, String> reject(@PathVariable String id, @Valid @RequestBody Review r) {
        gateway.reject(id, r.reviewer());
        return Map.of("result", "rejected");
    }

    /** The side effects that actually happened: what an attacker would be after. */
    @GetMapping("/sinks")
    public Map<String, Object> sinks() {
        var w = gateway.workspace();
        return Map.of("outbox", w.outbox(), "tickets", w.tickets(), "fetched", w.fetched());
    }

    @GetMapping("/docs")
    public Object docs() {
        return gateway.workspace().docs();
    }

    @PostMapping("/redteam")
    public RedTeamRunner.Report redTeam() throws IOException {
        return RedTeamRunner.run(() -> agent);
    }

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<Map<String, String>> notFound(RuntimeException e) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", e.getMessage()));
    }
}
