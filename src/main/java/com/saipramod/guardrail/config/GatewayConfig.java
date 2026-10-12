package com.saipramod.guardrail.config;

import com.saipramod.guardrail.agent.Agent;
import com.saipramod.guardrail.agent.GullibleAgent;
import com.saipramod.guardrail.agent.LlmAgent;
import com.saipramod.guardrail.core.Workspace;
import com.saipramod.guardrail.guard.Gateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Default agent is the deliberately vulnerable simulator; with LLM_PROVIDER=anthropic a real model sits behind the gateway. */
@Configuration
public class GatewayConfig {

    private static final Logger log = LoggerFactory.getLogger(GatewayConfig.class);

    @Bean
    Agent agent(ObjectProvider<ChatModel> chatModel) {
        ChatModel m = chatModel.getIfAvailable();
        Agent a = m == null ? new GullibleAgent() : new LlmAgent(ChatClient.create(m));
        log.info("Agent behind the gateway: {}", a.name());
        return a;
    }

    @Bean
    Gateway gateway(Agent agent) {
        return new Gateway(agent, Workspace.demo(), Gateway.Layers.all());
    }
}
