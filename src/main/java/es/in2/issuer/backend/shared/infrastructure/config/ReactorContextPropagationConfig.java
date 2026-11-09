package es.in2.issuer.backend.shared.infrastructure.config;

import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Hooks;

/**
 * Restores the Reactor Context into ThreadLocals (MDC) on every operator: without it traceId, spanId
 * and tenantDomain are empty in log lines written from operators such as flatMap or doOnSuccess.
 */
@Configuration
public class ReactorContextPropagationConfig {

    @PostConstruct
    public void init() {
        Hooks.enableAutomaticContextPropagation();
    }
}
