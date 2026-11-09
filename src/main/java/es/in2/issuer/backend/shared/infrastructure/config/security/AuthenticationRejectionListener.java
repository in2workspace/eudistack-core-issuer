package es.in2.issuer.backend.shared.infrastructure.config.security;

import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Told about a request the security chain rejects before it reaches any controller, so a feature that
 * must trace every request it receives can do so. The answer to the client does not depend on it: a
 * failure here is logged and the 401 goes out as usual.
 */
public interface AuthenticationRejectionListener {

    /** @param errorType the {@code type} of the 401 Problem Details the client is about to receive */
    Mono<Void> onRejected(ServerWebExchange exchange, String errorType);
}
