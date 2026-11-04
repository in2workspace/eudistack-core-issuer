package es.in2.issuer.backend.shared.infrastructure.config.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.infrastructure.controller.error.ErrorResponseFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Component
public class ProblemAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final ErrorResponseFactory errors;
    private final SecurityProblemResolver resolver;
    private final List<AuthenticationRejectionListener> rejectionListeners;

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        log.debug("ProblemAuthenticationEntryPoint.commence - inside");
        log.debug("Exception: ", ex);

        var response = exchange.getResponse();
        var spec = resolver.resolve(ex, true);

        response.setStatusCode(spec.status());
        response.getHeaders().setContentType(MediaType.valueOf("application/problem+json"));

        var msg = errors.handleWithNow(
                ex,
                exchange.getRequest(),
                spec.type(),
                spec.title(),
                spec.status(),
                spec.fallbackDetail()
        );

        byte[] body;
        try {
            body = objectMapper.writeValueAsBytes(msg);
        } catch (Exception e) {
            body = "{\"title\":\"Unauthorized\",\"status\":401}".getBytes(StandardCharsets.UTF_8);
        }
        byte[] problem = body;
        return notifyListeners(exchange, spec.type())
                .then(Mono.defer(() -> response.writeWith(Mono.just(response.bufferFactory().wrap(problem)))));
    }

    /** A listener that fails never changes the answer to the client. */
    private Mono<Void> notifyListeners(ServerWebExchange exchange, String errorType) {
        return Flux.fromIterable(rejectionListeners)
                .concatMap(listener -> listener.onRejected(exchange, errorType)
                        .onErrorResume(e -> {
                            log.warn("Authentication rejection listener failed: {}", e.getClass().getSimpleName());
                            return Mono.empty();
                        }))
                .then();
    }
}
