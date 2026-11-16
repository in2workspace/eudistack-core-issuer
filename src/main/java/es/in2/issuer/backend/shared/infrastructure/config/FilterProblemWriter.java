package es.in2.issuer.backend.shared.infrastructure.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.shared.infrastructure.controller.error.GlobalErrorMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Writes an RFC 9457 problem from a web filter, with the same body as the controller errors
 * ({@link GlobalErrorMessage}, {@code instance} = the request path as the client sent it) and
 * {@code Content-Type: application/problem+json} (EUD-269).
 */
@Slf4j
public class FilterProblemWriter {

    private final ObjectMapper objectMapper;

    public FilterProblemWriter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public Mono<Void> write(ServerWebExchange exchange, HttpStatus status, String type, String title,
                            String detail, Long retryAfterSeconds) {
        return write(exchange, status, type, title, detail, retryAfterSeconds, null);
    }

    /** As {@link #write(ServerWebExchange, HttpStatus, String, String, String, Long)}, with {@code violations}. */
    public Mono<Void> write(ServerWebExchange exchange, HttpStatus status, String type, String title,
                            String detail, Long retryAfterSeconds, List<GlobalErrorMessage.FieldViolation> violations) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON);
        response.getHeaders().setCacheControl("no-store");
        if (retryAfterSeconds != null) {
            response.getHeaders().set(HttpHeaders.RETRY_AFTER, String.valueOf(retryAfterSeconds));
        }
        GlobalErrorMessage problem = new GlobalErrorMessage(type, title, status.value(), detail,
                exchange.getRequest().getPath().value(), violations);
        byte[] body;
        try {
            body = objectMapper.writeValueAsBytes(problem);
        } catch (JsonProcessingException e) {
            log.error("Could not serialize problem type={}", type, e);
            body = ("{\"type\":\"" + type + "\",\"status\":" + status.value() + "}").getBytes(StandardCharsets.UTF_8);
        }
        return response.writeWith(Mono.just(response.bufferFactory().wrap(body)));
    }
}
