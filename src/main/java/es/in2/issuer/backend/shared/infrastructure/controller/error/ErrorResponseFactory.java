package es.in2.issuer.backend.shared.infrastructure.controller.error;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.reactive.ServerWebExchangeContextFilter;
import reactor.core.publisher.Mono;
import reactor.util.context.ContextView;

import java.util.List;
import java.util.UUID;

/**
 * Builds the Problem Details (RFC 9457) body of every handled error. On the management API
 * ({@code /api/**}, the APIs of the public guides) the response is served as
 * {@code application/problem+json} (EUD-307), whatever the {@code produces} of the controller that
 * failed: the exchange is taken from the Reactor context, where {@code ExchangeContextWebFilter} puts
 * it. The protocol endpoints (OAuth, OID4VCI, well-known) keep {@code application/json}, which RFC 6749
 * and OID4VCI require of their errors.
 */
@Slf4j
@Component
public class ErrorResponseFactory {

    /** Path prefix, within the application, of the management API served as Problem Details. */
    static final String MANAGEMENT_API_PREFIX = "/api/";

    public Mono<GlobalErrorMessage> handleWith(
            Exception ex, ServerHttpRequest request,
            String type, String title, HttpStatus status, String fallbackDetail
    ) {
        String detail = resolveDetail(ex, fallbackDetail);
        return Mono.deferContextual(ctx -> asProblem(ctx, request, buildError(type, title, status, detail, ex, request, null)));
    }

    /**
     * Handles an exception without ever leaking the exception message to the client.
     * Used for catch-all handlers where the exception message may contain internal details.
     */
    public Mono<GlobalErrorMessage> handleSafe(
            Exception ex, ServerHttpRequest request,
            String type, String title, HttpStatus status, String detail
    ) {
        return Mono.deferContextual(ctx -> asProblem(ctx, request, buildError(type, title, status, detail, ex, request, null)));
    }

    public Mono<GlobalErrorMessage> handleWithViolations(
            Exception ex, ServerHttpRequest request,
            String type, String title, HttpStatus status, String fallbackDetail,
            List<GlobalErrorMessage.FieldViolation> violations
    ) {
        String detail = resolveDetail(ex, fallbackDetail);
        return Mono.deferContextual(ctx -> asProblem(ctx, request, buildError(type, title, status, detail, ex, request, violations)));
    }

    public GlobalErrorMessage handleWithNow(
            Exception ex, ServerHttpRequest request,
            String type, String title, HttpStatus status, String fallbackDetail
    ) {
        String detail = resolveDetail(ex, fallbackDetail);
        return buildError(type, title, status, detail, ex, request, null);
    }

    /**
     * Serves a management API error as Problem Details: a concrete Content-Type set here wins over
     * content negotiation. A response already committed keeps its headers (they are read-only then).
     */
    private static Mono<GlobalErrorMessage> asProblem(ContextView ctx, ServerHttpRequest request,
                                                      GlobalErrorMessage body) {
        if (request.getPath().pathWithinApplication().value().startsWith(MANAGEMENT_API_PREFIX)) {
            ServerWebExchangeContextFilter.getExchange(ctx)
                    .filter(exchange -> !exchange.getResponse().isCommitted())
                    .ifPresent(exchange ->
                            exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_PROBLEM_JSON));
        }
        return Mono.just(body);
    }

    private String resolveDetail(Exception ex, String fallback) {
        String msg = ex.getMessage();
        return (msg == null || msg.isBlank()) ? fallback : msg;
    }

    private GlobalErrorMessage buildError(
            String type, String title, HttpStatus httpStatus, String detail,
            Exception ex, ServerHttpRequest request,
            List<GlobalErrorMessage.FieldViolation> violations
    ) {
        String instance = UUID.randomUUID().toString();
        RequestPath path = request.getPath();
        log.error("instance={} path={} status={} ex={} detail={} message={}",
                instance, path.value(), httpStatus.value(), ex.getClass().getName(), detail, ex.getMessage(), ex);
        return new GlobalErrorMessage(type, title, httpStatus.value(), detail, instance, violations);
    }
}
