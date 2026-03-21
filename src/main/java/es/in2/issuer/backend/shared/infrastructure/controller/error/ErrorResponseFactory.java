package es.in2.issuer.backend.shared.infrastructure.controller.error;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.RequestPath;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;

@Slf4j
@Component
public class ErrorResponseFactory {
    public Mono<GlobalErrorMessage> handleWith(
            Exception ex, ServerHttpRequest request,
            String type, String title, HttpStatus status, String fallbackDetail
    ) {
        String detail = resolveDetail(ex, fallbackDetail);
        return Mono.fromSupplier(() -> buildError(type, title, status, detail, ex, request, null));
    }

    /**
     * Handles an exception without ever leaking the exception message to the client.
     * Used for catch-all handlers where the exception message may contain internal details.
     */
    public Mono<GlobalErrorMessage> handleSafe(
            Exception ex, ServerHttpRequest request,
            String type, String title, HttpStatus status, String detail
    ) {
        return Mono.fromSupplier(() -> buildError(type, title, status, detail, ex, request, null));
    }

    public Mono<GlobalErrorMessage> handleWithViolations(
            Exception ex, ServerHttpRequest request,
            String type, String title, HttpStatus status, String fallbackDetail,
            List<GlobalErrorMessage.FieldViolation> violations
    ) {
        String detail = resolveDetail(ex, fallbackDetail);
        return Mono.fromSupplier(() -> buildError(type, title, status, detail, ex, request, violations));
    }

    public GlobalErrorMessage handleWithNow(
            Exception ex, ServerHttpRequest request,
            String type, String title, HttpStatus status, String fallbackDetail
    ) {
        String detail = resolveDetail(ex, fallbackDetail);
        return buildError(type, title, status, detail, ex, request, null);
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
        log.error("instance={} path={} status={} ex={} detail={} cause={}",
                instance, path.value(), httpStatus.value(), ex.getClass().getName(), detail, ex.getMessage(), ex);
        return new GlobalErrorMessage(type, title, httpStatus.value(), detail, instance, violations);
    }
}
