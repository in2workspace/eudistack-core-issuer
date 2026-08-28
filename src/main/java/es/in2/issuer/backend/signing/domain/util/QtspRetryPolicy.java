package es.in2.issuer.backend.signing.domain.util;

import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.net.ConnectException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeoutException;

public final class QtspRetryPolicy {

    private QtspRetryPolicy() {}

    // Callers (e.g. OAuth2AuthStrategy) rewrap low-level I/O failures into domain exceptions
    // such as RemoteSignatureException, so the recoverable cause is rarely the outermost
    // throwable. Walk the full cause chain instead of only inspecting the top-level exception.
    public static boolean isRecoverable(Throwable throwable) {
        Set<Throwable> seen = new HashSet<>();
        Throwable current = throwable;
        while (current != null && seen.add(current)) {
            if (isRecoverableCause(current)) {
                return true;
            }
            current = current.getCause();
        }
        return false;
    }

    private static boolean isRecoverableCause(Throwable throwable) {
        if (throwable instanceof WebClientResponseException ex) {
            return ex.getStatusCode().is5xxServerError();
        }
        // WebClientRequestException wraps connection-level I/O failures (connection reset,
        // refused, DNS resolution) that occur before any HTTP response is received.
        return throwable instanceof WebClientRequestException
                || throwable instanceof ConnectException
                || throwable instanceof TimeoutException;
    }
}
