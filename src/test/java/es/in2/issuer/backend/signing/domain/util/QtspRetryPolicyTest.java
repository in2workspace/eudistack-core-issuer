package es.in2.issuer.backend.signing.domain.util;

import es.in2.issuer.backend.shared.domain.exception.RemoteSignatureException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientRequestException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.net.ConnectException;
import java.net.URI;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class QtspRetryPolicyTest {

    @Test
    void isRecoverable_serverError5xx_returnsTrue() {
        WebClientResponseException ex = WebClientResponseException.create(
                502, "Bad Gateway", null, null, null);

        assertTrue(QtspRetryPolicy.isRecoverable(ex));
    }

    @Test
    void isRecoverable_clientError4xx_returnsFalse() {
        WebClientResponseException ex = WebClientResponseException.create(
                400, "Bad Request", null, null, null);

        assertFalse(QtspRetryPolicy.isRecoverable(ex));
    }

    @Test
    void isRecoverable_connectException_returnsTrue() {
        assertTrue(QtspRetryPolicy.isRecoverable(new ConnectException("refused")));
    }

    @Test
    void isRecoverable_timeoutException_returnsTrue() {
        assertTrue(QtspRetryPolicy.isRecoverable(new TimeoutException("timed out")));
    }

    @Test
    void isRecoverable_webClientRequestException_returnsTrue() {
        WebClientRequestException ex = new WebClientRequestException(
                new RuntimeException("Connection reset by peer"),
                org.springframework.http.HttpMethod.POST,
                URI.create("https://dss.fikua.com/oauth2/token"),
                new org.springframework.http.HttpHeaders());

        assertTrue(QtspRetryPolicy.isRecoverable(ex));
    }

    @Test
    void isRecoverable_webClientRequestExceptionWrappedInDomainException_returnsTrue() {
        WebClientRequestException connectionReset = new WebClientRequestException(
                new RuntimeException("Connection reset by peer"),
                org.springframework.http.HttpMethod.POST,
                URI.create("https://dss.fikua.com/oauth2/token"),
                new org.springframework.http.HttpHeaders());
        RemoteSignatureException wrapped = new RemoteSignatureException(
                "Unexpected error retrieving access token", connectionReset);

        assertTrue(QtspRetryPolicy.isRecoverable(wrapped));
    }

    @Test
    void isRecoverable_unrelatedExceptionWrappedInDomainException_returnsFalse() {
        RemoteSignatureException wrapped = new RemoteSignatureException(
                "Unauthorized: Invalid credentials");

        assertFalse(QtspRetryPolicy.isRecoverable(wrapped));
    }

    @Test
    void isRecoverable_selfReferencingCause_doesNotLoopForever() {
        RuntimeException ex = new RuntimeException("boom");
        // Some JDK/JVM built-ins report their own cause as themselves; guard against infinite loops.
        assertFalse(QtspRetryPolicy.isRecoverable(ex));
    }

    @Test
    void isRecoverable_httpStatusHelper_matches5xxOnly() {
        assertTrue(QtspRetryPolicy.isRecoverable(
                WebClientResponseException.create(HttpStatus.SERVICE_UNAVAILABLE.value(), "", null, null, null)));
        assertFalse(QtspRetryPolicy.isRecoverable(
                WebClientResponseException.create(HttpStatus.NOT_FOUND.value(), "", null, null, null)));
    }
}
