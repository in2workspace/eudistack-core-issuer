package es.in2.issuer.backend.shared.infrastructure.audit;

import io.netty.channel.ConnectTimeoutException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mail.MailAuthenticationException;
import org.springframework.mail.MailSendException;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ExternalFailureClassifierTest {

    @Nested
    @DisplayName("mail provider errors")
    class MailProvider {

        @Test
        void reasonOf_mailAuthenticationFailure_returnsAuthenticationRejected() {
            // Arrange
            Throwable error = new MailAuthenticationException("535 bad credentials");

            // Act
            String reason = ExternalFailureClassifier.reasonOf(error);

            // Assert
            assertEquals("AuthenticationRejected", reason);
        }

        @Test
        void reasonOf_sendFailureCausedByConnectionRefused_returnsUnreachable() {
            // Arrange
            Throwable error = new MailSendException("Mail server connection failed", new ConnectException("refused"));

            // Act
            String reason = ExternalFailureClassifier.reasonOf(error);

            // Assert
            assertEquals("Unreachable", reason);
        }

        @Test
        void reasonOf_sendFailureCausedBySocketTimeout_returnsTimeout() {
            // Arrange
            Throwable error = new MailSendException("failed", new SocketTimeoutException("Read timed out"));

            // Act
            String reason = ExternalFailureClassifier.reasonOf(error);

            // Assert
            assertEquals("Timeout", reason);
        }
    }

    @Nested
    @DisplayName("http client errors")
    class HttpClient {

        @Test
        void reasonOf_unauthorizedResponse_returnsAuthenticationRejected() {
            // Arrange
            Throwable error = WebClientResponseException.create(HttpStatus.UNAUTHORIZED.value(), "Unauthorized", null, null, null);

            // Act
            String reason = ExternalFailureClassifier.reasonOf(error);

            // Assert
            assertEquals("AuthenticationRejected", reason);
        }

        @Test
        void reasonOf_serverErrorResponse_returnsErrorResponse() {
            // Arrange
            Throwable error = WebClientResponseException.create(HttpStatus.BAD_GATEWAY.value(), "Bad Gateway", null, null, null);

            // Act
            String reason = ExternalFailureClassifier.reasonOf(error);

            // Assert
            assertEquals("ErrorResponse", reason);
        }

        @Test
        void reasonOf_connectTimeout_returnsTimeoutAndNotUnreachable() {
            // Arrange
            Throwable error = new ConnectTimeoutException("connect timed out");

            // Act
            String reason = ExternalFailureClassifier.reasonOf(error);

            // Assert
            assertEquals("Timeout", reason);
        }

        @Test
        void reasonOf_unknownHost_returnsUnreachable() {
            // Arrange
            Throwable error = new RuntimeException("wrapped", new UnknownHostException("qtsp.example.com"));

            // Act
            String reason = ExternalFailureClassifier.reasonOf(error);

            // Assert
            assertEquals("Unreachable", reason);
        }

        @Test
        void reasonOf_reactiveTimeoutException_returnsTimeout() {
            // Arrange
            Throwable error = new TimeoutException("no response in 2s");

            // Act
            String reason = ExternalFailureClassifier.reasonOf(error);

            // Assert
            assertEquals("Timeout", reason);
        }
    }

    @Test
    void reasonOf_unrecognisedError_returnsErrorResponse() {
        // Arrange
        Throwable error = new IllegalStateException("something else");

        // Act
        String reason = ExternalFailureClassifier.reasonOf(error);

        // Assert
        assertEquals("ErrorResponse", reason);
    }
}
