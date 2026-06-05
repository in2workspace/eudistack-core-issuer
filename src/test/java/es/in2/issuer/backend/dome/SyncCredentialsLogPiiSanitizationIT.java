package es.in2.issuer.backend.dome;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.dome.domain.spi.CredentialSyncPort;
import es.in2.issuer.backend.dome.domain.spi.TenantConfigPort;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

import static es.in2.issuer.backend.dome.support.DpopTestUtils.generateValidDpop;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

@SpringBootTest
@AutoConfigureWebTestClient
public class SyncCredentialsLogPiiSanitizationIT {

    @Autowired
    private WebTestClient webTestClient;

    @MockitoBean
    private CredentialSyncPort credentialSyncPort;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // Variables para capturar los logs
    private ListAppender<ILoggingEvent> listAppender;
    private Logger appLogger;

    @BeforeEach
    void setupLogAppender() {
        appLogger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        listAppender = new ListAppender<>();
        listAppender.start();
        appLogger.addAppender(listAppender);
    }

    @AfterEach
    void tearDownLogAppender() {
        appLogger.detachAppender(listAppender);
        listAppender.stop();
    }

    @Test
    @DisplayName("NFR-S-144-03: Validates 0 occurrences of PII in logs during happy path")
    void logsShouldNotContainPii() {
        when(tenantConfigPort.requireConfig(anyString())).thenReturn(Mono.empty());

        String sensitiveEmail = "topsecret.user@in2.es";
        String sensitiveName = "James Bond";
        String sensitivePhone = "+34600000000";
        String sensitiveSubject = "subject_12345ABC";
        String sensitiveJwtPayload = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SENSITIVE_PAYLOAD";

        JsonNode mockCredentialWithPii = objectMapper.createObjectNode()
                .put("format", "vc+sd-jwt")
                .put("credential", sensitiveJwtPayload)
                .set("claims", objectMapper.createObjectNode()
                        .put("email", sensitiveEmail)
                        .put("name", sensitiveName)
                        .put("phone", sensitivePhone)
                        .put("subject", sensitiveSubject));

        when(credentialSyncPort.findByHolderKey(anyString(), any()))
                .thenReturn(Flux.just(mockCredentialWithPii));

        String body = "{\"idempotencyKey\": \"018f2a99-9b80-7fc4-a82f-2c8e3100b468\", \"holderKeyThumbprint\": \"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\"}";

        webTestClient
                .mutateWith(csrf())
                .mutateWith(mockJwt().jwt(builder -> builder
                        .claim("tenant", "dome")
                        .claim("scope", "DomeRecovery/Sync")
                ))
                .post().uri("/internal/dome/sync-credentials")
                .header("DPoP", generateValidDpop("POST", "/internal/dome/sync-credentials"))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .exchange()
                .expectStatus().isOk();

        List<ILoggingEvent> logsList = listAppender.list;
        assertThat(logsList).isNotEmpty();

        for (ILoggingEvent event : logsList) {
            String logMessage = event.getFormattedMessage();

            assertThat(logMessage)
                    .as("Log message should not contain PII email")
                    .doesNotContain(sensitiveEmail);

            assertThat(logMessage)
                    .as("Log message should not contain PII name")
                    .doesNotContain(sensitiveName);

            assertThat(logMessage)
                    .as("Log message should not contain PII phone")
                    .doesNotContain(sensitivePhone);

            assertThat(logMessage)
                    .as("Log message should not contain PII subject")
                    .doesNotContain(sensitiveSubject);

            assertThat(logMessage)
                    .as("Log message should not dump raw JWT payload")
                    .doesNotContain("SENSITIVE_PAYLOAD");
        }
    }
}