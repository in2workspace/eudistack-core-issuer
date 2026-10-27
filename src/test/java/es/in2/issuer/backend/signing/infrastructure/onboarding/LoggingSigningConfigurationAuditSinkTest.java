package es.in2.issuer.backend.signing.infrastructure.onboarding;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.issuer.backend.signing.domain.model.SigningModality;
import es.in2.issuer.backend.signing.domain.onboarding.RejectionReason;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Operation;
import es.in2.issuer.backend.signing.domain.onboarding.SigningConfigurationChanged.Result;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class LoggingSigningConfigurationAuditSinkTest {

    private static final String CERTIFICATE_HASH = "ab".repeat(32);
    private static final String ACTOR = "arn:aws:sts::000000000000:assumed-role/own-key-operation/jane";

    private final ObjectMapper mapper = new ObjectMapper();
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    private final Logger auditLogger = (Logger) LoggerFactory.getLogger(LoggingSigningConfigurationAuditSink.AUDIT_LOGGER);

    @BeforeEach
    void attachAppender() {
        appender.start();
        auditLogger.addAppender(appender);
    }

    @AfterEach
    void detachAppender() {
        auditLogger.detachAppender(appender);
    }

    private static SigningConfigurationChanged replacement() {
        return new SigningConfigurationChanged("cgcom", Operation.REPLACE, Result.SUCCESS, null, SigningModality.QTSP,
                SigningModality.OWN_KEY, CERTIFICATE_HASH, ACTOR, Duration.ofMillis(1234),
                Instant.parse("2026-10-27T12:00:00Z"), "op-1");
    }

    private static SigningConfigurationChanged rejection() {
        return new SigningConfigurationChanged("cgcom", Operation.CREATE, Result.DENIED, RejectionReason.KEY_IN_USE, null,
                SigningModality.OWN_KEY, CERTIFICATE_HASH, ACTOR, Duration.ofMillis(5),
                Instant.parse("2026-10-27T12:00:00Z"), null);
    }

    @Test
    void toJson_replacement_followsTheCatalogue() throws Exception {
        JsonNode json = mapper.readTree(LoggingSigningConfigurationAuditSink.toJson(replacement()));

        assertThat(json.get("type").asText()).isEqualTo("SigningConfigurationChanged");
        assertThat(json.get("action").asText()).isEqualTo("ConfigureSigning");
        assertThat(json.get("tenant").asText()).isEqualTo("cgcom");
        assertThat(json.get("result").asText()).isEqualTo("Success");
        assertThat(json.get("actor").asText()).isEqualTo(ACTOR);
        assertThat(json.get("duration_ms").asLong()).isEqualTo(1234);
        assertThat(json.get("correlation_id").asText()).isEqualTo("op-1");
        assertThat(json.get("details").get("operation").asText()).isEqualTo("Replace");
        assertThat(json.get("details").get("previous_modality").asText()).isEqualTo("Qtsp");
        assertThat(json.get("details").get("new_modality").asText()).isEqualTo("OwnKey");
        assertThat(json.get("details").get("signing_certificate").asText()).isEqualTo(CERTIFICATE_HASH);
        assertThat(json.has("reason")).isFalse();
    }

    @Test
    void toJson_rejection_carriesTheReason() throws Exception {
        JsonNode json = mapper.readTree(LoggingSigningConfigurationAuditSink.toJson(rejection()));

        assertThat(json.get("result").asText()).isEqualTo("Denied");
        assertThat(json.get("reason").asText()).isEqualTo("KeyInUse");
        assertThat(json.get("details").has("previous_modality")).isFalse();
    }

    @Test
    void toJson_hasOnlyTheFieldsOfTheCatalogue_soNoSecretCanBeInIt() throws Exception {
        JsonNode json = mapper.readTree(LoggingSigningConfigurationAuditSink.toJson(replacement()));

        List<String> topLevel = new ArrayList<>();
        json.fieldNames().forEachRemaining(topLevel::add);
        List<String> details = new ArrayList<>();
        json.get("details").fieldNames().forEachRemaining(details::add);

        assertThat(topLevel).containsExactlyInAnyOrder("type", "action", "tenant", "result", "actor", "duration_ms",
                "occurred_at", "correlation_id", "details");
        assertThat(details).containsExactlyInAnyOrder("operation", "previous_modality", "new_modality",
                "signing_certificate");
    }

    @Test
    void afterCommit_writesOneLineToTheAuditLogger() {
        new LoggingSigningConfigurationAuditSink().afterCommit(replacement());

        assertThat(appender.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel().toString()).isEqualTo("INFO");
            assertThat(event.getFormattedMessage()).contains("\"type\":\"SigningConfigurationChanged\"");
        });
    }

    @Test
    void stage_writesNothing_becauseTheLineIsOnlyWrittenAfterTheCommit() {
        new LoggingSigningConfigurationAuditSink().stage(null, replacement());

        assertThat(appender.list).isEmpty();
    }
}
