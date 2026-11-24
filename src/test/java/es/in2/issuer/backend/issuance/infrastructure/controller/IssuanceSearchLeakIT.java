package es.in2.issuer.backend.issuance.infrastructure.controller;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.IThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.shared.domain.util.SubjectSearch;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-255 AC-09 and NFR-2 for the search by name: the text searched is personal data and the audit trail is the one
 * place it is kept. A search, a valid one and one refused for its shape, is made with a text that exists nowhere
 * else; then it is looked for in the address of the request, in the application's logs (what the OpenTelemetry
 * appender exports), in every observation (what becomes a span) and in every text column of the tenant's schema and
 * of {@code public}. It may only appear in {@code public.audit_outbox}, once per search.
 *
 * <p>The search by identifier gets the same proof with EUD-270 task 6, where only its fingerprint may remain.
 */
@TestPropertySource(properties = {
        "auditoria.publisher.enabled=true",
        "auditoria.dispatcher.enabled=false",
        "logging.level.es.in2=DEBUG"})
class IssuanceSearchLeakIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e-tenant-a";

    /** Every observation that finished, as text: name, key values and context. */
    static final class Observations implements ObservationHandler<Observation.Context> {

        private final List<String> finished = new CopyOnWriteArrayList<>();

        @Override
        public boolean supportsContext(Observation.Context context) {
            return true;
        }

        @Override
        public void onStop(Observation.Context context) {
            finished.add(context.getName() + " " + context.getContextualName() + " "
                    + context.getLowCardinalityKeyValues() + " " + context.getHighCardinalityKeyValues() + " " + context);
        }

        List<String> finished() {
            return List.copyOf(finished);
        }

        void clear() {
            finished.clear();
        }
    }

    @TestConfiguration
    static class ObservationRecording {

        @Bean
        Observations allObservations() {
            return new Observations();
        }
    }

    @Autowired
    private IssuancePort issuancePort;

    @Autowired
    private Observations observations;

    private final ListAppender<ILoggingEvent> logs = new ListAppender<>();

    @BeforeEach
    void captureLogs() {
        Logger root = ((LoggerContext) LoggerFactory.getILoggerFactory()).getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        logs.start();
        root.addAppender(logs);
        observations.clear();
    }

    @AfterEach
    void releaseLogs() {
        Logger root = ((LoggerContext) LoggerFactory.getILoggerFactory()).getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        root.detachAppender(logs);
        logs.stop();
    }

    @Test
    void theTextSearched_isOnlyInTheAuditTrail() {
        // Given: a process whose subject matches the text only once normalized, so the text as sent exists nowhere
        String marker = "zqx" + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
        String sent = "Ñ" + marker.toUpperCase() + "É";
        String organization = "VATES-LEAK-" + UUID.randomUUID();
        seed(organization, "Ana N" + marker + "e Prado");
        Map<String, Long> before = occurrencesInTables(sent);
        String token = mintOperatorAccessToken(TENANT, organization);
        logs.list.clear();
        observations.clear();

        // When: a search that finds it and one refused for its shape
        webTestClient().post().uri("/api/v1/issuances/search")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subject\": \"" + sent + "\"}")
                .exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.issuances.length()").isEqualTo(1);
        webTestClient().post().uri("/api/v1/issuances/search")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"subject\": \"" + sent + "\", \"identifier\": \"" + sent + "\"}")
                .exchange()
                .expectStatus().isBadRequest();

        // Then: the capture works -- the requests did log and observe something
        assertThat(logs.list).isNotEmpty();
        assertThat(observations.finished()).anySatisfy(observation -> assertThat(observation).contains("/api/v1/issuances/search"));
        // ...and neither the text as sent nor its compared form is in a log, an observation or an address
        String compared = SubjectSearch.normalize(sent);
        for (String value : List.of(sent, compared, marker.toUpperCase())) {
            assertThat(logLines()).as("logs").noneSatisfy(line -> assertThat(line).containsIgnoringCase(value));
            assertThat(observations.finished()).as("observations").noneSatisfy(line -> assertThat(line).contains(value));
        }
        // ...nor in a table, but in the audit trail of the search that was made
        Map<String, Long> after = occurrencesInTables(sent);
        assertThat(after).as("text columns holding the text searched").isEqualTo(before);
        assertThat(databaseClient.sql("SELECT count(*) AS n FROM public.audit_outbox WHERE payload::text LIKE :text")
                .bind("text", "%" + sent + "%")
                .fetch().one().block(Duration.ofSeconds(10))).containsEntry("n", 1L);
    }

    /** Every log event as text: the message with its arguments, and the messages of its exceptions. */
    private List<String> logLines() {
        List<String> lines = new ArrayList<>();
        for (ILoggingEvent event : List.copyOf(logs.list)) {
            StringBuilder line = new StringBuilder(event.getLoggerName()).append(' ').append(event.getFormattedMessage());
            event.getMDCPropertyMap().forEach((key, value) -> line.append(' ').append(key).append('=').append(value));
            for (IThrowableProxy error = event.getThrowableProxy(); error != null; error = error.getCause()) {
                line.append(' ').append(error.getClassName()).append(": ").append(error.getMessage());
            }
            lines.add(line.toString());
        }
        return lines;
    }

    /**
     * How many rows of each text column of the tenant's schema and of {@code public} contain the text, but for the
     * audit outbox, which is where it must be.
     */
    private Map<String, Long> occurrencesInTables(String text) {
        List<Map<String, Object>> columns = databaseClient.sql("SELECT table_schema, table_name, column_name "
                        + "FROM information_schema.columns c "
                        + "JOIN information_schema.tables t USING (table_schema, table_name) "
                        + "WHERE t.table_type = 'BASE TABLE' AND table_schema IN (:schemas) "
                        + "AND data_type IN ('text', 'character varying', 'character', 'json', 'jsonb') "
                        + "AND NOT (table_schema = 'public' AND table_name = 'audit_outbox') "
                        + "ORDER BY 1, 2, 3")
                .bind("schemas", List.of(TENANT + SCHEMA_SUFFIX, "public"))
                .fetch().all().collectList().block(Duration.ofSeconds(10));
        assertThat(columns).as("the tenant's tables are scanned").isNotEmpty();
        Map<String, Long> occurrences = new LinkedHashMap<>();
        for (Map<String, Object> column : columns) {
            String qualified = quoted(column.get("table_schema")) + "." + quoted(column.get("table_name"));
            String name = quoted(column.get("column_name"));
            Map<String, Object> count = databaseClient.sql("SELECT count(*) AS n FROM " + qualified
                            + " WHERE " + name + "::text ILIKE :text")
                    .bind("text", "%" + text + "%")
                    .fetch().one().block(Duration.ofSeconds(10));
            occurrences.put(qualified + "." + name, ((Number) count.get("n")).longValue());
        }
        return occurrences;
    }

    private static String quoted(Object identifier) {
        return "\"" + identifier.toString().replace("\"", "\"\"") + "\"";
    }

    private void seed(String organization, String subject) {
        Issuance issuance = Issuance.builder()
                .credentialFormat("dc+sd-jwt")
                .credentialDataSet("{}")
                .credentialStatus(CredentialStatusEnum.VALID)
                .organizationIdentifier(organization)
                .credentialType("doctor.sd.1")
                .subject(subject)
                .email("holder@example.com")
                .delivery("email")
                .build();
        issuancePort.insert(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
    }
}
