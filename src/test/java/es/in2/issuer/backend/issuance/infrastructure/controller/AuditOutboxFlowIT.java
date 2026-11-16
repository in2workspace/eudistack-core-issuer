package es.in2.issuer.backend.issuance.infrastructure.controller;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * The audit trail of the Issuer end to end, with the publisher of the starter on and a real PostgreSQL: a request
 * to the API goes through the real authorization, the real use case and the real outbox (DT-002 §2.3).
 *
 * <p>It checks two things the unit tests, which run against a recording double, cannot see:
 * <ul>
 *   <li>every event staged by a flow of §3.9 is a span {@code audit.outbox.stage} carrying its
 *       {@code audit.event_type} (RQ-23), and reaches {@code public.audit_outbox};</li>
 *   <li>an operation leaves one row per type, never two of the same (R-3). {@code AuthorizationDecision} and the
 *       event of the operation are different types and each appears once; the flows chosen take one decision.</li>
 * </ul>
 * The context the starter needs (tenant, actor) and the transaction it demands (EC-09) are the real ones, so a flow
 * that staged without them would fail here as it would in a deployment.
 */
@TestPropertySource(properties = {"auditoria.publisher.enabled=true", "auditoria.dispatcher.enabled=false"})
class AuditOutboxFlowIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e-tenant-a";
    private static final String ORGANIZATION = "org-of-the-audit-flow-it";
    private static final String ARCHIVED = "IssuanceArchived";
    private static final String DETAIL_ACCESSED = "IssuanceDetailAccessed";
    private static final String DECISION = "AuthorizationDecision";

    /** Records the {@code audit.event_type} of every stage span that finished. */
    static final class StageSpans implements ObservationHandler<Observation.Context> {

        private final List<String> eventTypes = new CopyOnWriteArrayList<>();

        @Override
        public boolean supportsContext(Observation.Context context) {
            return "audit.outbox.stage".equals(context.getName());
        }

        @Override
        public void onStop(Observation.Context context) {
            var eventType = context.getLowCardinalityKeyValue("audit.event_type");
            eventTypes.add(eventType == null ? "<none>" : eventType.getValue());
        }

        List<String> eventTypes() {
            return List.copyOf(eventTypes);
        }

        void clear() {
            eventTypes.clear();
        }
    }

    @TestConfiguration
    static class SpanRecording {

        @Bean
        StageSpans stageSpans() {
            return new StageSpans();
        }
    }

    @Autowired
    private IssuancePort issuancePort;

    @Autowired
    private StageSpans stageSpans;

    @BeforeEach
    void cleanOutboxAndSpans() {
        databaseClient.sql("DELETE FROM public.audit_outbox").then().block(Duration.ofSeconds(10));
        stageSpans.clear();
    }

    @Test
    void archiveAWithdrawnProcess_stagesTheDecisionAndTheArchiveOnce_eachAsAStageSpan() {
        // Given
        UUID issuanceId = seedIssuance(CredentialStatusEnum.WITHDRAWN);

        // When
        webTestClient().patch().uri("/api/v1/issuances/{id}", issuanceId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mintOperatorAccessToken(TENANT, ORGANIZATION))
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("status", "ARCHIVED"))
                .exchange()
                .expectStatus().isNoContent();

        // Then: one row of each type, and a span for each
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertThat(rowsPerType()).containsEntry(ARCHIVED, 1L).containsEntry(DECISION, 1L));
        assertOnePerType(rowsPerType());
        assertThat(stageSpans.eventTypes()).containsOnlyOnce(ARCHIVED).containsOnlyOnce(DECISION);
    }

    @Test
    void readTheDetailOfAProcess_stagesTheDecisionAndTheAccessOnce_eachAsAStageSpan() {
        // Given
        UUID issuanceId = seedIssuance(CredentialStatusEnum.VALID);

        // When
        webTestClient().get().uri("/api/v1/issuances/{id}", issuanceId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mintOperatorAccessToken(TENANT, ORGANIZATION))
                .header(X_TENANT_HEADER, TENANT)
                .exchange()
                .expectStatus().isOk();

        // Then
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertThat(rowsPerType()).containsEntry(DETAIL_ACCESSED, 1L).containsEntry(DECISION, 1L));
        assertOnePerType(rowsPerType());
        assertThat(stageSpans.eventTypes()).containsOnlyOnce(DETAIL_ACCESSED).containsOnlyOnce(DECISION);
    }

    @Test
    void archiveAProcessThatCannotBeArchived_stagesTheRefusalOnceAndNoArchive() {
        // Given: a valid process cannot be archived (it has to end first)
        UUID issuanceId = seedIssuance(CredentialStatusEnum.VALID);

        // When
        webTestClient().patch().uri("/api/v1/issuances/{id}", issuanceId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + mintOperatorAccessToken(TENANT, ORGANIZATION))
                .header(X_TENANT_HEADER, TENANT)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("status", "ARCHIVED"))
                .exchange()
                .expectStatus().is4xxClientError();

        // Then: the denial survives the rollback of the business (a transaction of its own) and is not doubled
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertThat(rowsPerType()).containsEntry(ARCHIVED, 1L).containsEntry(DECISION, 1L));
        assertOnePerType(rowsPerType());
        assertThat(databaseClient.sql("SELECT payload->>'result' AS result FROM public.audit_outbox "
                        + "WHERE event_type = 'IssuanceArchived'")
                .fetch().one().block(Duration.ofSeconds(10))).containsEntry("result", "Denied");
    }

    @Test
    void platformAdministratorReadsAProcessOfATenant_stagesTheAccessOnceUnderThatTenantAsTheAdministrator() {
        // Given: a process of the tenant e2e-tenant-a, with its holder in the data set
        UUID issuanceId = seedIssuance(CredentialStatusEnum.VALID);
        String adminToken = mintUserAccessToken("platform", "VATES-PLATFORM-ADMIN", List.of(Map.of(
                        "type", "organization", "domain", "EUDISTACK", "function", "System", "action", List.of("Administration"))),
                "platform.admin@example.com");

        // When: the administrator reads it from the platform tenant
        webTestClient().get().uri("/api/v1/issuances/{id}", issuanceId)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + adminToken)
                .header(X_TENANT_HEADER, "platform")
                .exchange()
                .expectStatus().isOk();

        // Then: one access, in the tenant that owns the process, never in platform
        await().atMost(Duration.ofSeconds(10)).untilAsserted(() ->
                assertThat(rowsPerType()).containsEntry(DETAIL_ACCESSED, 1L));
        Map<String, Object> access = databaseClient.sql("SELECT tenant, payload->'actor'->>'id' AS actor_id, "
                        + "payload->'actor'->>'kind' AS actor_kind, payload->'details'->'holder'->>'email' AS holder_email "
                        + "FROM public.audit_outbox WHERE event_type = 'IssuanceDetailAccessed'")
                .fetch().one().block(Duration.ofSeconds(10));
        assertThat(access).containsEntry("tenant", TENANT)
                .containsEntry("actor_id", "platform.admin@example.com")
                .containsEntry("actor_kind", "Person")
                .containsEntry("holder_email", "holder@example.com");
        assertThat(databaseClient.sql("SELECT count(*) AS n FROM public.audit_outbox "
                        + "WHERE event_type = 'IssuanceDetailAccessed' AND tenant = 'platform'")
                .fetch().one().block(Duration.ofSeconds(10))).containsEntry("n", 0L);
    }

    private void assertOnePerType(Map<String, Long> perType) {
        assertThat(perType.values()).as("an operation never queues two rows of the same type: %s", perType)
                .allMatch(count -> count == 1L);
    }

    /** What the outbox holds, by event type. */
    private Map<String, Long> rowsPerType() {
        Map<String, Long> perType = new HashMap<>();
        databaseClient.sql("SELECT event_type, count(*) AS n FROM public.audit_outbox GROUP BY event_type")
                .fetch().all()
                .doOnNext(row -> perType.put((String) row.get("event_type"), ((Number) row.get("n")).longValue()))
                .collectList().block(Duration.ofSeconds(10));
        return perType;
    }

    private UUID seedIssuance(CredentialStatusEnum status) {
        Issuance issuance = Issuance.builder()
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{}")
                .credentialStatus(status)
                .organizationIdentifier(ORGANIZATION)
                .credentialType("learcredential.employee.w3c.4")
                .email("holder@example.com")
                .delivery("email")
                .build();
        return issuancePort.insert(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .map(Issuance::getIssuanceId)
                .block();
    }
}
