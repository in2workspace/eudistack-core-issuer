package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.shared.domain.model.entities.Issuance;
import es.in2.issuer.backend.shared.domain.model.enums.CredentialStatusEnum;
import es.in2.issuer.backend.shared.domain.service.SearchIdentifierIndexer;
import es.in2.issuer.backend.shared.domain.spi.IssuancePort;
import es.in2.issuer.backend.support.PostgresIntegrationBase;
import es.in2.issuer.backend.support.TenantSchemaMigrations;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.support.TenantSchemaMigrations.schemaOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * EUD-255 AD-2 against a real Postgres: {@code V21__Add_last_changed_at_to_issuance.sql} backfills
 * existing rows and makes the column mandatory with its two indexes, and the application sets it on
 * creation and on every change of state, but not on a technical write.
 */
class IssuanceLastChangedAtIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e";

    @Autowired private FlywayProperties flywayProperties;
    @Autowired private R2dbcProperties r2dbcProperties;
    @Autowired private IssuancePort issuancePort;
    @Autowired private SearchIdentifierIndexer searchIdentifierIndexer;

    @Test
    void migration_backfillsFromUpdatedAt_thenCreatedAt_andMakesTheColumnMandatory() {
        String tenant = "last_changed_backfill";
        TenantSchemaMigrations.migrate(flywayProperties, r2dbcProperties, tenant, "18");
        UUID withUpdated = UUID.randomUUID();
        UUID onlyCreated = UUID.randomUUID();
        databaseClient.sql("INSERT INTO " + table(tenant) + " (issuance_id, credential_status, created_at, updated_at) VALUES "
                        + "('" + withUpdated + "', 'VALID', '2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z'), "
                        + "('" + onlyCreated + "', 'DRAFT', '2026-03-01T00:00:00Z', NULL)")
                .then().block();

        TenantSchemaMigrations.migrate(flywayProperties, r2dbcProperties, tenant, null);

        assertThat(lastChangedAt(tenant, withUpdated)).isEqualTo(Instant.parse("2026-02-01T00:00:00Z"));
        assertThat(lastChangedAt(tenant, onlyCreated)).isEqualTo(Instant.parse("2026-03-01T00:00:00Z"));
        var clearTheLastChange = databaseClient.sql("UPDATE " + table(tenant) + " SET last_changed_at = NULL").then();
        assertThatThrownBy(clearTheLastChange::block).isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void migration_createsTheKeysetIndexes() {
        String tenant = "last_changed_indexes";
        TenantSchemaMigrations.migrate(flywayProperties, r2dbcProperties, tenant, null);

        List<String> indexes = databaseClient.sql("SELECT indexname FROM pg_indexes WHERE schemaname = :schema "
                        + "AND tablename = 'issuance'")
                .bind("schema", schemaOf(tenant))
                .map(row -> row.get("indexname", String.class))
                .all().collectList().block();

        assertThat(indexes).contains("idx_issuance_last_changed", "idx_issuance_org_last_changed");
    }

    @Test
    void creation_setsTheLastChange() {
        Instant start = Instant.now();

        Issuance created = create();

        assertThat(reread(created.getIssuanceId()).getLastChangedAt()).isAfterOrEqualTo(truncated(start));
    }

    @Test
    void aChangeOfState_movesTheLastChange_andATechnicalWriteDoesNot() {
        Issuance created = create();
        Instant atCreation = reread(created.getIssuanceId()).getLastChangedAt();

        Issuance delivered = reread(created.getIssuanceId());
        delivered.setDeliveryAttemptedAt(Instant.now());
        save(delivered);
        assertThat(reread(created.getIssuanceId()).getLastChangedAt()).isEqualTo(atCreation);

        Issuance issued = reread(created.getIssuanceId());
        issued.setCredentialStatus(CredentialStatusEnum.ISSUED);
        save(issued);
        assertThat(reread(created.getIssuanceId()).getLastChangedAt()).isAfter(atCreation);
    }

    private Issuance create() {
        Issuance issuance = Issuance.builder()
                .credentialFormat("jwt_vc_json")
                .credentialDataSet("{}")
                .credentialStatus(CredentialStatusEnum.DRAFT)
                .organizationIdentifier("ORG-A")
                .credentialType("learcredential.employee.w3c.4")
                .email("holder@example.com")
                .delivery("email")
                .build();
        return searchIdentifierIndexer.saveWithFingerprints(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
    }

    private void save(Issuance issuance) {
        issuancePort.save(issuance)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
    }

    private Issuance reread(UUID issuanceId) {
        return issuancePort.findByIssuanceId(issuanceId)
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
    }

    private Instant lastChangedAt(String tenant, UUID issuanceId) {
        Map<String, Object> row = databaseClient.sql("SELECT last_changed_at FROM " + table(tenant)
                        + " WHERE issuance_id = '" + issuanceId + "'")
                .fetch().one().block();
        return ((OffsetDateTime) row.get("last_changed_at")).withOffsetSameInstant(ZoneOffset.UTC).toInstant();
    }

    /** Postgres keeps microseconds; the JVM clock may have nanoseconds. */
    private static Instant truncated(Instant instant) {
        return instant.truncatedTo(java.time.temporal.ChronoUnit.MICROS);
    }

    private static String table(String tenant) {
        return schemaOf(tenant) + ".issuance";
    }
}
