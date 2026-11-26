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

import java.util.Map;
import java.util.UUID;

import static es.in2.issuer.backend.shared.domain.util.Constants.TENANT_DOMAIN_CONTEXT_KEY;
import static es.in2.issuer.backend.support.TenantSchemaMigrations.schemaOf;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * EUD-255 AD-9 against a real Postgres: V22 backfills {@code subject_search} with the application's normalization,
 * installs {@code pg_trgm} in {@code public} -- not in the schema being migrated -- and indexes the column with
 * trigrams; and every save writes it from the subject.
 */
class IssuanceSubjectSearchIT extends PostgresIntegrationBase {

    private static final String TENANT = "e2e";

    @Autowired private FlywayProperties flywayProperties;
    @Autowired private R2dbcProperties r2dbcProperties;
    @Autowired private IssuancePort issuancePort;
    @Autowired private SearchIdentifierIndexer searchIdentifierIndexer;

    @Test
    void migration_backfillsWithTheNormalizationOfTheApplication() {
        String tenant = "subject_search_backfill";
        TenantSchemaMigrations.migrate(flywayProperties, r2dbcProperties, tenant, "21");
        UUID named = UUID.randomUUID();
        UUID unnamed = UUID.randomUUID();
        databaseClient.sql("INSERT INTO " + table(tenant) + " (issuance_id, credential_status, subject) VALUES "
                        + "('" + named + "', 'VALID', '  María  GARCÍA López'), ('" + unnamed + "', 'DRAFT', NULL)")
                .then().block();

        TenantSchemaMigrations.migrate(flywayProperties, r2dbcProperties, tenant, null);

        assertThat(subjectSearch(tenant, named)).isEqualTo("maria garcia lopez");
        assertThat(subjectSearch(tenant, unnamed)).isNull();
    }

    @Test
    void migration_indexesWithTrigrams_andLeavesTheExtensionInPublic() {
        String tenant = "subject_search_index";
        TenantSchemaMigrations.migrate(flywayProperties, r2dbcProperties, tenant, null);

        Map<String, Object> index = databaseClient.sql("SELECT indexdef FROM pg_indexes WHERE schemaname = :schema "
                        + "AND indexname = 'idx_issuance_subject_search'")
                .bind("schema", schemaOf(tenant))
                .fetch().one().block();
        Map<String, Object> extension = databaseClient.sql("SELECT n.nspname AS schema FROM pg_extension e "
                        + "JOIN pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = 'pg_trgm'")
                .fetch().one().block();

        assertThat((String) index.get("indexdef")).contains("USING gin").contains("gin_trgm_ops");
        assertThat(extension).containsEntry("schema", "public");
    }

    @Test
    void creation_andAChangeOfTheSubject_writeItsSearchForm() {
        Issuance created = searchIdentifierIndexer.saveWithFingerprints(Issuance.builder()
                        .credentialFormat("jwt_vc_json")
                        .credentialDataSet("{}")
                        .credentialStatus(CredentialStatusEnum.DRAFT)
                        .organizationIdentifier("ORG-A")
                        .subject("Núria Puigdomènech")
                        .credentialType("learcredential.employee.w3c.4")
                        .email("holder@example.com")
                        .delivery("email")
                        .build())
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
        assertThat(subjectSearch(TENANT, created.getIssuanceId())).isEqualTo("nuria puigdomenech");

        Issuance renamed = issuancePort.findByIssuanceId(created.getIssuanceId())
                .contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT))
                .block();
        renamed.setSubject("Núria Puigdomènech i Roca");
        issuancePort.save(renamed).contextWrite(ctx -> ctx.put(TENANT_DOMAIN_CONTEXT_KEY, TENANT)).block();

        assertThat(subjectSearch(TENANT, created.getIssuanceId())).isEqualTo("nuria puigdomenech i roca");
    }

    private String subjectSearch(String tenant, UUID issuanceId) {
        // fetch(), not map(): a row without a search form maps to null, which a Reactor map cannot emit.
        Map<String, Object> row = databaseClient.sql("SELECT subject_search FROM " + table(tenant) + " WHERE issuance_id = :id")
                .bind("id", issuanceId)
                .fetch().one().block();
        return (String) row.get("subject_search");
    }

    private static String table(String tenant) {
        return schemaOf(tenant) + ".issuance";
    }
}
