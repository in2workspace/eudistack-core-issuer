package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * EUD-289 B1 (EC-01, EC-03): proves {@code V15__tenant_signing_config_modality_and_own_key.sql}
 * against a real Postgres. Each test creates its own unregistered tenant schema and drives
 * Flyway by hand: migrate to V14, seed legacy rows, then migrate to the latest version.
 */
class TenantSigningConfigOwnKeyMigrationIT extends PostgresIntegrationBase {

    private static final String ID_1 = "00000000-0000-0000-0000-000000000001";
    private static final String ID_2 = "00000000-0000-0000-0000-000000000002";
    private static final String ID_3 = "00000000-0000-0000-0000-000000000003";
    private static final String SEED_STATEMENT = "INSERT INTO \"%s\".tenant_signing_config "
            + "(provider, csc_api_version, provider_specific_config) "
            + "VALUES ('digitel', 'v2', '{\"k\":\"v\"}'::jsonb) ON CONFLICT DO NOTHING";
    private static final String KMS_REF = "'arn:aws:kms:eu-west-1:111122223333:key/k'";
    private static final String CHAIN = "'[\"MIIB-leaf\",\"MIIB-intermediate\"]'::jsonb";

    @Autowired private FlywayProperties flywayProperties;
    @Autowired private R2dbcProperties r2dbcProperties;

    @Test
    void migration_withDuplicateRows_keepsNewestActiveAndWithdrawsOlder() {
        String schema = createSchemaAndMigrateTo("tsc-dup", "14");
        insertLegacy(schema, ID_1, "2026-01-01T10:00:00Z");
        insertLegacy(schema, ID_2, "2026-03-01T10:00:00Z");
        insertLegacy(schema, ID_3, "2026-02-01T10:00:00Z");

        migrateFully(schema);

        Map<String, Object> newest = row(schema, ID_2);
        assertThat(newest.get("status")).isEqualTo("active");
        assertThat(newest.get("modality")).isEqualTo("qtsp");
        assertThat(newest.get("withdrawn_at")).isNull();
        assertThat(((OffsetDateTime) newest.get("activated_at")).toInstant())
                .isEqualTo(((OffsetDateTime) newest.get("created_at")).toInstant());
        for (String olderId : List.of(ID_1, ID_3)) {
            Map<String, Object> older = row(schema, olderId);
            assertThat(older.get("status")).isEqualTo("withdrawn");
            assertThat(older.get("modality")).isEqualTo("qtsp");
            assertThat(older.get("withdrawn_at")).isNotNull();
            assertThat(((OffsetDateTime) older.get("activated_at")).toInstant())
                    .isEqualTo(((OffsetDateTime) older.get("created_at")).toInstant());
        }
        assertThat(count(schema)).isEqualTo(3);
    }

    @Test
    void migration_withSameCreatedAt_breaksTieById() {
        String schema = createSchemaAndMigrateTo("tsc-tie", "14");
        insertLegacy(schema, ID_1, "2026-01-01T10:00:00Z");
        insertLegacy(schema, ID_2, "2026-01-01T10:00:00Z");

        migrateFully(schema);

        assertThat(row(schema, ID_2).get("status")).isEqualTo("active");
        assertThat(row(schema, ID_1).get("status")).isEqualTo("withdrawn");
    }

    @Test
    void migration_withSingleRow_keepsItActive() {
        String schema = migratedSchemaWithOneActiveRow("tsc-single");

        Map<String, Object> only = row(schema, ID_1);
        assertThat(only.get("status")).isEqualTo("active");
        assertThat(only.get("withdrawn_at")).isNull();
        assertThat(only.get("activated_at")).isNotNull();
    }

    @Test
    void migration_onFreshSchemaWithoutRows_succeeds() {
        String schema = schemaOf("tsc-fresh");
        databaseClient.sql("CREATE SCHEMA IF NOT EXISTS \"" + schema + "\"").then().block();

        migrateFully(schema);

        assertThat(count(schema)).isZero();
        exec(String.format(SEED_STATEMENT, schema));
        assertThat(scalar(schema, "SELECT status || '/' || modality FROM \"%s\".tenant_signing_config"))
                .isEqualTo("active/qtsp");
    }

    @Test
    void secondActiveRow_isRejectedByUniqueIndex() {
        String schema = migratedSchemaWithOneActiveRow("tsc-unique");

        assertThatThrownBy(() -> exec("INSERT INTO \"" + schema + "\".tenant_signing_config (provider) "
                + "VALUES ('digitel')"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("idx_tenant_signing_config_single_active");
    }

    @Test
    void seedStatementWithOnConflictDoNothing_isNoOpWhenAnActiveRowExists() {
        String schema = migratedSchemaWithOneActiveRow("tsc-seed");

        Long inserted = databaseClient.sql(String.format(SEED_STATEMENT, schema))
                .fetch().rowsUpdated().block();

        assertThat(inserted).isZero();
        assertThat(count(schema)).isEqualTo(1);
    }

    @Test
    void ownKeyRow_withoutKmsRef_isRejected() {
        String schema = migratedSchemaWithOneActiveRow("tsc-nokms");

        assertOwnKeyInsertRejected(schema, "NULL", "'ES256'", CHAIN);
    }

    @Test
    void ownKeyRow_withoutAlgorithm_isRejected() {
        String schema = migratedSchemaWithOneActiveRow("tsc-noalg");

        assertOwnKeyInsertRejected(schema, KMS_REF, "NULL", CHAIN);
    }

    @Test
    void ownKeyRow_withoutChain_isRejected() {
        String schema = migratedSchemaWithOneActiveRow("tsc-nochain");

        assertOwnKeyInsertRejected(schema, KMS_REF, "'ES256'", "NULL");
    }

    @Test
    void ownKeyRow_withEmptyOrNonArrayChain_isRejected() {
        String schema = migratedSchemaWithOneActiveRow("tsc-badchain");

        assertOwnKeyInsertRejected(schema, KMS_REF, "'ES256'", "'[]'::jsonb");
        assertOwnKeyInsertRejected(schema, KMS_REF, "'ES256'", "'{\"a\":1}'::jsonb");
    }

    @Test
    void validOwnKeyRow_isAcceptedAsWithdrawnAlongsideTheActiveOne() {
        String schema = migratedSchemaWithOneActiveRow("tsc-ownkey-ok");

        exec(ownKeyInsert(schema, "withdrawn", "now()"));

        assertThat(scalar(schema, "SELECT count(*) FROM \"%s\".tenant_signing_config WHERE modality = 'own_key'"))
                .isEqualTo("1");
    }

    @Test
    void validOwnKeyRow_isAcceptedAsActiveAfterWithdrawingTheOther() {
        String schema = migratedSchemaWithOneActiveRow("tsc-ownkey-swap");

        exec("UPDATE \"" + schema + "\".tenant_signing_config SET status = 'withdrawn', withdrawn_at = now()");
        exec(ownKeyInsert(schema, "active", "NULL"));

        assertThat(scalar(schema, "SELECT provider || '/' || status FROM \"%s\".tenant_signing_config "
                + "WHERE modality = 'own_key'")).isEqualTo("aws-kms/active");
    }

    @Test
    void withdrawnRow_withoutWithdrawnAt_isRejected() {
        String schema = migratedSchemaWithOneActiveRow("tsc-nowithdrawn");

        assertThatThrownBy(() -> exec("UPDATE \"" + schema + "\".tenant_signing_config "
                + "SET status = 'withdrawn'"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tenant_signing_config_withdrawn_at");
    }

    @Test
    void invalidModalityOrStatus_isRejected() {
        String schema = migratedSchemaWithOneActiveRow("tsc-enum");

        assertThatThrownBy(() -> exec("INSERT INTO \"" + schema + "\".tenant_signing_config "
                + "(provider, modality, status, withdrawn_at) VALUES ('x', 'hsm', 'withdrawn', now())"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tenant_signing_config_modality");
        assertThatThrownBy(() -> exec("INSERT INTO \"" + schema + "\".tenant_signing_config "
                + "(provider, status) VALUES ('x', 'pending')"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tenant_signing_config_status");
    }

    private void assertOwnKeyInsertRejected(String schema, String kmsRef, String algorithm,
                                            String chain) {
        String sql = "INSERT INTO \"" + schema + "\".tenant_signing_config "
                + "(provider, modality, status, withdrawn_at, own_key_kms_key_ref, own_key_algorithm, "
                + "own_key_certificate_chain) "
                + "VALUES ('aws-kms', 'own_key', 'withdrawn', now(), "
                + kmsRef + ", " + algorithm + ", " + chain + ")";
        assertThatThrownBy(() -> exec(sql))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tenant_signing_config_own_key_required");
    }

    private String ownKeyInsert(String schema, String status, String withdrawnAt) {
        return "INSERT INTO \"" + schema + "\".tenant_signing_config "
                + "(provider, modality, status, withdrawn_at, own_key_kms_key_ref, own_key_algorithm, "
                + "own_key_certificate_chain) "
                + "VALUES ('aws-kms', 'own_key', '" + status + "', " + withdrawnAt
                + ", " + KMS_REF + ", 'ES256', " + CHAIN + ")";
    }

    private String migratedSchemaWithOneActiveRow(String tenant) {
        String schema = createSchemaAndMigrateTo(tenant, "14");
        insertLegacy(schema, ID_1, "2026-01-01T10:00:00Z");
        migrateFully(schema);
        return schema;
    }

    private static String schemaOf(String tenant) {
        return tenant + SCHEMA_SUFFIX;
    }

    private String createSchemaAndMigrateTo(String tenant, String targetVersion) {
        String schema = schemaOf(tenant);
        databaseClient.sql("CREATE SCHEMA IF NOT EXISTS \"" + schema + "\"").then().block();
        flyway(schema).target(targetVersion).load().migrate();
        return schema;
    }

    private void migrateFully(String schema) {
        flyway(schema).load().migrate();
    }

    private FluentConfiguration flyway(String schema) {
        return Flyway.configure()
                .dataSource(flywayProperties.getUrl(), r2dbcProperties.getUsername(), r2dbcProperties.getPassword())
                .locations("classpath:db/tenant")
                .defaultSchema(schema)
                .schemas(schema)
                .table("flyway_schema_history");
    }

    private void insertLegacy(String schema, String id, String createdAt) {
        exec("INSERT INTO \"" + schema + "\".tenant_signing_config (id, provider, created_at, updated_at) "
                + "VALUES ('" + id + "', 'digitel', '" + createdAt + "', '" + createdAt + "')");
    }

    private void exec(String sql) {
        databaseClient.sql(sql).then().block();
    }

    private Map<String, Object> row(String schema, String id) {
        return databaseClient.sql("SELECT * FROM \"" + schema + "\".tenant_signing_config WHERE id = '" + id + "'")
                .fetch().one().block();
    }

    private long count(String schema) {
        return Long.parseLong(scalar(schema, "SELECT count(*) FROM \"%s\".tenant_signing_config"));
    }

    private String scalar(String schema, String sqlWithSchemaPlaceholder) {
        Object value = databaseClient.sql(String.format(sqlWithSchemaPlaceholder, schema))
                .map(r -> r.get(0)).one().block();
        return String.valueOf(value);
    }
}
