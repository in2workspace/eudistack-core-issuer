package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.configuration.FluentConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;
import org.springframework.dao.DataIntegrityViolationException;

import java.util.List;

import static es.in2.issuer.backend.shared.domain.util.Constants.SCHEMA_SUFFIX;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Proves {@code V15__tenant_signing_config_modality_and_status.sql} against a real Postgres. Each test
 * creates its own unregistered tenant schema and drives Flyway by hand: migrate to V14, seed legacy
 * rows, then migrate to the latest version.
 */
class TenantSigningConfigModalityMigrationIT extends PostgresIntegrationBase {

    private static final String ID_1 = "00000000-0000-0000-0000-000000000001";
    private static final String ID_2 = "00000000-0000-0000-0000-000000000002";
    private static final String ID_3 = "00000000-0000-0000-0000-000000000003";
    private static final String SEED_STATEMENT = "INSERT INTO \"%s\".tenant_signing_config "
            + "(provider, csc_api_version, provider_specific_config) "
            + "VALUES ('digitel', 'v2', '{\"k\":\"v\"}'::jsonb) ON CONFLICT DO NOTHING";
    private static final String QTSP_CONFIG = "'{\"k\":\"v\"}'::jsonb";

    @Autowired private FlywayProperties flywayProperties;
    @Autowired private R2dbcProperties r2dbcProperties;

    @Test
    void migration_withDuplicateRows_keepsNewestActiveAndWithdrawsOlder() {
        String schema = createSchemaAndMigrateTo("tsc-dup", "14");
        insertLegacy(schema, ID_1, "2026-01-01T10:00:00Z");
        insertLegacy(schema, ID_2, "2026-03-01T10:00:00Z");
        insertLegacy(schema, ID_3, "2026-02-01T10:00:00Z");

        migrateFully(schema);

        assertThat(statusAndModality(schema, ID_2)).isEqualTo("active/qtsp");
        for (String olderId : List.of(ID_1, ID_3)) {
            assertThat(statusAndModality(schema, olderId)).isEqualTo("withdrawn/qtsp");
        }
        assertThat(count(schema)).isEqualTo(3);
    }

    @Test
    void migration_withSameCreatedAt_breaksTieById() {
        String schema = createSchemaAndMigrateTo("tsc-tie", "14");
        insertLegacy(schema, ID_1, "2026-01-01T10:00:00Z");
        insertLegacy(schema, ID_2, "2026-01-01T10:00:00Z");

        migrateFully(schema);

        assertThat(statusAndModality(schema, ID_2)).isEqualTo("active/qtsp");
        assertThat(statusAndModality(schema, ID_1)).isEqualTo("withdrawn/qtsp");
    }

    @Test
    void migration_withSingleRow_keepsItActive() {
        String schema = migratedSchemaWithOneActiveRow("tsc-single");

        assertThat(statusAndModality(schema, ID_1)).isEqualTo("active/qtsp");
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
    void migration_addsOnlyTheModalityAndTheStatus() {
        String schema = migratedSchemaWithOneActiveRow("tsc-columns");

        assertThat(scalar(schema, "SELECT string_agg(column_name, ',' ORDER BY column_name) "
                + "FROM information_schema.columns WHERE table_schema = '%s' "
                + "AND table_name = 'tenant_signing_config' AND column_name IN ('modality', 'status')"))
                .isEqualTo("modality,status");
        assertThat(scalar(schema, "SELECT count(*) FROM information_schema.columns WHERE table_schema = '%s' "
                + "AND table_name = 'tenant_signing_config' AND (column_name LIKE 'own_key%%' "
                + "OR column_name LIKE 'activated%%' OR column_name LIKE 'withdrawn%%')")).isEqualTo("0");
    }

    @Test
    void migration_withLegacyRowWithoutProviderConfig_fails() {
        String schema = createSchemaAndMigrateTo("tsc-legacy-nocfg", "14");
        exec("INSERT INTO \"" + schema + "\".tenant_signing_config (provider) VALUES ('digitel')");

        assertThatThrownBy(() -> migrateFully(schema))
                .hasMessageContaining("chk_tenant_signing_config_qtsp_required");
    }

    @Test
    void secondActiveRow_isRejectedByUniqueIndex() {
        String schema = migratedSchemaWithOneActiveRow("tsc-unique");

        assertThatThrownBy(() -> exec("INSERT INTO \"" + schema + "\".tenant_signing_config "
                + "(provider, provider_specific_config) VALUES ('digitel', " + QTSP_CONFIG + ")"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("idx_tenant_signing_config_single_active");
    }

    @Test
    void qtspRow_withoutProviderConfig_isRejected() {
        String schema = migratedSchemaWithOneActiveRow("tsc-noqtspcfg");

        assertThatThrownBy(() -> exec("INSERT INTO \"" + schema + "\".tenant_signing_config "
                + "(provider, status) VALUES ('digitel', 'withdrawn')"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tenant_signing_config_qtsp_required");
    }

    @Test
    void qtspRow_withAwsKmsProvider_isRejected() {
        String schema = migratedSchemaWithOneActiveRow("tsc-qtspkms");

        assertThatThrownBy(() -> exec("INSERT INTO \"" + schema + "\".tenant_signing_config "
                + "(provider, provider_specific_config, status) VALUES ('aws-kms', " + QTSP_CONFIG + ", 'withdrawn')"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tenant_signing_config_provider_modality");
    }

    @Test
    void ownKeyRow_withQtspProvider_isRejected() {
        String schema = migratedSchemaWithOneActiveRow("tsc-ownkeyqtsp");

        String insert = ownKeyInsert(schema, "withdrawn").replace("'aws-kms'", "'digitel'");

        assertThatThrownBy(() -> exec(insert))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tenant_signing_config_provider_modality");
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
    void ownKeyRow_isAcceptedWithoutProviderConfig() {
        String schema = migratedSchemaWithOneActiveRow("tsc-ownkey-ok");

        exec(ownKeyInsert(schema, "withdrawn"));

        assertThat(scalar(schema, "SELECT count(*) FROM \"%s\".tenant_signing_config WHERE modality = 'own_key'"))
                .isEqualTo("1");
    }

    @Test
    void ownKeyRow_isAcceptedAsActiveAfterWithdrawingTheOther() {
        String schema = migratedSchemaWithOneActiveRow("tsc-ownkey-swap");

        exec("UPDATE \"" + schema + "\".tenant_signing_config SET status = 'withdrawn'");
        exec(ownKeyInsert(schema, "active"));

        assertThat(scalar(schema, "SELECT provider || '/' || status FROM \"%s\".tenant_signing_config "
                + "WHERE modality = 'own_key'")).isEqualTo("aws-kms/active");
    }

    @Test
    void invalidModalityOrStatus_isRejected() {
        String schema = migratedSchemaWithOneActiveRow("tsc-enum");

        assertThatThrownBy(() -> exec("INSERT INTO \"" + schema + "\".tenant_signing_config "
                + "(provider, modality, status) VALUES ('x', 'hsm', 'withdrawn')"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tenant_signing_config_modality");
        assertThatThrownBy(() -> exec("INSERT INTO \"" + schema + "\".tenant_signing_config "
                + "(provider, provider_specific_config, status) VALUES ('x', " + QTSP_CONFIG + ", 'pending')"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tenant_signing_config_status");
    }

    private static String ownKeyInsert(String schema, String status) {
        return "INSERT INTO \"" + schema + "\".tenant_signing_config (provider, modality, status) "
                + "VALUES ('aws-kms', 'own_key', '" + status + "')";
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
        exec("INSERT INTO \"" + schema + "\".tenant_signing_config "
                + "(id, provider, provider_specific_config, created_at, updated_at) "
                + "VALUES ('" + id + "', 'digitel', " + QTSP_CONFIG + ", '" + createdAt + "', '" + createdAt + "')");
    }

    private void exec(String sql) {
        databaseClient.sql(sql).then().block();
    }

    private String statusAndModality(String schema, String id) {
        return scalar(schema, "SELECT status || '/' || modality FROM \"%s\".tenant_signing_config WHERE id = '"
                + id + "'");
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
