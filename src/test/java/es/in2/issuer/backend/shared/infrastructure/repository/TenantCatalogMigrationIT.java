package es.in2.issuer.backend.shared.infrastructure.repository;

import es.in2.issuer.backend.support.PostgresIntegrationBase;
import es.in2.issuer.backend.support.TenantSchemaMigrations;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

import static es.in2.issuer.backend.support.TenantSchemaMigrations.schemaOf;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Proves {@code V15__Add_entry_config_to_tenant_credential_profile.sql} and
 * {@code V16__Widen_subject_separator_of_tenant_credential_profile.sql} against a real Postgres:
 * the new columns, the validity and delivery-mode {@code CHECK}s (D14), the unique index on
 * {@code schema_uri} and the unlimited {@code subject_separator}. Each test migrates its own unregistered tenant schema, so it neither
 * depends on nor disturbs the schemas the application migrated at start-up.
 */
class TenantCatalogMigrationIT extends PostgresIntegrationBase {

    @Autowired private FlywayProperties flywayProperties;
    @Autowired private R2dbcProperties r2dbcProperties;

    @Test
    void migration_addsEntryConfigColumns_withFillableDefaults() {
        String tenant = "catalog-columns";
        migrate(tenant, null);

        insertRow(tenant, "doctorid.sd.1", "true", "NULL", "NULL");

        Map<String, Object> row = databaseClient.sql(
                        "SELECT schema_uri, validity_default_days, validity_requester_dates, validity_max_days, "
                                + "subject_fields, subject_separator, search_identifiers::text AS search_identifiers, version "
                                + "FROM " + table(tenant))
                .fetch().one().block();
        assertThat(row).containsEntry("schema_uri", null)
                .containsEntry("validity_default_days", null)
                .containsEntry("validity_requester_dates", false)
                .containsEntry("validity_max_days", null)
                .containsEntry("subject_fields", null)
                .containsEntry("subject_separator", null)
                .containsEntry("search_identifiers", "[]")
                .containsEntry("version", 0L);
    }

    @Test
    void migration_fromV14_keepsExistingRowsAndLeavesThemUnfilled() {
        String tenant = "catalog-from-v14";
        migrate(tenant, "14");
        databaseClient.sql("INSERT INTO " + table(tenant) + " (credential_configuration_id, enabled, delivery_modes) "
                        + "VALUES ('learcredential.employee.sd.1', true, 'email,ui')")
                .then().block();

        migrate(tenant, null);

        Map<String, Object> row = databaseClient.sql(
                        "SELECT delivery_modes, enabled, validity_default_days, version FROM " + table(tenant))
                .fetch().one().block();
        assertThat(row).containsEntry("delivery_modes", "email,ui")
                .containsEntry("enabled", true)
                .containsEntry("validity_default_days", null)
                .containsEntry("version", 0L);
    }

    @Test
    void migration_makesTheSubjectSeparatorUnlimitedText() {
        String tenant = "catalog-separator";
        migrate(tenant, null);
        String separator = " | ".repeat(100);

        databaseClient.sql("INSERT INTO " + table(tenant) + " (credential_configuration_id, subject_separator) "
                        + "VALUES ('doctorid.sd.1', '" + separator + "')")
                .then().block();

        Map<String, Object> row = databaseClient.sql("SELECT subject_separator FROM " + table(tenant)).fetch().one().block();
        assertThat(row).containsEntry("subject_separator", separator);
        assertThat(databaseClient.sql("SELECT data_type FROM information_schema.columns "
                        + "WHERE table_schema = '" + schemaOf(tenant) + "' AND table_name = 'tenant_credential_profile' "
                        + "AND column_name = 'subject_separator'").fetch().one().block())
                .containsEntry("data_type", "text");
    }

    @Test
    void migration_fromV15_widensTheSeparatorAndKeepsTheOnesAlreadyStored() {
        String tenant = "catalog-separator-from-v15";
        migrate(tenant, "15");
        databaseClient.sql("INSERT INTO " + table(tenant) + " (credential_configuration_id, subject_separator) "
                        + "VALUES ('doctorid.sd.1', ' - ')")
                .then().block();
        Mono<Void> tooLong = databaseClient.sql("UPDATE " + table(tenant) + " SET subject_separator = '"
                + "x".repeat(17) + "'").then();
        assertThatThrownBy(tooLong::block)
                .isInstanceOf(DataAccessException.class)
                .hasMessageContaining("subject_separator");

        migrate(tenant, null);

        assertThat(databaseClient.sql("SELECT subject_separator FROM " + table(tenant)).fetch().one().block())
                .containsEntry("subject_separator", " - ");
        databaseClient.sql("UPDATE " + table(tenant) + " SET subject_separator = '" + "x".repeat(17) + "'")
                .then().block();
    }

    @Test
    void schemaUriIndex_rejectsTwoRowsWithTheSameSchemaUri() {
        String tenant = "catalog-uri-unique";
        migrate(tenant, null);
        insertRow(tenant, "doctorid.sd.1", "true", "NULL", "'https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt'");

        assertThatThrownBy(() -> insertRow(tenant, "doctorid.sd.2", "true", "NULL",
                "'https://registry.eudistack.net/schemas/doctorid/1.0.0/dc+sd-jwt'"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("uq_tcp_schema_uri");
    }

    @Test
    void schemaUriIndex_allowsSeveralRowsWithoutSchemaUri() {
        String tenant = "catalog-uri-null";
        migrate(tenant, null);

        insertRow(tenant, "doctorid.sd.1", "true", "NULL", "NULL");
        insertRow(tenant, "eu.europa.ec.eudi.pid.1", "true", "NULL", "NULL");

        assertThat(count(tenant, "")).isEqualTo(2);
    }

    @ParameterizedTest
    @ValueSource(strings = {"direct", "email", "ui", "direct,email", "direct,ui", "email,ui", "direct,email,ui"})
    void deliveryModesCheck_admitsEachCanonicalValue(String canonical) {
        String tenant = "catalog-canonical";
        migrate(tenant, null);

        insertRow(tenant, "type." + canonical.replace(',', '-'), "true", "'" + canonical + "'", "NULL");

        assertThat(count(tenant, "WHERE delivery_modes = '" + canonical + "'")).isEqualTo(1);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ui,email", "email,email", "carrier-pigeon"})
    void deliveryModesCheck_rejectsNonCanonicalValues(String value) {
        String tenant = "catalog-noncanonical";
        migrate(tenant, null);

        assertThatThrownBy(() -> insertRow(tenant, "doctorid.sd.1", "false", "'" + value + "'", "NULL"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tcp_delivery_modes");
    }

    @Test
    void deliveryModesCheck_admitsEmptyListOnADisabledEntry() {
        String tenant = "catalog-empty-disabled";
        migrate(tenant, null);

        insertRow(tenant, "doctorid.sd.1", "false", "''", "NULL");

        assertThat(count(tenant, "WHERE delivery_modes = '' AND NOT enabled")).isEqualTo(1);
    }

    @Test
    void deliveryModesCheck_rejectsEmptyListOnAnEnabledEntry() {
        String tenant = "catalog-empty-enabled";
        migrate(tenant, null);

        assertThatThrownBy(() -> insertRow(tenant, "doctorid.sd.1", "true", "''", "NULL"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tcp_enabled_has_delivery_mode");
    }

    @Test
    void deliveryModesCheck_rejectsEnablingAnEntryHoldingAnEmptyList() {
        String tenant = "catalog-enable-empty";
        migrate(tenant, null);
        insertRow(tenant, "doctorid.sd.1", "false", "''", "NULL");

        Mono<Void> enable = databaseClient.sql("UPDATE " + table(tenant) + " SET enabled = true").then();
        assertThatThrownBy(enable::block)
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tcp_enabled_has_delivery_mode");
    }

    @Test
    void validityCheck_rejectsDefaultDaysBelowOne() {
        String tenant = "catalog-validity-default";
        migrate(tenant, null);

        assertThatThrownBy(() -> insertValidity(tenant, "0", "false", "NULL"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tcp_validity_default_days");
    }

    @Test
    void validityCheck_rejectsMaxDaysBelowDefaultDays() {
        String tenant = "catalog-validity-max";
        migrate(tenant, null);

        assertThatThrownBy(() -> insertValidity(tenant, "30", "true", "10"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tcp_validity_max_days");
    }

    @Test
    void validityCheck_rejectsRequesterDatesWithoutMaxDays() {
        String tenant = "catalog-validity-requester";
        migrate(tenant, null);

        assertThatThrownBy(() -> insertValidity(tenant, "30", "true", "NULL"))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("chk_tcp_validity_requester_dates");
    }

    @Test
    void validityCheck_admitsValidityWithoutRequesterDatesAndWithRequesterDatesUpToMax() {
        String tenant = "catalog-validity-ok";
        migrate(tenant, null);

        insertValidity(tenant, "36500", "false", "NULL");
        databaseClient.sql("INSERT INTO " + table(tenant) + " (credential_configuration_id, validity_default_days, "
                        + "validity_requester_dates, validity_max_days) VALUES ('other.type', 365, true, 365)")
                .then().block();

        assertThat(count(tenant, "WHERE validity_default_days IS NOT NULL")).isEqualTo(2);
    }

    // ---- helpers ---------------------------------------------------------------

    private void migrate(String tenant, String targetVersion) {
        TenantSchemaMigrations.migrate(flywayProperties, r2dbcProperties, tenant, targetVersion);
    }

    private static String table(String tenant) {
        return "\"" + schemaOf(tenant) + "\".tenant_credential_profile";
    }

    /** {@code deliveryModes} and {@code schemaUri} are SQL literals ({@code NULL} or a quoted string). */
    private void insertRow(String tenant, String ccid, String enabled, String deliveryModes, String schemaUri) {
        databaseClient.sql("INSERT INTO " + table(tenant) + " (credential_configuration_id, enabled, delivery_modes, schema_uri) "
                        + "VALUES ('" + ccid + "', " + enabled + ", " + deliveryModes + ", " + schemaUri + ")")
                .then().block();
    }

    private void insertValidity(String tenant, String defaultDays, String requesterDates, String maxDays) {
        databaseClient.sql("INSERT INTO " + table(tenant) + " (credential_configuration_id, validity_default_days, "
                        + "validity_requester_dates, validity_max_days) VALUES ('doctorid.sd.1', " + defaultDays + ", "
                        + requesterDates + ", " + maxDays + ")")
                .then().block();
    }

    private long count(String tenant, String where) {
        List<Map<String, Object>> rows = databaseClient.sql("SELECT count(*) AS n FROM " + table(tenant) + " " + where)
                .fetch().all().collectList().block();
        return (Long) rows.getFirst().get("n");
    }
}
