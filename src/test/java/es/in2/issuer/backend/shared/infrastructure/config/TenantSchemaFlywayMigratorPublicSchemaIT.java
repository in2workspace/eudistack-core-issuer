package es.in2.issuer.backend.shared.infrastructure.config;

import es.in2.issuer.backend.support.PostgresIntegrationBase;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;
import org.springframework.dao.DataIntegrityViolationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * EUD-289: proves {@code db/public/V1__signing_spki_reservation.sql} and the public-schema step of
 * {@link TenantSchemaFlywayMigrator} against a real Postgres. The application has already started,
 * so the migrator has run once on a {@code public} schema that was not empty: it held
 * {@code tenant_registry} from the Testcontainers init script.
 */
class TenantSchemaFlywayMigratorPublicSchemaIT extends PostgresIntegrationBase {

    private static final String SPKI_HASH = "decode(repeat('ab', 32), 'hex')";
    private static final String CONFIG_ID = "'00000000-0000-0000-0000-000000000001'";

    @Autowired private FlywayProperties flywayProperties;
    @Autowired private R2dbcProperties r2dbcProperties;

    @Test
    void startup_onANonEmptyPublicSchema_appliesV1AndKeepsTheBaselineBelowIt() {
        String history = TenantSchemaFlywayMigrator.PUBLIC_HISTORY_TABLE;

        assertThat(scalar("SELECT count(*) FROM public." + history + " WHERE version = '1' AND success AND type = 'SQL'"))
                .isEqualTo("1");
        assertThat(scalar("SELECT count(*) FROM public." + history + " WHERE version = '0' AND type = 'BASELINE'"))
                .isEqualTo("1");
        assertThat(scalar("SELECT to_regclass('public.signing_spki_reservation') IS NOT NULL")).isEqualTo("true");
    }

    @Test
    void startup_leavesTheDefaultHistoryTableOfPublicAlone() {
        assertThat(scalar("SELECT to_regclass('public.flyway_schema_history') IS NULL")).isEqualTo("true");
    }

    @Test
    void migrating_again_isANoOp() {
        assertThatCode(() -> TenantSchemaFlywayMigrator.publicSchemaConfiguration(
                        flywayProperties.getUrl(), r2dbcProperties.getUsername(), r2dbcProperties.getPassword())
                .load().migrate())
                .doesNotThrowAnyException();
    }

    @Test
    void reservation_sameSpkiForASecondTenant_isRejectedByThePrimaryKey() {
        exec("INSERT INTO public.signing_spki_reservation (public_key_spki_sha256, tenant_id, signing_configuration_id) "
                + "VALUES (decode(repeat('01', 32), 'hex'), 'cgcom', " + CONFIG_ID + ")");

        assertThatThrownBy(() -> exec("INSERT INTO public.signing_spki_reservation "
                + "(public_key_spki_sha256, tenant_id, signing_configuration_id) "
                + "VALUES (decode(repeat('01', 32), 'hex'), 'kpmg', " + CONFIG_ID + ")"))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void reservation_hashThatIsNot32Bytes_isRejected() {
        assertThatThrownBy(() -> exec("INSERT INTO public.signing_spki_reservation "
                + "(public_key_spki_sha256, tenant_id, signing_configuration_id) "
                + "VALUES (decode(repeat('02', 31), 'hex'), 'cgcom', " + CONFIG_ID + ")"))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void reservation_withdrawnKey_canBeReservedAgain() {
        String insert = "INSERT INTO public.signing_spki_reservation "
                + "(public_key_spki_sha256, tenant_id, signing_configuration_id) "
                + "VALUES (decode(repeat('03', 32), 'hex'), 'cgcom', " + CONFIG_ID + ")";
        exec(insert);
        exec("DELETE FROM public.signing_spki_reservation WHERE public_key_spki_sha256 = decode(repeat('03', 32), 'hex')");

        assertThatCode(() -> exec(insert)).doesNotThrowAnyException();
    }

    @Test
    void reservation_hasTheColumnsTheOnboardingToolWrites() {
        exec("INSERT INTO public.signing_spki_reservation (public_key_spki_sha256, tenant_id, signing_configuration_id) "
                + "VALUES (" + SPKI_HASH + ", 'cgcom', " + CONFIG_ID + ")");

        assertThat(scalar("SELECT reserved_at IS NOT NULL FROM public.signing_spki_reservation "
                + "WHERE public_key_spki_sha256 = " + SPKI_HASH)).isEqualTo("true");
    }

    private void exec(String sql) {
        databaseClient.sql(sql).then().block();
    }

    private String scalar(String sql) {
        return String.valueOf(databaseClient.sql(sql).map(r -> r.get(0)).one().block());
    }
}
