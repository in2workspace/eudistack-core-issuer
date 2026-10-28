package es.in2.issuer.backend.shared.infrastructure.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.flyway.FlywayProperties;
import org.springframework.boot.autoconfigure.r2dbc.R2dbcProperties;
import org.springframework.boot.DefaultApplicationArguments;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TenantSchemaFlywayMigratorTest {

    @ParameterizedTest
    @ValueSource(strings = {"sandbox_issuer", "e2e-tenant-a_issuer", "a", "kpmg_issuer"})
    void requireValidSchemaName_acceptsLowercaseIdentifiers(String schema) {
        assertThatCode(() -> TenantSchemaFlywayMigrator.requireValidSchemaName(schema))
                .doesNotThrowAnyException();
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "Sandbox_issuer", "1tenant_issuer", "-tenant", "ten ant", "a\"; DROP SCHEMA x; --", "a;b"})
    void requireValidSchemaName_rejectsUnsafeOrMalformedNames(String schema) {
        assertThatThrownBy(() -> TenantSchemaFlywayMigrator.requireValidSchemaName(schema))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageStartingWith("Invalid schema name");
    }

    @Test
    void requireValidSchemaName_rejectsNamesLongerThan63Characters() {
        String tooLong = "a".repeat(64);

        assertThatThrownBy(() -> TenantSchemaFlywayMigrator.requireValidSchemaName(tooLong))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatCode(() -> TenantSchemaFlywayMigrator.requireValidSchemaName("a".repeat(63)))
                .doesNotThrowAnyException();
    }

    @Test
    void publicSchemaConfiguration_usesItsOwnLocationAndHistoryTableAndBaselinesBelowV1() {
        var configuration = TenantSchemaFlywayMigrator.publicSchemaConfiguration("jdbc:postgresql://h/db", "u", "p");

        assertThat(configuration.getLocations()).singleElement()
                .satisfies(location -> assertThat(location.getPath()).isEqualTo("db/public"));
        assertThat(configuration.getTable()).isEqualTo("flyway_issuer_public_history");
        assertThat(configuration.getDefaultSchema()).isEqualTo("public");
        assertThat(configuration.getSchemas()).containsExactly("public");
        assertThat(configuration.isCreateSchemas()).isFalse();
        // public is never empty, and a baseline at version 1 (the default) would skip V1.
        assertThat(configuration.isBaselineOnMigrate()).isTrue();
        assertThat(configuration.getBaselineVersion().getVersion()).isEqualTo("0");
    }

    @Test
    void run_whenThePublicSchemaCannotBeMigrated_logsAnErrorAndDoesNotStopTheIssuer() {
        Logger migratorLogger = (Logger) LoggerFactory.getLogger(TenantSchemaFlywayMigrator.class);
        ListAppender<ILoggingEvent> logs = new ListAppender<>();
        logs.start();
        migratorLogger.addAppender(logs);
        FlywayProperties flyway = new FlywayProperties();
        // Nothing listens on this port: the migration of public fails, as it would without CREATE on the schema.
        flyway.setUrl("jdbc:postgresql://127.0.0.1:1/none");
        R2dbcProperties r2dbc = new R2dbcProperties();
        r2dbc.setUsername("u");
        r2dbc.setPassword("p");

        try {
            assertThatCode(() -> new TenantSchemaFlywayMigrator(flyway, r2dbc).run(new DefaultApplicationArguments()))
                    .doesNotThrowAnyException();
        } finally {
            migratorLogger.detachAppender(logs);
        }

        assertThat(logs.list).filteredOn(event -> event.getLevel() == Level.ERROR)
                .singleElement()
                .satisfies(event -> assertThat(event.getFormattedMessage())
                        .contains("signing_spki_reservation").contains("grant CREATE on schema public"));
        assertThat(logs.list).anyMatch(event -> event.getFormattedMessage().contains("Flyway multi-schema migration completed"));
    }
}
