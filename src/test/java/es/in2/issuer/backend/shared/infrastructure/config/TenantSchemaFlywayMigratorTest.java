package es.in2.issuer.backend.shared.infrastructure.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

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
}
