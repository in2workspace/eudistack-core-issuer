package es.in2.issuer.backend.signing.infrastructure.onboarding;

import es.in2.issuer.backend.signing.domain.onboarding.OnboardingFailedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static es.in2.issuer.backend.signing.infrastructure.onboarding.OnboardingTestDatabase.execute;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@code isKeyReferenced} guards the reconcile and the discard: if the role of the tool cannot read the signing
 * configurations of some tenant, the key must not be taken for unreferenced.
 */
class JdbcOwnKeyStoreFailClosedIT {

    private static final String READER = "tool_reader";
    private static final String READER_PASSWORD = "reader-pw";

    @BeforeEach
    void createAReaderWithoutAccessToOneTenant() {
        OnboardingTestDatabase.reset();
        execute("CREATE ROLE " + READER + " LOGIN PASSWORD '" + READER_PASSWORD + "'");
        execute("CREATE SCHEMA locked_issuer");
        execute("CREATE TABLE locked_issuer.tenant_signing_config (LIKE cgcom_issuer.tenant_signing_config INCLUDING ALL)");
        execute("INSERT INTO locked_issuer.tenant_signing_config (provider, modality, status, activated_by, "
                + "own_key_kms_key_ref, own_key_algorithm, own_key_certificate_chain) "
                + "VALUES ('aws-kms', 'own_key', 'active', 'x', 'arn:the-locked-key', 'ES256', '[\"AAAA\"]'::jsonb)");
        execute("GRANT SELECT ON public.tenant_registry TO " + READER);
        for (String tenant : new String[] {"cgcom", "kpmg", "dormant"}) {
            execute("GRANT USAGE ON SCHEMA " + tenant + "_issuer TO " + READER);
            execute("GRANT SELECT ON ALL TABLES IN SCHEMA " + tenant + "_issuer TO " + READER);
        }
    }

    @AfterEach
    void drop() {
        execute("DROP SCHEMA locked_issuer CASCADE");
        execute("DROP OWNED BY " + READER);
        execute("DROP ROLE " + READER);
    }

    private static JdbcOwnKeyStore storeAs(String user, String password) {
        return new JdbcOwnKeyStore(OnboardingTestDatabase.POSTGRES.getJdbcUrl(), user, password,
                new LoggingSigningConfigurationAuditSink());
    }

    @Test
    void isKeyReferenced_aTenantSchemaTheRoleCannotRead_failsInsteadOfAnsweringNo() {
        var store = storeAs(READER, READER_PASSWORD);

        assertThatThrownBy(() -> store.isKeyReferenced("arn:the-locked-key", true))
                .isInstanceOf(OnboardingFailedException.class)
                .hasMessageContaining("tenant 'locked'")
                .hasMessageContaining("cannot be shown to be unreferenced");
        assertThatThrownBy(() -> store.isKeyReferenced("arn:anything", false))
                .isInstanceOf(OnboardingFailedException.class);
    }

    @Test
    void isKeyReferenced_everySchemaReadable_answersFromTheRows() {
        execute("GRANT USAGE ON SCHEMA locked_issuer TO " + READER);
        execute("GRANT SELECT ON ALL TABLES IN SCHEMA locked_issuer TO " + READER);
        var store = storeAs(READER, READER_PASSWORD);

        assertThat(store.isKeyReferenced("arn:the-locked-key", true)).isTrue();
        assertThat(store.isKeyReferenced("arn:nowhere", false)).isFalse();
    }

    @Test
    void isKeyReferenced_findsASchemaThatTheRegistryDoesNotList() {
        var store = OnboardingTestDatabase.store(new LoggingSigningConfigurationAuditSink());

        assertThat(store.isKeyReferenced("arn:the-locked-key", true))
                .as("locked is not in tenant_registry, but its table exists").isTrue();
    }
}
